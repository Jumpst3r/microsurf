import logging
import os
import random
import tempfile
from collections import OrderedDict
from pathlib import Path, PurePath
from typing import Dict, List
import traceback

import magic
import matplotlib.pyplot as plt
import scipy.stats as stats
import seaborn as sns
from capstone import CS_ARCH_ARM, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, Cs

from qiling import Qiling

from microsurf.pipeline.LeakageModels import identity

from ..utils.hijack import (
    const_clock_gettime,
    const_clock_gettimeofday,
    const_getrandom,
    const_time,
    device_random,
    ql_fixed_syscall_faccessat,
)
from ..utils.logger import (
    LOGGING_LEVEL,
    getConsole,
    getLogger,
    getQillingLogger,
)
from .tracetools.Trace import MemTrace, MemTraceCollection

console = getConsole()
log = getLogger()


class Stage:
    def exec(*args, **kwargs):
        pass

    def finalize(*args, **kwargs):
        pass


class BinaryLoader(Stage):
    def __init__(self, path: str, args: List[str], **kwargs) -> None:
        self.binPath = Path(path)
        self.asm: Dict[str, str] = {}
        self.moduleroot = Path(__file__).parent.parent.parent
        self.dryRunOnly = kwargs["dryRunOnly"]
        self.args = args
        self.mappings = None
        try:
            self.rootfs = kwargs["jail"]
        except KeyError:
            self.rootfs = "/"
        self.QLEngine: Qiling = None
        try:
            self.deterministic = kwargs["deterministic"]
        except KeyError:
            self.deterministic = False
        try:
            self.leakageModel = kwargs["leakageModel"]
        except KeyError:
            self.leakageModel = identity
        try:
            self.rndGen = kwargs["rndGen"]
            self.fixGen = kwargs["fixGen"]
            self.asFile = kwargs["asFile"]
        except KeyError:
            # secret as argument, default to random integer.
            self.asFile = False
            self.rndGen = None
            self.fixGen = None
        try:
            self.secretArgIndex = args.index("@")
        except IndexError as e:
            log.error(f"No argument marked as secret dependent (@): {e}")
            raise ValueError()
        if self.deterministic:
            log.info("hooking sources of randomness")
        if not os.path.exists(self.binPath):
            log.error(f"target path {str(self.binPath)} not found")
        fileinfo = magic.from_file(path)
        if "80386" in fileinfo:
            if "Linux" in fileinfo:
                self.md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif "Windows" in fileinfo:
                self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif "x86" in fileinfo:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif "ARM" in fileinfo:
            self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        else:
            log.info(fileinfo)
            log.error("Target architecture not implemented")
            exit(-1)

        if "dynamic" in fileinfo:
            log.warn(
                "Detected dynamically linked binary, ensure that the appropriate shared objects are available"
            )
            self.dynamic = True
            log.info(f"rootfs = {self.rootfs}")
        else:
            self.dynamic = False
            self.rootfs = PurePath(tempfile.mkdtemp())
            log.info(f"detected static binary, jailing to {self.rootfs}")
        try:
            # initialize args;
            val, path = self.rndArg()
            self.QLEngine = Qiling(
                [str(self.binPath), *args],
                str(self.rootfs),
                log_override=getQillingLogger(),
                verbose=4,
                console=True,
                multithread=True,
            )
            if path:
                self.QLEngine.add_fs_mapper(path.split("/")[-1], path.split("/")[-1])
            self.fixRandomness(self.deterministic)
        except FileNotFoundError as e:
            if ".so" in str(e):
                log.error(f"Lib {str(e.filename)} not found in jail")
                exit(1)
        try:
            self.exec()
            log.info("Looks like binary is supported")
        except Exception as e:
            log.error(f"Emulation dry run failed: {str(e)}")
            log.error(traceback.format_exc())
            exit(1)
        self.md.detail = True

    def _rand(self):
        path = None
        if self.rndGen:
            val = self.rndGen()
            if self.asFile:
                tmpfile, path = tempfile.mkstemp(dir=self.rootfs)
                log.info(f"generated keyfile:{path}")
                os.write(tmpfile, val.encode())
                os.close(tmpfile)
                self.args[self.secretArgIndex] = path.split("/")[-1]
            else:
                self.args[self.secretArgIndex] = val
        else:
            if self.asFile:
                val = random.randint(0x00, 0xFF)
                tmpfile, path = tempfile.mkstemp()
                os.write(tmpfile, val)
                os.close(tmpfile)
                self.args[self.secretArgIndex] = path
            else:
                val = random.randint(0x00, 0xFF)
                self.args[self.secretArgIndex] = str(val)
        return val, path

    def _fixed(self):
        path = None
        if self.fixGen:
            val = self.fixGen()
            if self.asFile:
                tmpfile, path = tempfile.mkstemp()
                os.write(tmpfile, val.encode())
                os.close(tmpfile)
                self.args[self.secretArgIndex] = path
            else:
                self.args[self.secretArgIndex] = str(val)
        else:
            val = 42
            if self.asFile:
                tmpfile, path = tempfile.mkstemp()
                os.write(tmpfile, val)
                os.close(tmpfile)
                self.args[self.secretArgIndex] = path
            else:
                self.args[self.secretArgIndex] = str(val)
        return val, path

    def rndArg(self):
        val, path = self._rand()
        return val, path

    def fixedArg(self):
        val, path = self._fixed()
        return val, path

    def getlibname(self, addr):
        return next(
            (
                os.path.split(info)[1]
                for s, e, _, info, _ in self.mappings
                if s < addr < e
            ),
            -1,
        )

    # we can't call qiling's function (undef mappings), so replicate it here
    # FIXME there has to be a cleaner way
    def getlibbase(self, name):
        return next(
            (s for s, _, _, info, _ in self.mappings if os.path.split(info)[1] == name),
            -1,
        )

    def exec(self):
        self.fixedArg()
        log.info(f"Emulating {self.QLEngine._argv} (dry run)")
        self.QLEngine.run()
        self.mappings = self.QLEngine.mem.get_mapinfo()
        self.QLEngine.stop()
        self.refreshQLEngine()
        if self.dryRunOnly:
            return 0

    def refreshQLEngine(self) -> Qiling:
        self.QLEngine = Qiling(
            [str(self.binPath), *[str(a) for a in self.args]],
            str(self.rootfs),
            console=False,
            verbose=-1,
            multithread=True,
        )
        self.fixRandomness(self.deterministic)

    # TODO rename - as it now inlcudes fixes for broken qiling syscall hooks
    def fixRandomness(self, bool):
        if bool:
            self.QLEngine.add_fs_mapper("/dev/urandom", device_random)
            self.QLEngine.add_fs_mapper("/dev/random", device_random)
            self.QLEngine.add_fs_mapper("/dev/arandom", device_random)
            # ref https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html
            if self.md.arch == CS_ARCH_ARM:
                self.QLEngine.os.set_syscall(403, const_time)
                self.QLEngine.os.set_syscall(384, const_getrandom)
                self.QLEngine.os.set_syscall(78, const_clock_gettimeofday)
                self.QLEngine.os.set_syscall(263, const_clock_gettime)
            if self.md.arch == CS_ARCH_X86 and self.md.mode == CS_MODE_64:
                self.QLEngine.os.set_syscall(318, const_getrandom)
                self.QLEngine.os.set_syscall(96, const_clock_gettimeofday)
                self.QLEngine.os.set_syscall(228, const_clock_gettime)
            if self.md.arch == CS_ARCH_X86 and self.md.mode == CS_MODE_32:
                self.QLEngine.os.set_syscall(403, const_time)
                self.QLEngine.os.set_syscall(13, const_time)
                self.QLEngine.os.set_syscall(355, const_getrandom)
                self.QLEngine.os.set_syscall(78, const_clock_gettimeofday)
                self.QLEngine.os.set_syscall(265, const_clock_gettime)
        else:
            self.QLEngine.add_fs_mapper("/dev/urandom", "/dev/urandom")
            self.QLEngine.add_fs_mapper("/dev/random", "/dev/random")
            self.QLEngine.add_fs_mapper("/dev/arandom", "/dev/arandom")

        # replace broken qiling hooks with working ones:
        self.QLEngine.os.set_syscall("faccessat", ql_fixed_syscall_faccessat)


class MemWatcher(Stage):
    """
    Hooks memory reads
    """

    def __init__(self, binaryLoader: BinaryLoader) -> None:
        self.traces: List[MemTrace] = []
        self.bl = binaryLoader
        self.md = self.bl.md

    def _trace_mem_read(self, ql: Qiling, access, addr, size, value):
        self.currenttrace.add(ql.arch.regs.arch_pc, addr)

    def exec(self, generator, pindex, mt_res):
        secret, path = generator()  # updates the secret
        self.currenttrace = MemTrace(secret)
        self.bl.refreshQLEngine()
        self.bl.QLEngine.hook_mem_read(self._trace_mem_read)
        self.bl.QLEngine.run()
        mt_res[pindex] = self.currenttrace
        self.bl.QLEngine.stop()


class DistributionAnalyzer(Stage):
    def __init__(
        self,
        fixedTraceCollection: MemTraceCollection,
        rndTraceCollection: MemTraceCollection,
        binaryLoader: BinaryLoader,
    ):
        self.fixedTraceCollection = fixedTraceCollection
        self.rndTraceCollection = rndTraceCollection
        self.loader = binaryLoader

    def analyze(self):
        results = []
        for leakAddr in self.fixedTraceCollection.possibleLeaks:
            addrSetFixed = []
            addrSetRnd = []
            # Convert traces to trace per IP/PC
            for t in self.fixedTraceCollection.traces:
                vset = t.trace[leakAddr]
                for v in vset:
                    addrSetFixed.append(v)
            for t in self.rndTraceCollection.traces:
                vset = t.trace[leakAddr]
                for v in vset:
                    addrSetRnd.append(v)
            # Due to non determinism, it is possible that addresses are not present in both sets
            if len(addrSetFixed) == 0 or len(addrSetRnd) == 0:
                log.debug(f"Skipping {hex(leakAddr)}, not present in both sets")
                continue
            # Skip obviously non secret dependent case:
            if set(addrSetFixed) == set(addrSetRnd):
                continue
            # Skip obviously secret dependent, zero variance case:
            if len(set(addrSetFixed)) == 1:
                results.append(leakAddr)
                continue
            _, p_value = stats.mannwhitneyu(addrSetFixed, addrSetRnd)

            if LOGGING_LEVEL == logging.DEBUG:
                fig, ax = plt.subplots(1, 1)
                fig.suptitle(
                    f"IP={hex(leakAddr)} in {self.loader.getlibname(leakAddr)} MWU p={p_value:e}"
                )
                sns.distplot(
                    addrSetFixed,
                    ax=ax,
                    hist=False,
                    kde=True,
                    bins=int(180 / 5),
                    hist_kws={"edgecolor": "black"},
                    kde_kws={"linewidth": 1},
                    label="Fixed secret input",
                )
                sns.distplot(
                    addrSetRnd,
                    ax=ax,
                    hist=False,
                    kde=True,
                    bins=int(180 / 5),
                    hist_kws={"edgecolor": "black"},
                    kde_kws={"linewidth": 1},
                    label="Random secret input",
                )
                plt.savefig(f"debug/{hex(leakAddr)}.png")

            if p_value < 0.01:
                log.info("Exectuted MWU analysis")
                results.append(leakAddr)
        log.info(
            f"filtered {len(self.fixedTraceCollection.possibleLeaks) - len(results)} false positives"
        )
        self.results = results

    def exec(self, *args, **kwargs):
        self.analyze()

    def finalize(self, *args, **kwargs):
        return self.results


class LeakageClassification(Stage):
    def __init__(
        self,
        rndTraceCollection: MemTraceCollection,
        binaryLoader: BinaryLoader,
        possibleLeaks,
        leakageModelFunction,
    ):
        self.rndTraceCollection = rndTraceCollection
        self.possibleLeaks = possibleLeaks
        # The leakage function can return one dimensional data (ex. hamm. dist.) or multidimensional data (bit/byte slices)
        self.leakageModelFunction = leakageModelFunction
        self.loader = binaryLoader
        self.results: Dict[str, float] = {}

    def _key(self, t):
        return self.leakageModelFunction(t[0])

    def analyze(self):
        import numpy as np
        from sklearn.feature_selection import mutual_info_regression

        secrets = set()
        # Convert traces to trace per IP/PC
        for leakAddr in self.possibleLeaks:
            addList = {}
            # Store the secret according to the given leakage model
            for t in self.rndTraceCollection.traces:
                secrets.add(t.secret)
                try:
                    addList[int(t.secret)] = t.trace[leakAddr]
                except ValueError:
                    addList[t.secret] = t.trace[leakAddr]
            mat = np.zeros((len(addList), 1), dtype=np.uint64)
            if not self.leakageModelFunction(
                self.rndTraceCollection.traces[0].secret
            ).shape:
                secretFeatureShape = 1
            else:
                secretFeatureShape = self.leakageModelFunction(
                    self.rndTraceCollection.traces[0].secret
                ).shape
            secretMat = np.zeros((len(addList.keys()), secretFeatureShape))
            addList = OrderedDict(sorted(addList.items(), key=self._key))
            for idx, k in enumerate(addList):
                mat[idx] = np.mean(addList[k])
                secretMat[idx] = self.leakageModelFunction(k)

            # Build a matrix containing the masked secret (according to the given leakage model)

            # For now, let's work with the mutual information instead of the more complex RDC
            # We'll switch to the RDC stat. when we understand the nitty gritty math behind it.

            mival = np.sum(mutual_info_regression(mat, secretMat, random_state=42))
            # log.info(f"mat{hex(leakAddr)} = {mat}")
            # log.info(f"secretMat = {secretMat}")
            if mival < 0.1:
                continue
            log.debug(f"MI score for {hex(leakAddr)}: {mival:.2f}")
            self.results[hex(leakAddr)] = mival

    def exec(self, *args, **kwargs):
        self.analyze()

    def finalize(self, *args, **kwargs):
        return self.results
