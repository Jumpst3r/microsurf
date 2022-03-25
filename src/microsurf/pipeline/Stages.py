import logging
import os
import random
import tempfile
import time
import traceback
from collections import OrderedDict
from datetime import datetime
from functools import lru_cache
from pathlib import Path, PurePath
from typing import Dict, List, Tuple
import matplotlib.ticker as ticker

import magic
import matplotlib.pyplot as plt
import numpy as np
import ray
import scipy.stats as stats
import seaborn as sns
from capstone import CS_ARCH_ARM, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, Cs
from microsurf.pipeline.LeakageModels import getCryptoModels, identity
from qiling import Qiling
import microsurf

from ..utils.hijack import (
    const_clock_gettime,
    const_clock_gettimeofday,
    const_getrandom,
    const_time,
    device_random,
    ql_fixed_syscall_faccessat,
    syscall_exit_group,
)
from ..utils.logger import LOGGING_LEVEL, getConsole, getLogger, getQilingLogger
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
        self.dryRunOnly = kwargs["dryRunOnly"]
        self.args = args
        self.mappings = None
        self.OLDVAL = None
        self.OLDPATH = None
        self.emulationruntime = None
        self.runtime = None
        self.rootfs = kwargs.get("jail", None)
        self.QLEngine: Qiling = None
        self.deterministic = kwargs.get("deterministic", False)
        self.rndGen = kwargs.get("rndGen", None)
        self.asFile = kwargs.get("asFile", False)
        self.sharedObjects = kwargs.get("sharedObjects", [])
        self.ignoredObjects = []
        self.newArgs = self.args.copy()
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
        self.filemagic = fileinfo
        if "80386" in fileinfo:
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
                f"Detected dynamically linked binary, ensure that the appropriate shared objects are available under {self.rootfs}"
            )
            self.dynamic = True
            log.info(f"rootfs = {self.rootfs}")
        else:
            self.dynamic = False
            if not self.rootfs:
                self.rootfs = PurePath(tempfile.mkdtemp())
            log.info(f"detected static binary, jailing to {self.rootfs}")
            if self.sharedObjects:
                log.warn(
                    "You provided a list of shared objects - but the target binary is static. Ignoring objects."
                )
        try:
            # initialize args;
            val, path = self.rndArg()
            self.QLEngine = Qiling(
                [str(self.binPath), *self.newArgs],
                str(self.rootfs),
                log_override=getQilingLogger(),
                verbose=1,
                console=True,
                multithread=True,
            )
            if path:
                self.QLEngine.add_fs_mapper(path.split("/")[-1], path.split("/")[-1])
            self.fixRandomness(self.deterministic)
        except FileNotFoundError as e:
            if ".so" in str(e):
                log.error(
                    f"Shared object {str(e.filename)} not found in emulation root {self.rootfs}"
                )
                log.debug(e)
                exit(1)
        try:
            starttime = datetime.now()
            self.exec()
            endtime = datetime.now()
            self.emulationruntime = str((endtime - starttime))
            console.rule(
                f"Looks like binary is supported (emulated in {self.emulationruntime})"
            )
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
                self.newArgs[self.secretArgIndex] = path.split("/")[-1]
            else:
                self.newArgs[self.secretArgIndex] = val
        else:
            if self.asFile:
                val = random.randint(0x00, 0xFF)
                tmpfile, path = tempfile.mkstemp()
                os.write(tmpfile, val)
                os.close(tmpfile)
                self.newArgs[self.secretArgIndex] = path
            else:
                val = random.randint(0x00, 0xFF)
                self.newArgs[self.secretArgIndex] = str(val)
        return val, path

    def _fixed(self):
        if not self.OLDVAL:
            self.OLDVAL, self.OLDPATH = self.rndArg()
        return self.OLDVAL, self.OLDPATH

    def rndArg(self):
        return self._rand()

    def fixedArg(self):
        return self._fixed()

    def validateObjects(self):
        for obname in self.sharedObjects:
            base = self.getlibbase(obname)
            if base != -1:
                log.info(f"Located shared object {obname} (base {hex(base)})")
            else:
                log.error(
                    "you provided a shared object name which was not found in memory."
                )
                exit(-1)
        for _, _, _, label, c in self.mappings:
            labelIgnored = True
            for obname in self.sharedObjects:
                if obname in label or self.binPath.name in label:
                    labelIgnored = False
            if labelIgnored and ((" " in label) or c):
                if c and self.binPath.name not in c.split("/")[-1]:
                    self.ignoredObjects.append(label)
                elif not c:
                    self.ignoredObjects.append(label)

        self.ignoredObjects = list(set(self.ignoredObjects))

        log.info(f"The following objects are not traced {self.ignoredObjects}")

    def getlibname(self, addr):
        return next(
            (label for s, e, _, label, _ in self.mappings if s < addr < e),
            -1,
        )

    # we can't call qiling's function (undef mappings), so replicate it here
    # FIXME there has to be a cleaner way
    @lru_cache(maxsize=None)
    def getlibbase(self, name):
        return next(
            (s for s, _, _, label, _ in self.mappings if str(name) in label),
            -1,
        )

    @lru_cache(maxsize=None)
    def issharedObject(self, addr):
        return next(
            (
                not bool(container)
                for s, e, _, _, container in self.mappings
                if s < addr < e
            ),
            False,
        )

    def exec(self):
        self.fixedArg()
        console.rule(f"Emulating {self.QLEngine._argv} (dry run)")
        log.info(f"args={self.QLEngine._argv}")
        self.QLEngine.run()
        self.mappings = self.QLEngine.mem.get_mapinfo()
        self.validateObjects()
        self.QLEngine.stop()
        self.refreshQLEngine()
        if self.dryRunOnly:
            return 0

    def refreshQLEngine(self) -> Qiling:
        self.QLEngine = Qiling(
            [str(self.binPath), *[str(a) for a in self.args]],
            str(self.rootfs),
            console=True,
            log_override=getQilingLogger(),
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
        self.QLEngine.os.set_syscall("exit_group", syscall_exit_group)


@ray.remote
class MemWatcher(Stage):
    """
    Hooks memory reads
    """

    def __init__(
        self,
        binpath,
        args,
        rootfs,
        ignoredObjects,
        mappings,
        locations=None,
        deterministic=False,
    ) -> None:
        self.traces: List[MemTrace] = []
        self.binPath = binpath
        self.args = args
        self.rootfs = rootfs
        self.locations = (
            {l: 1 for l in locations} if locations is not None else locations
        )
        self.ignoredObjects = ignoredObjects
        self.mappings = mappings
        self.deterministic = deterministic

    def _trace_mem_read(self, ql: Qiling, access, addr, size, value):
        pc = ql.arch.regs.arch_pc
        if self.locations is None:
            self.currenttrace.add(pc, addr)
        elif pc in self.locations:
            self.currenttrace.add(pc, addr)

    def getlibname(self, addr):
        return next(
            (label for s, e, _, label, _ in self.mappings if s < addr < e),
            -1,
        )

    def exec(self, secret):
        start_time = time.time()
        args = self.args.copy()
        args[args.index("@")] = secret
        self.QLEngine = Qiling(
            [str(self.binPath), *[str(a) for a in args]],
            str(self.rootfs),
            console=False,
            multithread=True,
            libcache=True,
        )
        self.currenttrace = MemTrace(secret)
        self.QLEngine.hook_mem_read(self._trace_mem_read)
        # duplicate code. Ugly - fixme.
        if self.deterministic:
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
        self.QLEngine.run()
        self.QLEngine.stop()
        dropset = []
        for t in self.currenttrace.trace:
            if self.getlibname(t) in self.ignoredObjects:
                dropset.append(t)
        self.currenttrace.remove(dropset)
        endtime = time.time()
        self.tracetime = endtime - start_time

    def getResults(self):
        return self.currenttrace, self.tracetime


class DistributionAnalyzer(Stage):
    def __init__(
        self,
        fixedTraceCollection: MemTraceCollection,
        rndTraceCollection: MemTraceCollection,
        binaryLoader: BinaryLoader,
        deterministic: bool,
    ):
        self.fixedTraceCollection = fixedTraceCollection
        self.rndTraceCollection = rndTraceCollection
        log.debug(f"len rndTraces: {len(self.rndTraceCollection)}")
        log.debug(f"len fixedTraces: {len(self.fixedTraceCollection)}")
        log.debug(f"possible leaks: {self.rndTraceCollection.possibleLeaks}")
        self.loader = binaryLoader
        self.deterministic = deterministic

    def analyze(self):
        results = []
        skipped = 0
        for leakAddr in self.rndTraceCollection.possibleLeaks:
            addrSetFixed = []
            addrSetRnd = []
            # Convert traces to trace per IP/PC
            libname = self.loader.getlibname(leakAddr)

            offset = (
                leakAddr - self.loader.getlibbase(libname)
                if ".so" in libname
                else leakAddr
            )
            secret = None
            for t in self.fixedTraceCollection.traces:
                if secret == None:
                    secret = t.secret
                else:
                    assert secret == t.secret
                vset = t.trace[leakAddr]
                for v in vset:
                    assert v > 0
                    addrSetFixed.append(v)
            for t in self.rndTraceCollection.traces:
                vset = t.trace[leakAddr]
                for v in vset:
                    assert v > 0
                    addrSetRnd.append(v)
            if len(addrSetFixed) == 0 or len(addrSetRnd) == 0:
                continue
            _, p_value = stats.mannwhitneyu(addrSetFixed, addrSetRnd)
            # _, p_value = stats.ks_2samp(addrSetFixed, addrSetRnd)

            if False and LOGGING_LEVEL == logging.DEBUG:
                fig, ax = plt.subplots(1, 1)
                fig.suptitle(
                    f"IP={hex(leakAddr)} offset={hex(offset)} in {libname} Added :{p_value < 0.01}, {p_value:e}"
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
            target_p_val = 0.01
            # zero var fixed and pos. var. rand should be detected.
            if np.var(addrSetFixed) == 0 and np.var(addrSetRnd) > 0:
                target_p_val = 0.5
            if p_value < target_p_val or self.deterministic:
                log.debug(
                    f"{libname}-{hex(offset)} len fixed / rnd = {len(addrSetFixed)}, {len(addrSetRnd)}"
                )

                results.append(leakAddr)
                log.debug(f"Added {libname}-{hex(offset)} with p_value {p_value}")
            else:
                skipped += 1
                log.debug(f"{libname}-{hex(offset)} skipped (p={p_value})")
                log.debug(
                    f"{libname}-{hex(offset)} len fixed / rnd = {len(addrSetFixed)}, {len(addrSetRnd)}"
                )
                log.debug(
                    f"{libname}-{hex(offset)} var fixed / var rnd = {np.std(addrSetFixed)}, {np.std(addrSetRnd)}"
                )
        log.info(
            f"filtered {len(self.rndTraceCollection.possibleLeaks) - len(results)} false positives, {skipped} through KS analysis"
        )
        log.info(f"total leaks: {len(results)}")
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
    ):
        self.rndTraceCollection = rndTraceCollection
        self.possibleLeaks = possibleLeaks
        # The leakage function can return one dimensional data (ex. hamm. dist.) or multidimensional data (bit/byte slices)
        self.loader = binaryLoader
        self.results: Dict[str, float] = {}
        self.KEYLEN = None

    def _key(self, t):
        return t[0]

    def analyze(self):
        import numpy as np
        from sklearn.feature_selection import mutual_info_regression

        secrets = [t.secret for t in self.rndTraceCollection.traces]
        slen = -1
        fixedLenSecrets = True
        for s in secrets:
            secret = int(s, 16)
            if slen == -1:
                slen = len(s) * 4
            elif slen != len(s) * 4:
                log.error(slen)
                log.error(s)
                fixedLenSecrets = False
        if fixedLenSecrets:
            CRYPTO_MODELS = getCryptoModels(slen)
            log.info(f"using fixed key leakage models (KEYLEN: {slen})")
            self.KEYLEN = slen
        else:
            log.info("using variable key leakage models.")
            CRYPTO_MODELS = getCryptoModels(0)
        # Convert traces to trace per IP/PC
        for leakAddr in self.possibleLeaks:
            addList = {}
            # Store the secret according to the given leakage model
            for t in self.rndTraceCollection.traces:
                if t.trace[leakAddr]:
                    addList[int(t.secret, 16)] = t.trace[leakAddr]
            # check that we have the same number of targets
            tlen = min([len(l) for l in list(addList.values())])
            for k, v in addList.items():
                if len(v) != tlen:
                    addList[k] = v[:tlen]
            mat = np.zeros(
                (len(addList), len(list(addList.values())[0])), dtype=np.int32
            )
            secretMat = np.zeros((len(addList.keys()), 1))
            addList = OrderedDict(sorted(addList.items(), key=self._key))
            for idx, k in enumerate(addList):
                addr = addList[k]
                mat[idx] = [
                    a - self.loader.getlibbase(self.loader.getlibname(a)) for a in addr
                ]
                secretMat[idx] = [identity()(k)]

            from .NeuralLeakage import NeuralLeakageModel

            log.info(f"learning optimal leakage model for PC {hex(leakAddr)}")
            nleakage = NeuralLeakageModel(mat, secretMat, self.KEYLEN, leakAddr)
            nleakage.train()

            # log.info(f"mat{hex(leakAddr)} = {mat}")
            # log.info(f"secretMat = {secretMat}")
            # log.info(f"MI score for {hex(leakAddr)}: {mival:.2f}")
            log.info(f"MI score for {hex(leakAddr)}: {nleakage.getMI()}")
            self.results[hex(leakAddr)] = {nleakage, nleakage.getMI()}

    def exec(self, *args, **kwargs):
        self.analyze()

    def finalize(self, *args, **kwargs):
        return self.results


class LeakageRegression(Stage):
    def __init__(
        self,
        rndTraceCollectionTrain: MemTraceCollection,
        rndTraceCollectionTest: MemTraceCollection,
        binaryLoader: BinaryLoader,
        possibleLeaks,
        mivals,
    ):
        self.rndTraceCollectionTrain = rndTraceCollectionTrain
        self.rndTraceCollectionTest = rndTraceCollectionTest
        self.possibleLeaks = possibleLeaks
        self.loader = binaryLoader
        self.results: Dict[int, float] = {}
        self.mivals = mivals

    def _key(self, t):
        return t[0]

    def convertTraces(self, rndTraceCollection, leakAddr):
        addList = {}
        # Store the secret according to the given leakage model
        for t in rndTraceCollection.traces:
            if t.trace[leakAddr]:
                addList[int(t.secret, 16)] = t.trace[leakAddr]
        # check that we have the same number of targets
        tlen = min([len(l) for l in list(addList.values())])
        for k, v in addList.items():
            if len(v) != tlen:
                addList[k] = v[:tlen]
        mat = np.zeros((len(addList), len(list(addList.values())[0])), dtype=np.uint64)
        secretMat = np.zeros((len(addList.keys()), 1))
        addList = OrderedDict(sorted(addList.items(), key=self._key))
        for idx, k in enumerate(addList):
            addr = addList[k]
            mat[idx] = [
                a - self.loader.getlibbase(self.loader.getlibname(a)) for a in addr
            ]
            secretMat[idx] = self.leakageModelFunction(k)
        return mat, secretMat, tlen

    def regress(self):
        import numpy as np
        from sklearn.linear_model import LinearRegression
        from sklearn import tree
        import seaborn as sns

        # Convert traces to trace per IP/PC
        log.debug(f"leak locations in LeakRegression: {self.possibleLeaks}")
        for leakAddr in self.possibleLeaks:
            self.leakageModelFunction = list(self.mivals[hex(leakAddr)].keys())[0]

            X_train, Y_train, tlen = self.convertTraces(
                self.rndTraceCollectionTrain, leakAddr
            )
            X_test, Y_test, tlen = self.convertTraces(
                self.rndTraceCollectionTest, leakAddr
            )

            if "bit" in str(self.leakageModelFunction):  # two class classification
                # should be named classifier but this makes the code shorter
                regressor = tree.DecisionTreeClassifier(max_depth=2).fit(
                    X_train, Y_train.ravel()
                )
                classcore = regressor.score(X_test, Y_test.ravel())
                regscore = 0
            else:
                regressor = LinearRegression().fit(X_train, Y_train.ravel())
                regscore = regressor.score(X_test, Y_test.ravel())
                classcore = 0
            if regscore > classcore:
                log.info(
                    f"Linear regression score for {hex(leakAddr - self.loader.getlibbase(self.loader.getlibname(leakAddr)))}: {regscore:.2f}"
                )
            else:
                log.info(
                    f"Prediction score for {hex(leakAddr - self.loader.getlibbase(self.loader.getlibname(leakAddr)))}: {classcore:.2f}"
                )
            if LOGGING_LEVEL == logging.DEBUG:
                if tlen >= 2:
                    PLOTSECRETS = 5 if Y_test.shape[0] >= 5 else Y_test.shape[0]
                    heatmat = np.zeros(
                        (
                            PLOTSECRETS,
                            int(X_test[:PLOTSECRETS].max())
                            - int(X_test[:PLOTSECRETS].min())
                            + 1,
                        )
                    )
                    absvals = X_test - X_test[:PLOTSECRETS].min()
                    for rowid, _ in enumerate(X_test[:PLOTSECRETS]):
                        for colid, _ in enumerate(X_test.T):
                            heatmat[rowid][absvals[rowid, colid]] = rowid + 1
                    sns.set(font_scale=0.4)
                    plt.figure(figsize=(7, 3))
                    hfig = sns.heatmap(
                        heatmat,
                        cbar=False,
                        xticklabels=[
                            hex(int(s)) if int(s) % 128 == 0 else ""
                            for s in range(
                                X_test[:PLOTSECRETS].min(), X_test[:PLOTSECRETS].max()
                            )
                        ],
                        cmap="cubehelix_r",
                        yticklabels=[hex(int(s[0])) for s in Y_test[:PLOTSECRETS]],
                    )
                    hfig.set(
                        xlabel="Memory offset",
                        ylabel=f"{str(self.leakageModelFunction)}(secret)",
                    )

                    fig = hfig.get_figure()
                    fig.savefig(f"debug/heatmap-{leakAddr}.png", dpi=300)
                if tlen == 1:
                    plt.style.use("seaborn")
                    fig, ax = plt.subplots(1, 1)
                    figtitle = f"Trace regression for PC={hex(leakAddr)} (lib = {self.loader.getlibname(leakAddr)})\n score={regscore:.2f}"
                    fig.suptitle(figtitle)
                    if "bit" in str(self.leakageModelFunction):
                        ax.scatter(X_test, Y_test)
                        # ax.scatter(X_test, regressor.predict(X_test), c='g')
                    else:
                        ax.scatter(X_test, Y_test)
                        ax.plot(X_test, regressor.predict(X_test))
                    ax.set_xlabel(f"{str(self.leakageModelFunction)}(secret)")
                    ax.set_ylabel("offset")
                    plt.savefig(f"debug/reg-{hex(leakAddr)}.png")
                    plt.close()
            self.results[leakAddr] = (regscore, classcore)

    def exec(self, *args, **kwargs):
        self.regress()

    def finalize(self, *args, **kwargs):
        return self.results
