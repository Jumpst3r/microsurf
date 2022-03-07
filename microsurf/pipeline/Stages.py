from argparse import ArgumentError
from collections import defaultdict, OrderedDict
import os
import tempfile
from abc import abstractmethod
from pathlib import Path, PurePath

import magic
import matplotlib.pyplot as plt
import scipy.stats as stats
import seaborn as sns
from capstone import Cs, CS_ARCH_ARM, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_32, CS_MODE_64
from capstone.arm_const import *
from capstone.x86_const import *
from qiling import Qiling
from qiling.const import *
from utils.logger import (
    getConsole,
    getLogger,
    LOGGING_LEVEL,
    logging,
    getQillingLogger,
    QILING_VERBOSE,
)
from utils.hijack import *
from .tracetools.Trace import MemTrace, MemTraceCollection
import re

console = getConsole()
log = getLogger()


class Stage:
    @abstractmethod
    def exec(*args, **kwargs):
        pass

    @abstractmethod
    def finalize(*args, **kwargs):
        pass


class BinaryLoader(Stage):
    def __init__(self, path: str, args: list, **kwargs) -> None:
        self.binPath = Path(path)
        self.asm = {}
        self.mem_ip_map = defaultdict(set)
        self.moduleroot = Path(__file__).parent.parent.parent
        self.dryRunOnly = kwargs["dryRunOnly"]
        try:
            self.deterministic = kwargs["deterministic"]
        except KeyError:
            self.deterministic = False
        if self.deterministic:
            log.info("hooking sources of randomness")
        if not os.path.exists(self.binPath):
            log.error(f"target path {str(self.binPath)} not found")
        fileinfo = magic.from_file(path)
        if "80386" in fileinfo:
            if "Linux" in fileinfo:
                self.rootfs = PurePath(self.moduleroot, Path("rootfs/x86_linux"))
                self.md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif "Windows" in fileinfo:
                self.rootfs = PurePath(self.moduleroot, Path("rootfs/x86_windows"))
                self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif "x86" in fileinfo:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
            if "Linux" in fileinfo:
                self.rootfs = PurePath(self.moduleroot, Path("rootfs/x8664_linux"))
            elif "Windows" in fileinfo:
                self.rootfs = PurePath(self.moduleroot, Path("rootfs/x8664_windows"))
        elif "ARM" in fileinfo:
            self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            if "Linux" in fileinfo:
                self.rootfs = PurePath(self.moduleroot, Path("rootfs/arm_linux"))
            else:
                log.info(fileinfo)
                log.error("Target architecture not implemented")
                exit(-1)
        else:
            log.info(fileinfo)
            log.error("Target architecture not implemented")
            exit(-1)
        if "dynamic" in fileinfo:
            log.warn(
                f"Detected dynamically linked binary, ensure that the appropriate shared objects are available in {self.rootfs}"
            )
        else:
            self.rootfs = tempfile.mkdtemp()
            log.info(f"detected static binary, jailing to {self.rootfs}")
        try:
            self.QLEngine = Qiling(
                [str(self.binPath), *args],
                str(self.rootfs),
                log_override=getQillingLogger(),
                verbose=QILING_VERBOSE,
            )
            self.fixRandomness(self.deterministic)
        except Exception as e:
            log.error(f"Qilling initialization failed: {str(e)}")
            exit(-1)
        try:
            self.exec()
            log.info("Looks like binary is supported")
        except Exception as e:
            log.error(f"Emulation dry run failed: {str(e)}")
            exit(-1)
        self.md.detail = True
        self.QLEngine.os.stdout

    def exec(self) -> None:
        log.info(f"Emulating {self.QLEngine._argv} (dry run)")
        self.QLEngine.run()
        self.QLEngine.stop()
        self.refreshQLEngine([0])
        if self.dryRunOnly:
            return 0

    def refreshQLEngine(self, args) -> Qiling:
        self.QLEngine = Qiling(
            [str(self.binPath), *[str(a) for a in args]],
            str(self.rootfs),
            console=False,
            verbose=-1,
        )
        self.fixRandomness(self.deterministic)

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


class FindMemOps(Stage):
    """
    Hooks all code and records any oerands which likely perform memory accesses along with a computation of the target memory address
    Will likely return false positives (lea eax, [..]) but the target addresses are then watched for memory accesses in phase II
    (Class MemWatcher) and these false positives will be filtered.
    """

    def __init__(self, binaryLoader: BinaryLoader) -> None:
        self.traces = []
        self.bl = binaryLoader
        self.md = binaryLoader.md
        self.secret = None

    def _trace_mem_op(self, ql: Qiling, address, size):
        buf = ql.mem.read(address, size)
        for i in self.md.disasm(buf, address):
            if len(i.operands) == 2:
                if i.operands[1].type in [ARM_OP_MEM, X86_OP_MEM]:
                    # We cannot directly trace memory reads for ARM
                    # though this is not a prob since only LDR* ops performs
                    # a memory read !
                    if self.md.arch == CS_ARCH_ARM and not re.compile("^ldr.*").match(
                        i.mnemonic
                    ):
                        continue
                    memop_src = i.operands[1].mem
                    try:
                        memaddr = hex(
                            ql.arch.regs.read(i.reg_name(memop_src.base))
                            + (
                                0
                                if not memop_src.index
                                else ql.arch.regs.read(i.reg_name(memop_src.index))
                            )
                            * memop_src.scale
                            + memop_src.disp
                        )
                    except Exception as e:
                        # The above computation will fail if the value between [.] is not a real
                        # memory address. In that case we just ignore it anyways.
                        continue
                    self.bl.asm[hex(address)] = i.mnemonic + " " + i.op_str
                    if self.bl.asm[hex(address)] == "movzx  eax, BYTE PTR [rax + rdx]":
                        log.info(f"{self.secret}, {memaddr}")
                    self.currenttrace.add(address, memaddr)

    def exec(self, secret):
        self.bl.refreshQLEngine([secret])
        self.bl.QLEngine.hook_code(self._trace_mem_op)
        self.secret = secret
        self.currenttrace = MemTrace(secret)
        self.bl.QLEngine.run()
        self.bl.QLEngine.stop()
        self.traces.append(self.currenttrace)

    def finalize(self):
        assert len(self.traces) > 0
        self.memTraceDetectionCollection = MemTraceCollection(self.traces, self.bl)
        return self.memTraceDetectionCollection


class MemWatcher(Stage):
    """
    Hooks memory reads for a set of addresses returned by the FindMemOps class.
    """

    def __init__(
        self, binaryLoader: BinaryLoader, memTraceCollection: MemTraceCollection
    ) -> None:
        self.traces = []
        self.bl = binaryLoader
        self.memTraceDetectionCollection = memTraceCollection
        self.md = self.bl.md

    def _trace_mem_read(self, ql: Qiling, access, addr, size, value):
        if ql.arch.regs.arch_pc in self.memTraceDetectionCollection.possibleLeaks:
            self.currenttrace.add(ql.arch.regs.arch_pc, addr)

    def _trace_mem_op_fast(self, ql: Qiling, address, size):
        # The unicorn emulation framework might not support reading the pc in a read_mem hook for ARM !
        # https://github.com/unicorn-engine/unicorn/issues/358#issuecomment-169214744
        # so for ARM we use a code hook similar to phase I
        # TODO: Patch Unicorn / Qiling if time permits

        # Only process potential leaks:
        if address not in self.memTraceDetectionCollection.possibleLeaks:
            return
        buf = ql.mem.read(address, size)
        for i in self.md.disasm(buf, address):
            if len(i.operands) == 2:
                if i.operands[1].type in [ARM_OP_MEM, X86_OP_MEM]:
                    memop_src = i.operands[1].mem
                    memaddr = hex(
                        ql.arch.regs.read(memop_src.base)
                        + ql.arch.regs.read(memop_src.index) * memop_src.scale
                        + memop_src.disp
                    )
                    self.currenttrace.add(address, int(memaddr, 16))

    def exec(self, secret):
        self.bl.refreshQLEngine([secret])
        if self.bl.md.arch != CS_ARCH_ARM:
            # Unicorn supports reading PC in mem hook
            self.bl.QLEngine.hook_mem_read(self._trace_mem_read)
        else:
            self.bl.QLEngine.hook_code(self._trace_mem_op_fast)
        self.currenttrace = MemTrace(secret)
        self.bl.QLEngine.run()
        self.traces.append(self.currenttrace)
        self.bl.QLEngine.stop()

    def finalize(self):
        assert len(self.traces) > 0
        self.memTraceDetectionCollection = MemTraceCollection(self.traces, self.bl)
        mtc = MemTraceCollection(self.traces, self.bl)
        return mtc


class DistributionAnalyzer(Stage):
    def __init__(
        self,
        fixedTraceCollection: MemTraceCollection,
        rndTraceCollection: MemTraceCollection,
        binaryLoader: BinaryLoader,
    ):
        self.fixedTraceCollection = fixedTraceCollection
        self.rndTraceCollection = rndTraceCollection
        self.asm = binaryLoader.asm

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
                    f"IP={hex(leakAddr)} ({self.asm[hex(leakAddr)]}) MWU p={p_value:e}"
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
                plt.savefig(f"{hex(leakAddr)}.png")

            if p_value < 0.01:
                results.append(leakAddr)
        log.info(
            f"filtered {len(self.fixedTraceCollection.possibleLeaks) - len(results)} false positives"
        )
        self.results = results

    def exec(self, *args, **kwargs):
        self.analyze()

    def finalize(self, *args, **kwargs):
        return self.results


# FIXME: This clearly does not work. Investigate tommorow
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
        self.asm = binaryLoader.asm
        self.results = {}

    def analyze(self):
        import numpy as np
        from sklearn.feature_selection import mutual_info_regression
        from sklearn.feature_selection import mutual_info_classif

        secrets = set()
        # Convert traces to trace per IP/PC
        for leakAddr in self.possibleLeaks:
            addList = {}
            # Store the secret according to the given leakage model
            for t in self.rndTraceCollection.traces:
                secrets.add(t.secret)
                addList[int(t.secret)] = t.trace[leakAddr]
            # get the number of different addresses:
            distinctAdd = set()
            for _, t in addList.items():
                for a in t:
                    distinctAdd.add(a)
            distinctAdd = sorted(list(distinctAdd))
            # Build matrix with entries (i,j) being with # of times that address a_i as been accessed in trace j
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
            addList = OrderedDict(sorted(addList.items(), key=lambda t: t[0]))
            for idx, k in enumerate(addList):
                mat[idx] = np.mean(addList[k])
                secretMat[idx] = self.leakageModelFunction(k)

            # Build a matrix containing the masked secret (according to the given leakage model)

            # For now, let's work with the mutual information instead of the more complex RDC
            # We'll switch to the RDC stat. when we understand the nitty gritty math behind it.

            mival = np.sum(mutual_info_regression(mat, secretMat, random_state=42))
            # log.info(f"mat{hex(leakAddr)} = {mat}")
            # log.info(f"secretMat = {secretMat}")
            log.debug(f"MI score for {hex(leakAddr)}: {mival:.2f}")
            if mival < 0.2:
                # filter bad scores
                continue
            self.results[hex(leakAddr)] = mival

    def exec(self, *args, **kwargs):
        self.analyze()

    def finalize(self, *args, **kwargs):
        return self.results
