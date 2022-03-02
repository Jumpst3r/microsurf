from collections import defaultdict
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
from utils.logger import getConsole, getLogger, LOGGING_LEVEL, logging

from .tracetools.Trace import MemTrace, MemTraceCollection

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
    def __init__(self, path: str, args: list, dryRunOnly=False) -> None:
        self.binPath = Path(path)
        self.asm = {}
        self.mem_ip_map = defaultdict(set)
        self.moduleroot = Path(__file__).parent.parent.parent
        self.dryRunOnly = dryRunOnly
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
                [str(self.binPath), *args], str(self.rootfs), console=False, verbose=-1
            )
            self.QLEngine.add_fs_mapper("/dev/urandom", "/dev/urandom")

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

    def exec(self) -> None:
        log.info(f"Emulating {self.QLEngine._argv} (dry run)")
        self.QLEngine.run()
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
        self.QLEngine.add_fs_mapper("/dev/urandom", "/dev/urandom")


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

    def _trace_mem_op(self, ql: Qiling, address, size):
        buf = ql.mem.read(address, size)
        for i in self.md.disasm(buf, address):
            if len(i.operands) == 2:
                if i.operands[1].type in [ARM_OP_MEM, X86_OP_MEM]:
                    # We cannot directly trace memory reads for ARM
                    # though this is not a prob since only LDR performs
                    # a memory read !
                    if self.md.arch == CS_ARCH_ARM and i.mnemonic != "ldr":
                        continue
                    memop_src = i.operands[1].mem
                    memaddr = hex(
                        ql.arch.regs.read(memop_src.base)
                        + ql.arch.regs.read(memop_src.index) * memop_src.scale
                        + memop_src.disp
                    )
                    self.bl.asm[hex(address)] = i.mnemonic + " " + i.op_str
                    self.currenttrace.add(address, memaddr)

    def exec(self, secret):
        self.bl.refreshQLEngine([secret])
        self.bl.QLEngine.hook_code(self._trace_mem_op)
        self.currenttrace = MemTrace(secret)
        self.bl.QLEngine.run()
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
