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
    def exec(*args,**kwargs):
        pass
    @abstractmethod
    def finalize(*args,**kwargs):
        pass

class BinaryLoader(Stage):
    def __init__(self, path: str, args: list, dryRunOnly=False) -> None:
        self.binPath = Path(path)
        self.asm = {}
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
            log.warn(f"Detected dynamically linked binary, ensure that the appropriate shared objects are available in {self.rootfs}")
        else:
            self.rootfs = tempfile.mkdtemp()
            log.info(f"detected static binary, jailing to {self.rootfs}")
        try:
            self.QLEngine = Qiling([str(self.binPath), *args], str(self.rootfs), console=False, verbose=-1)
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
        if self.dryRunOnly: return 0

    def refreshQLEngine(self, args)-> Qiling:
        self.QLEngine = Qiling([str(self.binPath), *[str(a) for a in args]], str(self.rootfs), console=False, verbose=-1)
        self.QLEngine.add_fs_mapper("/dev/urandom", "/dev/urandom")

class MemTracer(Stage):
    def __init__(self, binaryLoader: BinaryLoader, coarse=True, possibleLeaks=None) -> None:
        self.traces = []
        self.bl = binaryLoader
        self.md = binaryLoader.md
        self.possibleLeaks = possibleLeaks
        if not coarse:
            self.stageName = "LeakConfirm"
        else:
            self.stageName = "LeakDetection"

    def _trace_mem_op(self, ql: Qiling, address, size, user_data=None):
        if (user_data != None and user_data == address) or user_data == None:
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
                        st = f"-> tracing \t {i.mnemonic} \t [{memaddr}]".ljust(
                            80, " "
                        )
                        #console.print(st, end="\r", overflow='ellipsis')
                        self.bl.asm[hex(address)] = i.mnemonic + " " + i.op_str
                        self.currenttrace.add(address, memaddr)
    

    def __str__(self) -> str:
        return self.stageName

    def exec(self, secret):
        self.bl.refreshQLEngine([secret])
        if self.stageName == "LeakDetection":
            self.bl.QLEngine.hook_code(self._trace_mem_op)
        if self.stageName == "LeakConfirm":
            if len(self.possibleLeaks) == 0:
                log.error(f"Stage {self.stageName} failed: No possible leaks found")
                exit(-1)
            for addr in self.possibleLeaks:
                self.bl.QLEngine.hook_code(self._trace_mem_op, addr)
        self.currenttrace = MemTrace(secret)
        self.bl.QLEngine.run()
        self.traces.append(self.currenttrace)
    
    def finalize(self):
        if self.stageName == "LeakDetection":
            assert len(self.traces) > 0
            self.memTraceDetectionCollection = MemTraceCollection(self.traces, self.bl, prune=True)
            self.possibleLeaks = self.memTraceDetectionCollection.possibleLeaks
            return self.possibleLeaks
        if self.stageName == "LeakConfirm":
            assert len(self.traces) > 0
            self.memTraceDetectionCollection = MemTraceCollection(self.traces, self.bl)
            return self.memTraceDetectionCollection

class DistributionAnalyzer(Stage):
    def __init__(self, fixedTraceCollection : MemTraceCollection, rndTraceCollection :MemTraceCollection, possibleLeaks, binaryLoader : BinaryLoader):
        self.fixedTraceCollection = fixedTraceCollection
        self.rndTraceCollection = rndTraceCollection
        self.possibleLeaks = possibleLeaks
        self.asm = binaryLoader.asm
    def analyze(self):
        results = []
        for leakAddr in self.possibleLeaks:
            addrSetFixed = []
            addrSetRnd = []
            for t in self.fixedTraceCollection.traces:
                vset = t.trace[leakAddr]
                for v in vset:
                    addrSetFixed.append(int(v, 16))
            for t in self.rndTraceCollection.traces:
                vset = t.trace[leakAddr]
                for v in vset:
                    addrSetRnd.append(int(v, 16))
            # Due to non determinism, it is possible that addresses are not present in both sets
            if (len(addrSetFixed) == 0 or len(addrSetRnd) == 0):
                log.warning(f"Skipping {hex(leakAddr)}, not present in both sets")
                continue
            # Skip obviously non secret dependent case:
            if (addrSetFixed == addrSetRnd):
                continue
            # Skip obviously secret dependent, zero variance case:
            if len(set(addrSetFixed)) == 1:
                results.append(leakAddr)
                continue
            _,p_value = stats.mannwhitneyu(addrSetFixed, addrSetRnd)
            
            if LOGGING_LEVEL == logging.DEBUG:
                fig, ax = plt.subplots(1, 1)
                fig.suptitle(f'IP={hex(leakAddr)} ({self.asm[hex(leakAddr)]}) MWU p={p_value:e}')
                sns.distplot(addrSetFixed, ax=ax, hist=False, kde=True, 
                    bins=int(180/5),
                    hist_kws={'edgecolor':'black'},
                    kde_kws={'linewidth': 1},
                    label="Fixed secret input",
                    )
                sns.distplot(addrSetRnd, ax=ax, hist=False, kde=True, 
                    bins=int(180/5),
                    hist_kws={'edgecolor':'black'},
                    kde_kws={'linewidth': 1},
                    label="Random secret input"
                    )
                plt.savefig(f'{hex(leakAddr)}.png')
          
            if p_value < 0.01:
                results.append(leakAddr)
        log.info(f"filtered {len(self.possibleLeaks) - len(results)} false positives")
        self.results = results
            

    def exec(self, *args, **kwargs):
        self.analyze() 

    def finalize(self, *args, **kwargs):
        return self.results
