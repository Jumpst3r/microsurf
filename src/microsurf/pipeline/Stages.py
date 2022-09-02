import logging
import os
import shutil
import sys
import tempfile
import traceback
import uuid
from datetime import datetime
from functools import lru_cache
from pathlib import Path, PurePath
from typing import Dict, List
import magic
import ray
from capstone import CS_ARCH_ARM, CS_ARCH_PPC, CS_ARCH_RISCV, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_MIPS32, \
    CS_ARCH_MIPS, CS_MODE_RISCV64, Cs
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_ARCH, QL_OS

# ECX reg vals
AESNI_ID = 0b00000010000000000000000000000000

from .NeuralLeakage import NeuralLeakageModel
from .tracetools.Trace import MemTrace, PCTrace, TraceCollection
from ..utils.generators import SecretGenerator
from ..utils.hijack import (
    const_clock_gettime,
    const_clock_gettimeofday,
    const_getrandom,
    const_time,
    device_random,
    ql_fixed_syscall_faccessat,
    ql_fixed_syscall_newfstatat,
    syscall_exit_group,
    syscall_futex
)
from ..utils.logger import getConsole, getLogger, getQilingLogger, LOGGING_LEVEL
from ..utils.rayhelpers import ProgressBar

console = getConsole()
log = getLogger()


class BinaryLoader:
    """
    The BinaryLoader class is used to tell the framwork where to located the target binary, shared libraries and to
    specify emulation and general execution settings.

    Args:
        path: The path to the target executable (ELF-linux format, ARM/MIPS/X86/RISCV).
        args: List of arguments to pass, '@' may be used to mark one argument as secret.
        rootfs: The emulation root directory. Has to contain expected shared objects for dynamic binaries.
        rndGen: The function which will be called to generate secret inputs.
        x8664Extensions: List of x86 features, ["DEFAULT"] for all (supported) extensions. Must be subset of: ["DEFAULT", "AESNI", "NONE"]
        sharedObjects: List of shared objects to trace, defaults to tracing everything. Include binary name to also trace the binary.
        deterministic: Force deterministic execution.
        resultDir: Path to the results directory.
    """

    def __init__(
            self,
            path: Path,
            args: List[str],
            rootfs: str,
            rndGen: SecretGenerator,
            x8664Extensions : List[str] = ["DEFAULT", "AESNI"],
            sharedObjects: List[str] = [],
            deterministic: bool = True,
            resultDir: str = "results",
    ) -> None:
        self.binPath = Path(path)
        self.x8664Extensions = x8664Extensions
        self.args = args
        self.rootfs = rootfs
        self.rndGen = rndGen
        self.sharedObjects = sharedObjects
        self.deterministic = deterministic
        self.resultDir = resultDir
        self.ignoredObjects = []
        self.newArgs = self.args.copy()
        self.mappings = None
        self.emulationruntime = None
        self.runtime = None
        self.QLEngine: Qiling = None
        self.executableCode = []
        self.dryRun = False
        self.multithreaded = False
        from microsurf.utils.logger import banner
        console.print(banner)

        try:
            self.secretArgIndex: int = args.index("@")
        except ValueError:
            log.warning('no argument marked as secret dependent - executing as is and exiting (dry run)')
            self.dryRun = True

        if self.deterministic:
            log.info("hooking sources of randomness")
        if not os.path.exists(self.binPath):
            log.error(f"target path {str(self.binPath)} not found")
            exit(1)
        fileinfo = magic.from_file(path)
        self.filemagic = fileinfo
        if "80386" in fileinfo:
            self.ARCH = "X86_32"
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
            self.archtype = QL_ARCH.X86
            self.ostype = QL_OS.LINUX
        elif "x86" in fileinfo:
            self.ARCH = "X86_64"
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
            self.archtype = QL_ARCH.X8664
            self.ostype = QL_OS.LINUX
        elif "ARM" in fileinfo and '64-bit' not in fileinfo:
            log.debug("Detected 32 bit ARM")
            self.ARCH = "ARM"
            self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            self.archtype = QL_ARCH.ARM
            self.ostype = QL_OS.LINUX
        elif "ARM" in fileinfo and "64-bit" in fileinfo:
            log.debug("Detected 64 bit ARM")
            self.ARCH = "ARM64"
            self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self.archtype = QL_ARCH.ARM64
            self.ostype = QL_OS.LINUX
        elif "MIPS32" in fileinfo:
            self.ARCH = "MIPS32"
            self.md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32)
            self.archtype = QL_ARCH.MIPS
            self.ostype = QL_OS.LINUX
        elif "RISC-V" in fileinfo:
            self.ARCH = "RISCV"
            self.md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
            self.archtype = QL_ARCH.RISCV64
            self.ostype = QL_OS.LINUX
        elif "Power" in fileinfo:
            self.ARCH = "POWERPC"
            self.md = Cs(CS_ARCH_PPC, CS_MODE_32)
            self.archtype = QL_ARCH.PPC
            self.ostype = QL_OS.LINUX
        else:
            log.info(fileinfo)
            log.error("Target architecture not implemented")
            exit(1)
        self.uuid = f"{str(uuid.uuid4())[:6]}-{self.binPath.name}-{self.ARCH}"
        self.resultDir += f"/{self.uuid}"
        os.makedirs(self.resultDir + "/" + "assets", exist_ok=True)
        os.makedirs(self.resultDir + "/" + "traces", exist_ok=True)
        if "dynamic" in fileinfo:
            log.warn(
                f"Detected dynamically linked binary, ensure that the appropriate shared objects are available under "
                f"{self.rootfs} "
            )
            self.dynamic = True
            log.info(f"rootfs = {self.rootfs}")
        else:
            self.dynamic = False
            if not self.rootfs:
                self.rootfs = PurePath(tempfile.mkdtemp())
            log.info(f"detected static binary, jailing to {self.rootfs}")
            if self.sharedObjects:
                log.warning(
                    "You provided a list of shared objects - but the target binary is static. Ignoring objects."
                )

    def configure(self) -> int:
        try:
            val = self.rndGen()
            if self.rndGen.asFile:
                os.makedirs(self.rootfs + "/" + "tmp", exist_ok=True)
                dst = self.rootfs.rstrip('/') + val
                shutil.copy(val, dst)
            if not self.dryRun:
                # initialize args;
                nargs = []
                if isinstance(val, list):
                    for idx, a in enumerate(self.newArgs):
                        if idx == self.secretArgIndex:
                            for k in val:
                                nargs.append(k)
                        else:
                            nargs.append(a)
                    self.newArgs = nargs
                else:
                    self.newArgs[self.secretArgIndex] = val

            self.multithreaded = False
            self.QLEngine = Qiling(
                [str(self.binPath), *self.newArgs],
                str(self.rootfs),
                log_override=getQilingLogger(),
                verbose=QL_VERBOSE.DISABLED if LOGGING_LEVEL == logging.INFO else QL_VERBOSE.DEBUG,
                console=True,
                archtype=self.archtype,
                ostype=self.ostype,
                multithread=self.multithreaded,
            )
            self.Cs = self.QLEngine.arch.disassembler
            self.fixSyscalls()
            if self.rndGen.asFile:
                self.QLEngine.add_fs_mapper(val, val)
        except FileNotFoundError as e:
            if ".so" in str(e):
                log.error(
                    f"Shared object {str(e.filename)} not found in emulation root {self.rootfs}"
                )
                log.error(e)
                return 1
            else:
                log.error(e)
                return 1
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
            tback = traceback.format_exc()
            sys.stdout.fileno = lambda: False
            sys.stderr.fileno = lambda: False
            if "cur_thread" in tback and "spawn" not in str(e):
                log.info("re-running with threading support enabled")
                try:
                    self.multithreaded = True
                    self.QLEngine = Qiling(
                        [str(self.binPath), *self.newArgs],
                        str(self.rootfs),
                        log_override=getQilingLogger(),
                        verbose=QL_VERBOSE.DEFAULT if LOGGING_LEVEL == logging.INFO else QL_VERBOSE.DEBUG,
                        console=True,
                        archtype=self.archtype,
                        ostype=self.ostype,
                        multithread=self.multithreaded,
                    )
                    self.fixSyscalls()
                    if self.rndGen.asFile:
                        self.QLEngine.add_fs_mapper(val, val)
                    starttime = datetime.now()
                    self.exec()
                    endtime = datetime.now()
                    self.emulationruntime = str((endtime - starttime))
                    console.rule(
                        f"Looks like binary is supported (emulated in {self.emulationruntime})"
                    )
                except Exception as e:
                    log.error(f"Emulation dry run failed: {str(e)}")
                    if log.level == logging.DEBUG:
                        tback = traceback.format_exc()
                        log.error(tback)
                    return 1
            else:
                log.error(tback)
                return 1
        if self.dryRun:
            log.warn("no arg marked as secret, exiting (emulation successful).")
            return 0

    def validateObjects(self):
        log.info("mappings:")
        for s, e, perm, label, c in self.mappings:
            log.info(f"{hex(s)}-{hex(e)} {perm} {label} {c if c is not None else ''}")
        for obname in self.sharedObjects:
            base = self.getlibbase(obname)
            if base != -1:
                log.info(f"Located shared object {obname} (base {hex(base)})")
            else:
                log.error(
                    "you provided a shared object name which was not found in memory."
                )
                return 1
        for s, e, perm, label, c in self.mappings:
            if "x" not in perm:
                continue
            labelIgnored = True
            if not self.sharedObjects:
                self.executableCode.append((s, e))
            for obname in self.sharedObjects:
                if obname in label:
                    labelIgnored = False
            if labelIgnored:
                self.ignoredObjects.append(label)
            else:
                self.executableCode.append((s, e))

        self.ignoredObjects = list(set(self.ignoredObjects))

        log.info(f"The following objects are not traced {self.ignoredObjects}")
        for (s, e) in self.executableCode:
            log.info(f"Tracing {hex(s)}-{hex(e)}")

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
        console.rule(f"Emulating {self.QLEngine._argv} (dry run)")
        log.info(f"args={self.QLEngine._argv}")
        self.QLEngine.run()
        self.mappings = self.QLEngine.mem.get_mapinfo()
        self.validateObjects()
        self.QLEngine.stop()

    def fixSyscalls(self):
        self.QLEngine.os.set_syscall("faccessat", ql_fixed_syscall_faccessat)
        self.QLEngine.os.set_syscall("newfstatat", ql_fixed_syscall_newfstatat)
        self.QLEngine.os.set_syscall("exit_group", syscall_exit_group)
        if not self.multithreaded:
            self.QLEngine.os.set_syscall("futex", syscall_futex)
        if self.deterministic:
            self.QLEngine.add_fs_mapper("/dev/urandom", device_random)
            self.QLEngine.add_fs_mapper("/dev/random", device_random)
            self.QLEngine.add_fs_mapper("/dev/arandom", device_random)
            self.QLEngine.os.set_syscall('time', const_time)
            self.QLEngine.os.set_syscall('getrandom', const_getrandom)
            self.QLEngine.os.set_syscall('gettimeofday', const_clock_gettimeofday)
            self.QLEngine.os.set_syscall('gettime', const_clock_gettime)
            self.QLEngine.os.set_syscall('clock_gettime', const_clock_gettime)
            self.QLEngine.os.set_syscall('clock_gettime64', const_clock_gettime)
        else:
            self.QLEngine.add_fs_mapper("/dev/urandom", "/dev/urandom")
            self.QLEngine.add_fs_mapper("/dev/random", "/dev/random")
            self.QLEngine.add_fs_mapper("/dev/arandom", "/dev/arandom")

@ray.remote
class MemWatcher:
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
            arch,
            mode,
            locations=None,
            getAssembly=False,
            x8664Extensions=["DEFAULT"],
            deterministic=False,
            multithread=True,
            codeRanges=[],
    ) -> None:
        self.tracetime = None
        self.traces: List[MemTrace] = []
        self.binPath = binpath
        self.arch = arch
        self.mode = mode
        self.args = args
        self.rootfs = rootfs
        self.locations = (
            {l: 1 for l in locations} if locations is not None else locations
        )
        self.getAssembly = getAssembly
        self.x8664Extensions = x8664Extensions
        self.ignoredObjects = ignoredObjects
        self.mappings = mappings
        self.deterministic = deterministic
        self.multithread = multithread
        self.codeRanges = codeRanges
        self.asm = {}

    def _trace_mem(self, ql: Qiling, access, addr, size, value):
        pc = ql.arch.regs.arch_pc
        if self.locations is None:
            self.currenttrace.add(pc, addr)
        elif pc in self.locations:
            self.currenttrace.add(pc, addr)

    def _hook_code(self, ql: Qiling, address: int, size: int):
        if not self.getAssembly:
            return
        pc = ql.arch.regs.arch_pc
        buf = ql.mem.read(address, size)
        for insn in ql.arch.disassembler.disasm(buf, address):
            self.asm[
                hex(pc)
            ] = f"{insn.address:#x}| : {insn.mnemonic:10s} {insn.op_str}"
            if insn.mnemonic.lower() == 'cpuid':
                log.debug(f"[CPUID@{pc:#x}] with EAX={ql.arch.regs.eax:032b}")
                ecxval = 0
                edxval = 0
                if "DEFAULT" not in self.x8664Extensions:
                    if 'AESNI-ONLY' in self.x8664Extensions:
                        ecxval |= AESNI_ID
                    if "NONE" in self.x8664Extensions:
                        ecxval = 0
                        edxval = 0
                    ql.arch.regs.edx = edxval
                    ql.arch.regs.ecx = ecxval
                    ql.arch.regs.arch_pc += 2
    
    def getlibname(self, addr):
        return next(
            (label for s, e, _, label, _ in self.mappings if s < addr < e),
            -1,
        )

    def exec(self, secretString, asFile, secret):
        args = self.args.copy()
        nargs = []
        if isinstance(secretString, list):
            for idx, a in enumerate(args):
                if idx == args.index("@"):
                    for k in secretString:
                        nargs.append(k)
                else:
                    nargs.append(a)
            args = nargs
        else:
            args[args.index("@")] = secretString
        sys.stdout.fileno = lambda: False
        sys.stderr.fileno = lambda: False
        self.QLEngine = Qiling(
            [str(self.binPath), *[str(a) for a in args]],
            str(self.rootfs),
            console=False,
            verbose=QL_VERBOSE.DISABLED,
            archtype=self.mode[0],
            ostype=self.mode[1],
            multithread=self.multithread,
        )
        if asFile:
            self.QLEngine.add_fs_mapper(secretString, secretString)
            dst = self.rootfs.rstrip('/') + secretString
            shutil.copy(secretString, dst)

        self.currenttrace = MemTrace(secret)
        self.QLEngine.hook_mem_read(self._trace_mem)
        self.QLEngine.hook_mem_write(self._trace_mem)


        # no code hooks on x86, as the PC is always correct in the memread hook (not given on other archs)
        if self.arch != CS_ARCH_X86 and not self.getAssembly:
            for (s, e) in self.codeRanges:
                self.QLEngine.hook_code(self._hook_code, begin=s, end=e)
            pass
        elif self.getAssembly or 'DEFAULT' not in self.x8664Extensions:
            for (s, e) in self.codeRanges:
                self.QLEngine.hook_code(self._hook_code, begin=s, end=e)

        if self.deterministic:
            self.QLEngine.add_fs_mapper("/dev/urandom", device_random)
            self.QLEngine.add_fs_mapper("/dev/random", device_random)
            self.QLEngine.add_fs_mapper("/dev/arandom", device_random)
            # ref https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html
            self.QLEngine.os.set_syscall('time', const_time)
            self.QLEngine.os.set_syscall('getrandom', const_getrandom)
            self.QLEngine.os.set_syscall('gettimeofday', const_clock_gettimeofday)
            self.QLEngine.os.set_syscall('gettime', const_clock_gettime)
            self.QLEngine.os.set_syscall('clock_gettime', const_clock_gettime)
            self.QLEngine.os.set_syscall('clock_gettime64', const_clock_gettime)
        else:
            self.QLEngine.add_fs_mapper("/dev/urandom", "/dev/urandom")
            self.QLEngine.add_fs_mapper("/dev/random", "/dev/random")
            self.QLEngine.add_fs_mapper("/dev/arandom", "/dev/arandom")

        # replace broken qiling hooks with working ones:
        self.QLEngine.os.set_syscall("faccessat", ql_fixed_syscall_faccessat)
        self.QLEngine.os.set_syscall("newfstatat", ql_fixed_syscall_newfstatat)
        self.QLEngine.os.set_syscall("exit_group", syscall_exit_group)
        if not self.multithread:
            self.QLEngine.os.set_syscall("futex", syscall_futex)
        self.QLEngine.run()
        self.QLEngine.stop()
        dropset = []
        for t in self.currenttrace.trace:
            if self.getlibname(t) in self.ignoredObjects:
                dropset.append(t)
        self.currenttrace.remove(dropset)

    def getResults(self):
        return self.currenttrace, self.asm


@ray.remote
class CFWatcher:
    """
    records the sequence of IPs to determine CF leaks
    """

    def __init__(
            self,
            binpath,
            args,
            rootfs,
            tracedObjects,
            arch,
            mode,
            locations=None,
            getAssembly=False,
            x8664Extensions=["DEFAULT"],
            deterministic=False,
            multithread=True,
    ) -> None:
        self.QLEngine = None
        self.currenttrace = None
        self.traces: List[PCTrace] = []
        self.binPath = binpath
        self.x8664Extensions = x8664Extensions
        self.args = args
        self.rootfs = rootfs
        self.tracedObjects = tracedObjects
        self.arch = arch
        self.mode = mode
        self.locations = (
            {l: 1 for l in locations} if locations is not None else locations
        )
        self.getAssembly = getAssembly
        self.deterministic = deterministic
        self.multithread = multithread
        self.asm = {}
        """
        if a list of location is given (possible leaks), then we need to record
            a) the block at the leak location
            b) the next block (target of jump, call, etc)
        """
        self.saveNext = False

    def _hook_code(self, ql: Qiling, address: int, size: int):
        if not self.getAssembly:
            return
        pc = ql.arch.regs.arch_pc
        buf = ql.mem.read(address, size)
        for insn in ql.arch.disassembler.disasm(buf, address):
            self.asm[
                hex(pc)
            ] = f"{insn.address:#x}| : {insn.mnemonic:10s} {insn.op_str}"
            if insn.mnemonic.lower() == 'cpuid':
                log.debug(f"[CPUID@{pc:#x}] with EAX={ql.arch.regs.eax:032b}")
                ecxval = 0
                edxval = 0
                if "DEFAULT" not in self.x8664Extensions:
                    if 'AESNI-ONLY' in self.x8664Extensions:
                        ecxval |= AESNI_ID
                    if "NONE" in self.x8664Extensions:
                        ecxval = 0
                        edxval = 0
                    ql.arch.regs.edx = edxval
                    ql.arch.regs.ecx = ecxval
                    ql.arch.regs.arch_pc += 2
                   

    def _trace_block(self, ql, address, size):
        buf = ql.mem.read(address, size)
        addrs = []
        asm = []
        for insn in ql.arch.disassembler.disasm(buf, address):
            addrs.append(insn.address)
            if self.getAssembly:
                asm.append(f"{insn.address:#x}| : {insn.mnemonic:10s} {insn.op_str}")
        loc = addrs[-1]
        if self.getAssembly:
            self.asm[hex(addrs[-1])] = asm[-1]
        if not self.locations:
            self.currenttrace.add(addrs[-1])
            return
        if loc in self.locations or self.saveNext:
            if loc in self.locations:
                self.saveNext = True
            else:
                self.saveNext = False
            self.currenttrace.add(addrs[-1])

    def exec(self, secretString, asFile, secret):
        args = self.args.copy()
        nargs = []
        if isinstance(secretString, list):
            for idx, a in enumerate(args):
                if idx == args.index("@"):
                    for k in secretString:
                        nargs.append(k)
                else:
                    nargs.append(a)
            args = nargs
        else:
            args[args.index("@")] = secretString

        sys.stdout.fileno = lambda: False
        sys.stderr.fileno = lambda: False

        self.QLEngine = Qiling(
            [str(self.binPath), *args],
            str(self.rootfs),
            console=False,
            verbose=QL_VERBOSE.DISABLED,
            multithread=self.multithread,
            archtype=self.mode[0],
            ostype=self.mode[1],
        )

        if asFile:
            self.QLEngine.add_fs_mapper(secretString, secretString)
            dst = self.rootfs.rstrip('/') + secretString
            shutil.copy(secretString, dst)

        self.currenttrace = PCTrace(secret)
        for (s, e) in self.tracedObjects:
            if self.arch != CS_ARCH_X86 and not self.getAssembly:
                self.QLEngine.hook_code(self._hook_code)
            elif self.getAssembly:
                self.QLEngine.hook_code(self._hook_code, begin=s, end=e)

            self.QLEngine.hook_block(self._trace_block, begin=s, end=e)
        if self.deterministic:
            self.QLEngine.add_fs_mapper("/dev/urandom", device_random)
            self.QLEngine.add_fs_mapper("/dev/random", device_random)
            self.QLEngine.add_fs_mapper("/dev/arandom", device_random)
            # ref https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html
            self.QLEngine.os.set_syscall('time', const_time)
            self.QLEngine.os.set_syscall('getrandom', const_getrandom)
            self.QLEngine.os.set_syscall('gettimeofday', const_clock_gettimeofday)
            self.QLEngine.os.set_syscall('gettime', const_clock_gettime)
            self.QLEngine.os.set_syscall('clock_gettime', const_clock_gettime)
            self.QLEngine.os.set_syscall('clock_gettime64', const_clock_gettime)
        else:
            self.QLEngine.add_fs_mapper("/dev/urandom", "/dev/urandom")
            self.QLEngine.add_fs_mapper("/dev/random", "/dev/random")
            self.QLEngine.add_fs_mapper("/dev/arandom", "/dev/arandom")

        # replace broken qiling hooks with working ones:
        self.QLEngine.os.set_syscall("faccessat", ql_fixed_syscall_faccessat)
        self.QLEngine.os.set_syscall("newfstatat", ql_fixed_syscall_newfstatat)
        self.QLEngine.os.set_syscall("exit_group", syscall_exit_group)
        if not self.multithread:
            self.QLEngine.os.set_syscall("futex", syscall_futex)
        self.QLEngine.run()
        self.QLEngine.stop()

    def getResults(self):
        self.currenttrace.finalize()
        return self.currenttrace, self.asm


@ray.remote(num_cpus=1)
def train(X, Y, leakAddr, keylen, reportDir, threshold, pba):
    nleakage = NeuralLeakageModel(
        X, Y, leakAddr, keylen, reportDir + "/assets", threshold
    )
    try:
        nleakage.train()
    except Exception as e:
        log.error("worker encountered exception:")
        log.error(str(e))
        log.error(traceback.format_exc())
        pba.update.remote(1)
        return (-1, leakAddr)
    pba.update.remote(1)
    return (nleakage.MIScore, leakAddr)


class LeakageClassification:
    def __init__(
            self,
            rndTraceCollection: TraceCollection,
            binaryLoader: BinaryLoader,
            threshold,
    ):
        self.rndTraceCollection = rndTraceCollection
        self.possibleLeaks = rndTraceCollection.possibleLeaks
        self.loader = binaryLoader
        self.results: Dict[str, float] = {}
        self.KEYLEN = self.loader.rndGen.keylen
        self.threshold = threshold

    def analyze(self):
        log.info("Estimating scores and key bit dependencies")
        futures = []
        num_ticks = 0
        for k, v in self.rndTraceCollection.DF.items():
            num_ticks += 1
        if num_ticks == 0:
            return self.results
        pb = ProgressBar(num_ticks)
        actor = pb.actor
        for k, v in self.rndTraceCollection.DF.items():
            futures.append(
                train.remote(
                    v.loc[:, v.columns != "secret"].values,
                    v.loc[:, "secret"].to_numpy(),
                    k,
                    self.KEYLEN,
                    self.loader.resultDir,
                    self.threshold,
                    actor,
                )
            )

        pb.print_until_done()
        results = ray.get(futures)
        for r in results:
            (MIScore, leakAddr) = r
            self.results[hex(leakAddr)] = MIScore
