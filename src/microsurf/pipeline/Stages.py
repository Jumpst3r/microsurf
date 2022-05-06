import os
import sys
import tempfile
import traceback
import uuid
from asyncio import Event
from datetime import datetime
from functools import lru_cache
from pathlib import Path, PurePath
from typing import Dict, List, Tuple, Callable

import magic
import ray
from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    Cs,
    CS_ARCH_MIPS,
    CS_ARCH_RISCV,
    CS_MODE_ARM,
    CS_MODE_RISCV64,
)
from qiling import Qiling
from qiling.const import QL_VERBOSE
from unicorn.unicorn_const import UC_MEM_READ

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
)
from ..utils.logger import getConsole, getLogger, getQilingLogger

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
        sharedObjects: List of shared objects to trace, defaults to tracing everything.
        deterministic: Force deterministic execution.
        resultDir: Path to the results directory.
    """

    def __init__(
            self,
            path: Path,
            args: List[str],
            rootfs: str,
            rndGen: SecretGenerator,
            sharedObjects: List[str] = [],
            deterministic: bool = False,
            resultDir: str = "results",
    ) -> None:
        self.binPath = Path(path)
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
        self.uuid = uuid.uuid4()
        self.resultDir += f"/{self.uuid}"
        os.makedirs(self.resultDir + "/" + "assets", exist_ok=True)
        os.makedirs(self.resultDir + "/" + "traces", exist_ok=True)

        try:
            self.secretArgIndex: int = args.index("@")
        except ValueError:
            log.error('no argument marked as secret dependent - exiting.')
            exit(0)

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
        elif "x86" in fileinfo:
            self.ARCH = "X86_64"
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif "ARM" in fileinfo:
            self.ARCH = "ARM"
            self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        elif "MIPS32" in fileinfo:
            self.ARCH = "MIPS32"
            self.md = Cs(CS_ARCH_MIPS, CS_MODE_32)
        elif "RISC-V" in fileinfo:
            self.ARCH = "RISCV"
            self.md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
        else:
            log.info(fileinfo)
            log.error("Target architecture not implemented")
            exit(-1)
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
                log.warn(
                    "You provided a list of shared objects - but the target binary is static. Ignoring objects."
                )
        try:
            # initialize args;
            val = self.rndGen()
            self.newArgs[self.secretArgIndex] = val
            self.multithreaded = False
            self.QLEngine = Qiling(
                [str(self.binPath), *self.newArgs],
                str(self.rootfs),
                log_override=getQilingLogger(),
                verbose=QL_VERBOSE.DEFAULT,
                console=True,
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
            tback = traceback.format_exc()
            log.error(tback)
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
                        verbose=QL_VERBOSE.DEFAULT,
                        console=True,
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
                    tback = traceback.format_exc()
                    log.error(tback)
                    exit(1)

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
        log.info("executable segments:")
        for s, e, perm, label, c in self.mappings:
            if "x" not in perm:
                continue
            log.info(f"{hex(s)}-{hex(e)} {perm} {label}")
            labelIgnored = True
            if not self.sharedObjects and self.binPath.name in label:
                self.executableCode.append((s, e))
            for obname in self.sharedObjects:
                if obname in label:
                    labelIgnored = False
            if labelIgnored and self.binPath.name not in label:
                self.ignoredObjects.append(label)
            else:
                self.executableCode.append((s, e))

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
        self.ignoredObjects = ignoredObjects
        self.mappings = mappings
        self.deterministic = deterministic
        self.multithread = multithread
        self.codeRanges = codeRanges
        self.asm = {}

    def _trace_mem_read(self, ql: Qiling, access, addr, size, value):
        assert access == UC_MEM_READ
        pc = ql.arch.regs.arch_pc
        if self.locations is None:
            self.currenttrace.add(pc, addr)
        elif pc in self.locations:
            self.currenttrace.add(pc, addr)

    def _hook_code(self, ql: Qiling, address: int, size: int):
        pc = ql.arch.regs.arch_pc
        if self.locations is None:
            return
        if pc in self.locations:
            buf = ql.mem.read(address, size)
            for insn in ql.arch.disassembler.disasm(buf, address):
                self.asm[
                    hex(pc)
                ] = f"{insn.address:#x}| : {insn.mnemonic:10s} {insn.op_str}"

    def getlibname(self, addr):
        return next(
            (label for s, e, _, label, _ in self.mappings if s < addr < e),
            -1,
        )

    def exec(self, secretString, asFile, secret):
        args = self.args.copy()
        args[args.index("@")] = secretString
        sys.stdout.fileno = lambda: False
        sys.stderr.fileno = lambda: False
        self.QLEngine = Qiling(
            [str(self.binPath), *[str(a) for a in args]],
            str(self.rootfs),
            console=False,
            verbose=QL_VERBOSE.DISABLED,
            multithread=self.multithread,
            libcache=True,
        )
        if asFile:
            self.QLEngine.add_fs_mapper(secretString, secretString)
        self.currenttrace = MemTrace(secret)
        self.QLEngine.hook_mem_read(self._trace_mem_read)
        if self.codeRanges:
            for (s, e) in self.codeRanges:
                self.QLEngine.hook_code(self._hook_code, begin=s, end=e)
        else:
            self.QLEngine.hook_code(self._hook_code)
        # duplicate code. Ugly - fixme.
        if self.deterministic:
            self.QLEngine.add_fs_mapper("/dev/urandom", device_random)
            self.QLEngine.add_fs_mapper("/dev/random", device_random)
            self.QLEngine.add_fs_mapper("/dev/arandom", device_random)
            # ref https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html
            if self.arch == CS_ARCH_ARM:
                self.QLEngine.os.set_syscall(403, const_time)
                self.QLEngine.os.set_syscall(384, const_getrandom)
                self.QLEngine.os.set_syscall(78, const_clock_gettimeofday)
                self.QLEngine.os.set_syscall(263, const_clock_gettime)
            if self.arch == CS_ARCH_X86 and self.mode == CS_MODE_64:
                self.QLEngine.os.set_syscall(318, const_getrandom)
                self.QLEngine.os.set_syscall(96, const_clock_gettimeofday)
                self.QLEngine.os.set_syscall(228, const_clock_gettime)
            if self.arch == CS_ARCH_X86 and self.mode == CS_MODE_32:
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
        self.QLEngine.os.set_syscall("newfstatat", ql_fixed_syscall_newfstatat)
        self.QLEngine.os.set_syscall("exit_group", syscall_exit_group)
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
            deterministic=False,
            multithread=True,
    ) -> None:
        self.QLEngine = None
        self.currenttrace = None
        self.traces: List[PCTrace] = []
        self.binPath = binpath
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
        pass

    def _trace_block(self, ql, address, size):
        buf = ql.mem.read(address, size)
        ql.arch.disassembler.detail = True
        addrs = []
        asm = []
        for insn in ql.arch.disassembler.disasm(buf, address):
            addrs.append(insn.address)
            asm.append(f"{insn.address:#x}| : {insn.mnemonic:10s} {insn.op_str}")
        loc = addrs[-1]
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
        args[args.index("@")] = secretString
        sys.stdout.fileno = lambda: False
        sys.stderr.fileno = lambda: False

        self.QLEngine = Qiling(
            [str(self.binPath), *args],
            str(self.rootfs),
            console=False,
            verbose=QL_VERBOSE.DISABLED,
            multithread=self.multithread,
            libcache=True,
        )
        if asFile:
            self.QLEngine.add_fs_mapper(secretString, secretString)
        self.currenttrace = PCTrace(secret)
        for (s, e) in self.tracedObjects:
            self.QLEngine.hook_block(self._trace_block, begin=s, end=e)
        if self.deterministic:
            self.QLEngine.add_fs_mapper("/dev/urandom", device_random)
            self.QLEngine.add_fs_mapper("/dev/random", device_random)
            self.QLEngine.add_fs_mapper("/dev/arandom", device_random)
            # ref https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html
            if self.arch == CS_ARCH_ARM:
                self.QLEngine.os.set_syscall(403, const_time)
                self.QLEngine.os.set_syscall(384, const_getrandom)
                self.QLEngine.os.set_syscall(78, const_clock_gettimeofday)
                self.QLEngine.os.set_syscall(263, const_clock_gettime)
            if self.arch == CS_ARCH_X86 and self.mode == CS_MODE_64:
                self.QLEngine.os.set_syscall(318, const_getrandom)
                self.QLEngine.os.set_syscall(96, const_clock_gettimeofday)
                self.QLEngine.os.set_syscall(228, const_clock_gettime)
            if self.arch == CS_ARCH_X86 and self.mode == CS_MODE_32:
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
        self.QLEngine.os.set_syscall("newfstatat", ql_fixed_syscall_newfstatat)
        self.QLEngine.os.set_syscall("exit_group", syscall_exit_group)
        self.QLEngine.run()
        self.QLEngine.stop()

    def getResults(self):
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


# BEGIN RAY UTILS PROGRESS BAR (taken from https://docs.ray.io/en/latest/ray-core/examples/progress_bar.html)
from ray.actor import ActorHandle
from tqdm.rich import tqdm


@ray.remote
class ProgressBarActor:
    def __init__(self) -> None:
        self.counter = 0
        self.delta = 0
        self.event = Event()

    def update(self, num_items_completed: int) -> None:
        self.counter += num_items_completed
        self.delta += num_items_completed
        self.event.set()

    async def wait_for_update(self) -> Tuple[int, int]:
        await self.event.wait()
        self.event.clear()
        saved_delta = self.delta
        self.delta = 0
        return saved_delta, self.counter

    def get_counter(self) -> int:
        return self.counter


class ProgressBar:
    def __init__(self, total: int, description: str = ""):
        self.progress_actor = ProgressBarActor.remote()  # type: ignore
        self.total = total
        self.description = description

    @property
    def actor(self) -> ActorHandle:
        return self.progress_actor

    def print_until_done(self) -> None:
        pbar = tqdm(desc=self.description, total=self.total)
        while True:
            delta, counter = ray.get(self.actor.wait_for_update.remote())
            pbar.update(delta)
            if counter >= self.total:
                pbar.close()
                return


### END RAY PROGRESSBAR SNIPPET


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
        self.KEYLEN = int(len(self.loader.rndGen()) * 4)
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
                    v.loc[:, v.columns != "hits"].values,
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
