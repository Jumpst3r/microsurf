"""
Microsurf: An architecture independent dynamic side channel detection framework
@author nicolas
"""

import multiprocessing
from typing import Any, Callable, List

from microsurf.pipeline.tracetools.Trace import (
    MemTraceCollectionFixed,
    MemTraceCollectionRandom,
)
from .pipeline.Executor import PipeLineExecutor
from .pipeline.Stages import BinaryLoader, MemWatcher
from .utils.logger import getConsole, getLogger
from pathlib import Path
import ray
from rich.progress import track

console = getConsole()
log = getLogger()


class SCDetector:
    """The SCDetector class can be used to detect secret dependent memory accesses in generic applications.

    Args:
        binPath: Path to the target binary
        args: List of arguments to pass to the binary. For a secret argument,
            substitute the value of the argument with @ (for example, ['--encrypt', '<privkeyfile>']
            would become ['--encrypt', '@'] ). Only one argument can be defined as secret.
        randGen: A function that generates random bytes in the format
            expected by the target binary. The SCDetector class will save these bytes
            to a temporary file and substitute the secret placeholder ('@') with the path to the file
        deterministic: Force deterministic execution by hooking relevant syscalls
        asFile: Specifies whether the target binary excepts the secret to be read from a file.
            If false, the secret will be passed directly as an argument
        jail: Specifies the a directory to which the binary will be jailed during emulation.
            For dynamic binaries, the user must ensure that the appropriate shared objects are present.
            Optional for static binaries, defaults to a tmp directory.
        sharedObjects: List of shared libraries to trace. For example ['libssl.so.1.1', 'libcrypto.so.1.1'].
            Defaults to None, tracing only the target binary. Only applicable to dynamic binaries.
        resultsDir: Directory to which the markdown report will be saved, created if not not already existing.
        randomTraces: Path to pre-recorded random traces, optional.
        fixedTraces: Path to pre-recorded fixed traces, optional.
        saveTraces: Save the recorded traces to results/assets.
    """

    def __init__(
        self,
        binPath: str,
        args: list[str],
        randGen: Callable[[], str],
        deterministic: bool,
        asFile: bool,
        sharedObjects: list[str] = [],
        jail: str = None,
        resultsDir: str = "results",
        randomTraces: str = None,
        fixedTraces: str = None,
        saveTraces: bool = True
    ) -> None:
        self.binPath = binPath
        self.args = args
        self.randGen = randGen
        self.deterministic = deterministic
        self.asFile = asFile
        self.rootfs = jail
        self.sharedObjects = sharedObjects
        self.resultsDir = resultsDir
        self.saveTraces = saveTraces
        if randomTraces:
            if not Path(randomTraces).exists():
                log.error(f"random traces path ({randomTraces}) does not exit")
                exit(1)
            else:
                self.randomTraces = randomTraces
                self.saveTraces = False
        else:
            self.randomTraces = None
        if fixedTraces:
            if not Path(fixedTraces).exists():
                log.error(f"fixed traces path ({fixedTraces}) does not exit")
                exit(1)
            else:
                self.fixedTraces = fixedTraces
                self.saveTraces = False
        else:
            self.fixedTraces = None
        self._validate()
        Path(self.resultsDir + "/assets").mkdir(parents=True, exist_ok=True)
        Path(self.resultsDir + "/traces").mkdir(parents=True, exist_ok=True)
        self.NB_CORES = (
            multiprocessing.cpu_count() - 1 if multiprocessing.cpu_count() > 2 else 1
        )
        if not ray.is_initialized():
            ray.init(num_cpus=self.NB_CORES)
        self.binPath_id = ray.put(self.loader.binPath)
        self.args_id = ray.put(self.loader.args)
        self.rootfs_id = ray.put(self.loader.rootfs)
        self.ignoredObjects_id = ray.put(self.loader.ignoredObjects)
        self.mappings_id = ray.put(self.loader.mappings)
        self.deterministic_id = ray.put(self.loader.deterministic)

    def _validate(self):
        resrnd = set()
        for _ in range(10):
            resrnd.add(self.randGen())
        if len(resrnd) < 5:
            log.error(
                f"Provided random function not random enough (got {len(resrnd)} repeated values in 10 invocation."
            )
            exit(1)
        count = 0
        # Check that we only have a single secret marker
        for arg in self.args:
            count += arg.count("@")
        if count > 1:
            log.error(
                f"Only a single secret marker can be included in the argument list ({self.args})"
            )
            exit(1)
        self.loader = BinaryLoader(
            path=self.binPath,
            args=self.args,
            dryRunOnly=True,
            deterministic=self.deterministic,
            rndGen=self.randGen,
            asFile=self.asFile,
            jail=self.rootfs,
            sharedObjects=self.sharedObjects,
            reportDir=self.resultsDir,
        )

    def exec(self, report=False):
        """Executes the complete side channel analysis pipeline with sensible defaults (secret dependent memory accesses).

        Args:
            report: Generates a markdown report. Defaults to False.

        Returns:
            A list of leak locations, as integers (IP values).
            For dynamic objects, the offsets are reported.
        """
        pipeline = PipeLineExecutor(loader=self.loader)
        pipeline.run(self)
        if report:
            pipeline.generateReport()
        return pipeline.finalize()

    def recordTracesFixed(
        self, n: int, pcList: List = None, **kwargs
    ) -> MemTraceCollectionFixed:
        """Record memory accesses resulting from repeated execution with the same secret.

        By default, it will target:
            - For dynamic binaries only the shared objects which were passed to the SCDetector constructor
            - For static binaries, the entire binary.
            - Determinism will be fixed if the appropriate parameter was passed to the SCDetector constructor.
        The last point can be modified by passing deterministic=True or deterministic=False

        Args:
            n: Number of traces to collect
            pcList: Specifc PCs to trace. Defaults to None.

        Returns:
            A MemTraceCollectionFixed object representing the set of traces collected.
        """
        self.deterministic = kwargs.get("deterministic", self.loader.deterministic)
        NB_CORES = min(self.NB_CORES, n)
        memWatchers = [
            MemWatcher.remote(
                self.binPath_id,
                self.args_id,
                self.rootfs_id,
                self.ignoredObjects_id,
                self.mappings_id,
                locations=pcList,
                deterministic=self.deterministic,
            )
            for _ in range(NB_CORES)
        ]
        resList = []
        for _ in track(
            range(0, n, NB_CORES),
            description=f"Collecting {n} traces with fixed secrets",
        ):
            [m.exec.remote(secret=self.loader.fixedArg()[0]) for m in memWatchers]
            futures = [m.getResults.remote() for m in memWatchers]
            res = ray.get(futures)
            resList += [r[0] for r in res]
        mt = MemTraceCollectionFixed([r for r in resList])
        return mt

    def isDeterministic(self, traceCollection: MemTraceCollectionFixed) -> bool:
        """Determines whether the memory reads are deterministic given a MemTraceCollectionFixed object

        Args:
            traceCollection: A MemTraceCollectionFixed object with at least two traces.

        Returns:
            True or False, depending on whether the execution is deterministic.
        """
        deterministic = True
        for t in traceCollection.traces:
            for t2 in traceCollection.traces:
                for (k1, v1), (k2, v2) in zip(t.trace.items(), t2.trace.items()):
                    if k1 != k2 or v1 != v2:
                        deterministic = False
        return deterministic

    def recordTracesRandom(
        self, n: int, pcList: List = None, **kwargs
    ) -> MemTraceCollectionRandom:
        """Record memory accesses resulting from repeated execution with random secrets.

        By default, it will target:
            - For dynamic binaries only the shared objects which were passed to the SCDetector constructor
            - For static binaries, the entire binary.
            - Determinism will be fixed if the appropriate parameter was passed to the SCDetector constructor.
        The last point can be modified by passing deterministic=True or deterministic=False

        Args:
            n: Number of traces to collect
            pcList: Specifc PCs to trace. Defaults to None.

        Returns:
            A MemTraceCollectionRandom object representing the set of traces collected.
        """
        self.deterministic = kwargs.get("deterministic", self.loader.deterministic)
        NB_CORES = min(self.NB_CORES, n)
        memWatchers = [
            MemWatcher.remote(
                self.binPath_id,
                self.args_id,
                self.rootfs_id,
                self.ignoredObjects_id,
                self.mappings_id,
                locations=pcList,
                deterministic=self.deterministic,
            )
            for _ in range(NB_CORES)
        ]
        resList = []
        for _ in track(
            range(0, n, NB_CORES),
            description=f"Collecting {n} traces with random secrets",
        ):
            [m.exec.remote(secret=self.loader.rndArg()[0]) for m in memWatchers]
            futures = [m.getResults.remote() for m in memWatchers]
            res = ray.get(futures)
            resList += [r[0] for r in res]
        mt = MemTraceCollectionRandom([r for r in resList])
        mt.prune()
        return mt


