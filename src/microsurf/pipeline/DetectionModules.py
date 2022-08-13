import multiprocessing
from collections import ChainMap
from typing import List

import ray
from rich.progress import track

from microsurf.pipeline.Stages import MemWatcher, BinaryLoader, CFWatcher
from microsurf.pipeline.tracetools.Trace import (
    TraceCollection,
    MemTraceCollection,
    PCTraceCollection,
)
from microsurf.utils.logger import getLogger

log = getLogger()

class Detector:
    def __init__(self, binaryLoader: BinaryLoader, miThreshold=0.2, granularity: int = 1):
        self.loader = binaryLoader
        self.miThreshold = miThreshold
        self.NB_CORES = multiprocessing.cpu_count() - 1 if multiprocessing.cpu_count() > 1 else 1
        self.granularity = granularity

    def recordTraces(
            self, n: int, pcList: List[int] = None, getAssembly=False
    ) -> TraceCollection:
        pass


class DataLeakDetector(Detector):
    """The DataLeakDetector class is used to collect traces for analysis of secret dependent memory accesses.

    Args: 
        binaryLoader: A BinaryLoader instance.
        miThreshold: The treshold for which to produce key bit estimates (if key bit estimates are requested). Values lower than 0.2 might produce results which do not make any sense (overfitted estimation).
        granularity: Resultion of the detection algorithm (in bytes). The default value of one flags any memory accesses which differ by at least one byte. This value can be increased to simlulate detection of cross-cache line leaks.
       
    """

    def __init__(self, binaryLoader: BinaryLoader, miThreshold: float = 0.2, granularity: int = 1):
        super().__init__(binaryLoader, miThreshold, granularity)

    def recordTraces(
            self, n: int, pcList: List[int] = None, getAssembly=False) -> MemTraceCollection:
        codeRanges = self.loader.executableCode
        NB_CORES = min(self.NB_CORES, n)
        memWatchers = [
            MemWatcher.remote(
                self.loader.binPath,
                self.loader.args,
                self.loader.rootfs,
                self.loader.ignoredObjects,
                self.loader.mappings,
                self.loader.md.arch,
                (self.loader.archtype, self.loader.ostype),
                locations=pcList,
                getAssembly=getAssembly,
                x8664Extensions=self.loader.x8664Extensions,
                deterministic=self.loader.deterministic,
                multithread=self.loader.multithreaded,
                codeRanges=codeRanges,
            )
            for _ in range(NB_CORES)
        ]
        resList = []
        for _ in track(
                range(0, n, NB_CORES),
                description=f"Collecting {n} traces ",
        ):
            [m.exec.remote(secretString=self.loader.rndGen(), asFile=self.loader.rndGen.asFile, secret=self.loader.rndGen.getSecret()) for m in memWatchers]
            futures = [m.getResults.remote() for m in memWatchers]
            res = ray.get(futures)
            resList += [r for r in res]
        asm = [r[1] for r in resList]
        mt = MemTraceCollection([r[0] for r in resList[:n]], possibleLeaks=pcList, granularity=self.granularity)
        return mt, dict(ChainMap(*asm))

    def __str__(self):
        return "Secret dep. mem. operation (R/W)"


class CFLeakDetector(Detector):
    """
    The CFLeakDetector class is used to collect traces for analysis of secret dependent conctrol flow.

    Args:
        binaryLoader: A BinaryLoader instance 
        miThreshold: The treshold for which to produce key bit estimates.
            Values lower than 0.2 might produce results which do not make any sense (overfitted estimation).
        flagVariableHitCount: Include branching instruction which were hit a variable number of times in the report.
            Doing so will catch things like secret dependent iteration counts but might also cause false positives. Usually
            these are caused by a secret dependent branch earlier in the control flow, which causes variable hit rates for
            subsequent branching instructions. Fixing any secret dependent branching and then running with
            flagVariableHitCount=True is advised.
    """

    def __init__(self, *, binaryLoader: BinaryLoader, miThreshold: float = 0.2, flagVariableHitCount: bool = False):
        super().__init__(binaryLoader, miThreshold)
        self.flagVariableHitCount = flagVariableHitCount
        self.save = False

    def recordTraces(
            self, n: int, pcList: List[int] = None, getAssembly=False
    ) -> PCTraceCollection:
        NB_CORES = min(self.NB_CORES, n)
        cfWatchers = [
            CFWatcher.remote(
                binpath=self.loader.binPath,
                args=self.loader.args,
                rootfs=self.loader.rootfs,
                tracedObjects=self.loader.executableCode,
                arch=self.loader.md.arch,
                mode=(self.loader.archtype, self.loader.ostype),
                locations=pcList,
                getAssembly=getAssembly,
                x8664Extensions=self.loader.x8664Extensions,
                deterministic=self.loader.deterministic,
                multithread=self.loader.multithreaded,
            )
            for _ in range(NB_CORES)
        ]
        resList = []
        for _ in track(
                range(0, n, NB_CORES),
                description=f"Collecting {n} traces",
        ):
            [m.exec.remote(secretString=self.loader.rndGen(), asFile=self.loader.rndGen.asFile, secret=self.loader.rndGen.getSecret()) for m in cfWatchers]
            futures = [m.getResults.remote() for m in cfWatchers]
            res = ray.get(futures)
            resList += [r for r in res]
        asm = [r[1] for r in resList]
        mt = PCTraceCollection([r[0] for r in resList], possibleLeaks=pcList,
                               flagVariableHitCount=self.flagVariableHitCount)
        return mt, dict(ChainMap(*asm))

    def __str__(self):
        return "Secret dep. CF"
