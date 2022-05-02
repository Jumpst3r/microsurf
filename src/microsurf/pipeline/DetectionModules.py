import multiprocessing
from collections import ChainMap
from typing import List

import ray
from rich.progress import track

from microsurf.pipeline.Stages import MemWatcher, BinaryLoader, CFWatcher
from microsurf.pipeline.tracetools.Trace import (
    MemTraceCollectionFixed,
    MemTraceCollectionRandom,
    PCTraceCollectionRandom,
    PCTraceCollectionFixed,
    TraceCollection,
    MemTraceCollection,
    PCTraceCollection,
)


class Detector:
    def __init__(self, binaryLoader: BinaryLoader, save=True, miThreshold=0.2):
        """Generic Detector class.
        Args:
            binaryLoader: A binary loader instance.
            sharedObjects: List of shared objects to trace. Names do not need to match exactly, for example, "libcypto"
            instead of "libcrypto.so.1.1" works fine.
            tracePath: Full path to pre-recorded trace. If the file does not exist, a new trace recording
            will be generated and saved at the specified location.
        """
        self.loader = binaryLoader
        self.miThreshold = miThreshold
        self.save = save
        self.NB_CORES = multiprocessing.cpu_count() - 1

    def recordTraces(
        self, n: int, pcList: List[int] = None, fixedSecret=False, getAssembly=False
    ) -> TraceCollection:
        pass


class DataLeakDetector(Detector):
    def __init__(self, *, binaryLoader, save=True, miThreshold=0.2):
        super().__init__(binaryLoader, save, miThreshold)

    def recordTraces(
        self, n: int, pcList: List[int] = None, fixedSecret=False, getAssembly=False
    ) -> MemTraceCollection:
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
                self.loader.md.mode,
                locations=pcList,
                getAssembly=getAssembly,
                deterministic=self.loader.deterministic,
                multithread=self.loader.multithreaded,
                codeRanges=codeRanges,
            )
            for _ in range(NB_CORES)
        ]
        resList = []
        for _ in track(
            range(0, n, NB_CORES),
            description=f"Collecting {n} traces with {'fixed' if fixedSecret else 'random'} secrets",
        ):
            if fixedSecret:
                [m.exec.remote(secret=self.loader.fixedArg()[0]) for m in memWatchers]
            else:
                [m.exec.remote(secret=self.loader.rndArg()[0]) for m in memWatchers]
            futures = [m.getResults.remote() for m in memWatchers]
            res = ray.get(futures)
            resList += [r for r in res]
        asm = [r[1] for r in resList]
        if fixedSecret:
            mt = MemTraceCollectionFixed([r[0] for r in resList])
        else:
            mt = MemTraceCollectionRandom([r[0] for r in resList], possibleLeaks=pcList)
        if self.save:
            path = (
                f"{self.loader.resultDir}/traces/traces-data-"
                f'{"fixed" if fixedSecret else "random"}-{n}-{self.loader.ARCH}.pickle '
            )
            mt.toDisk(path)
        return mt, dict(ChainMap(*asm))

    def __str__(self):
        return "Secret dep. mem. read detector"


class CFLeakDetector(Detector):
    def __init__(self, *, binaryLoader, save=True, miThreshold=0.2):
        super().__init__(binaryLoader, save, miThreshold)

    def recordTraces(
        self,
        n: int,
        pcList: List[int] = None,
        fixedSecret=False,
        getAssembly=False
    ) -> PCTraceCollection:
        NB_CORES = min(self.NB_CORES, n)
        cfWatchers = [
            CFWatcher.remote(
                binpath=self.loader.binPath,
                args=self.loader.args,
                rootfs=self.loader.rootfs,
                tracedObjects=self.loader.executableCode,
                arch=self.loader.md.arch,
                mode=self.loader.md.mode,
                locations=pcList,
                getAssembly=getAssembly,
                deterministic=self.loader.deterministic,
                multithread=self.loader.multithreaded,
            )
            for _ in range(NB_CORES)
        ]
        resList = []
        for _ in track(
            range(0, n, NB_CORES),
            description=f"Collecting {n} traces with  {'fixed' if fixedSecret else 'random'} secrets",
        ):
            if fixedSecret:
                [m.exec.remote(secret=self.loader.fixedArg()[0]) for m in cfWatchers]
            else:
                [m.exec.remote(secret=self.loader.rndArg()[0]) for m in cfWatchers]
            futures = [m.getResults.remote() for m in cfWatchers]
            res = ray.get(futures)
            resList += [r for r in res]
        asm = [r[1] for r in resList]
        if fixedSecret:
            mt = PCTraceCollectionFixed([r[0] for r in resList])
        else:
            mt = PCTraceCollectionRandom([r[0] for r in resList], possibleLeaks=pcList)
        if self.save:
            path = (
                f"{self.loader.resultDir}/traces/traces-CF-"
                f'{"fixed" if fixedSecret else "random"}-{n}-{self.loader.ARCH}.pickle'
            )
            mt.toDisk(path)
        return mt, dict(ChainMap(*asm))

    def __str__(self):
        return "Secret dep. CF detector"
