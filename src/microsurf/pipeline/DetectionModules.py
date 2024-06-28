import multiprocessing
from collections import ChainMap
from typing import List

from concurrent.futures import ProcessPoolExecutor, as_completed
from itertools import repeat
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
        miThreshold: The threshold for which to produce key bit estimates (if key bit estimates are requested). Values lower than 0.2 might produce results which do not make any sense (overfitted estimation).
        granularity: Resolution of the detection algorithm (in bytes). The default value of one flags any memory accesses which differ by at least one byte. This value can be increased to simlulate detection of cross-cache line leaks.
       
    """

    def __init__(self, binaryLoader: BinaryLoader, miThreshold: float = 0.2, granularity: int = 1):
        super().__init__(binaryLoader, miThreshold, granularity)

    def recordTraces(
            self, n: int, pcList: List[int] = None, getAssembly=False) -> MemTraceCollection:
        codeRanges = self.loader.executableCode
        NB_CORES = min(self.NB_CORES, n)
        log.debug(f"Using {NB_CORES} cores")
        memWatchers = [
            MemWatcher(
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
        mt_list = []
        asm = []

        with ProcessPoolExecutor(max_workers=NB_CORES) as executor:
            futures = [executor.submit(m.exec, self.loader.rndGen(), 
                                       self.loader.rndGen.asFile,
                                       self.loader.rndGen.getSecret())
                                       for m in memWatchers]

            for future in as_completed(futures):
                try:
                    m, a = future.result()
                    asm.append(a)
                    mt_list.append(m)
                except Exception as e:
                    # usually a OOM exception
                    print("Error in process: {}".format(str(e)))
                    raise e

        mt = MemTraceCollection(mt_list, possibleLeaks=pcList, granularity=self.granularity)
        return mt, dict(ChainMap(*asm))

    def __str__(self):
        return "Secret dep. mem. operation (R/W)"


class CFLeakDetector(Detector):
    """
    The CFLeakDetector class is used to collect traces for analysis of secret dependent control flow.

    Args:
        binaryLoader: A BinaryLoader instance 
        miThreshold: The threshold for which to produce key bit estimates.
            Values lower than 0.2 might produce results which do not make any sense (overfitted estimation).
        flagVariableHitCount: Include branching instruction which were hit a variable number of times in the report.
    """

    def __init__(self, *, binaryLoader: BinaryLoader, miThreshold: float = 0.2, flagVariableHitCount: bool = True):
        super().__init__(binaryLoader, miThreshold)
        self.flagVariableHitCount = flagVariableHitCount
        self.save = False

    def recordTraces(
            self, n: int, pcList: List[int] = None, getAssembly=False
    ) -> PCTraceCollection:
        NB_CORES = min(self.NB_CORES, n)
        cfWatchers = [
            CFWatcher(
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
        mt_list = []
        asm = []

        with ProcessPoolExecutor(max_workers=NB_CORES) as executor:
            futures = [executor.submit(m.exec, self.loader.rndGen(), 
                                       self.loader.rndGen.asFile,
                                       self.loader.rndGen.getSecret())
                                       for m in cfWatchers]

            for future in as_completed(futures):
                try:
                    m, a = future.result()
                    asm.append(a)
                    mt_list.append(m)
                except Exception as e:
                    # usually a OOM exception
                    print("Error in process: {}".format(str(e)))
                    raise e

        mt = PCTraceCollection(mt_list, possibleLeaks=pcList,
                               flagVariableHitCount=self.flagVariableHitCount)
        return mt, dict(ChainMap(*asm))

    def __str__(self):
        return "Secret dep. CF"
