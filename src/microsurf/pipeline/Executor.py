import multiprocessing
from typing import List

from capstone import CS_ARCH_ARM
from microsurf.pipeline.tracetools.Trace import MemTraceCollection
from tqdm import tqdm

from ..pipeline.LeakageModels import hamming
from ..pipeline.Stages import (
    BinaryLoader,
    DistributionAnalyzer,
    FindMemOps,
    LeakageClassification,
    MemWatcher,
)
from ..utils.elf import getfnname
from ..utils.logger import getConsole, getLogger

log = getLogger()
console = getConsole()


class PipeLineExecutor:
    def __init__(self, loader: BinaryLoader) -> None:
        self.loader = loader
        self.results: List[int] = []

    def run(self):
        import time

        starttime = time.time()
        try:
            val, _ = self.loader._rand()
            encoded = hamming(val)
            log.info(f"L(secret) = {encoded}, leakage model compatible.")
        except ValueError:
            log.error(f"leakage model does not suppport input {val}")
            exit(1)
        isARCH = False
        if self.loader.md.arch == CS_ARCH_ARM:
            isARCH = True
            memOpFinder = FindMemOps(binaryLoader=self.loader)
            memOpFinder.exec(self.loader.fixedArg)
            possibleLeaks = memOpFinder.finalize()

        memWatcherFixed = MemWatcher(
            binaryLoader=self.loader, archPCs=possibleLeaks if isARCH else None
        )
        memWatcherRnd = MemWatcher(
            binaryLoader=self.loader, archPCs=possibleLeaks if isARCH else None
        )
        log.info("Running stage Leak Confirm")

        jobs = []
        manager = multiprocessing.Manager()
        tracesFixed = manager.dict()
        tracesRandom = manager.dict()
        FIXED_ITER_CNT = 100
        # TODO let the user define how many cores.
        nbCores = (
            1 if multiprocessing.cpu_count() == 1 else multiprocessing.cpu_count() - 1
        )
        for i in range(FIXED_ITER_CNT):
            pfixed = multiprocessing.Process(
                target=memWatcherFixed.exec, args=(self.loader.fixedArg, i, tracesFixed)
            )
            jobs.append(pfixed)
            prand = multiprocessing.Process(
                target=memWatcherRnd.exec, args=(self.loader.rndArg, i, tracesRandom)
            )
            jobs.append(prand)

        log.info(f"Batching {len(jobs)} jobs across {nbCores} cores")
        for i in tqdm(range(0, len(jobs), nbCores)):
            batch = []
            for j in jobs[i: i + nbCores]:
                batch.append(j)
                j.start()
            for j in batch:
                j.join()

        fixedTraceCollection = MemTraceCollection(tracesFixed.values())
        del tracesFixed
        rndTraceCollection = MemTraceCollection(tracesRandom.values())
        del tracesRandom

        log.info("Filtering stochastic events")
        distAnalyzer = DistributionAnalyzer(
            fixedTraceCollection, rndTraceCollection, self.loader
        )
        distAnalyzer.exec()
        possibleLeaks = distAnalyzer.finalize()
        degenerateCases = set()
        # traces which, for non-deterministic reasons, do not contain meaningful info
        for idx, t in enumerate(rndTraceCollection.traces):
            for leak in possibleLeaks:
                if len(t.trace[leak]) == 0:
                    degenerateCases.add(idx)
        rndTraceCollection.remove(degenerateCases)
        for idx, t in enumerate(rndTraceCollection.traces):
            for leak in possibleLeaks:
                assert len(t.trace[leak]) > 0
        log.info("Classifying leaks")
        lc = LeakageClassification(
            rndTraceCollection, self.loader, possibleLeaks, self.loader.leakageModel
        )
        lc.exec()
        res = lc.finalize()
        self.mivals = res
        log.info(f"Ignoring {len(possibleLeaks) - len(res)} leaks with low score")
        log.info(f"Indentified {len(res)} leak with good MI score:")
        self.results = [int(k, 16) for k in res.keys()]
        endtime = time.time()
        console.rule(
            f"results (took {time.strftime('%H:%M:%S', time.gmtime(endtime-starttime))})"
        )

        # Pinpoint where the leak occured - for dyn. bins report only the offset:
        for (
            lbound,
            ubound,
            _,
            label,
            _,
        ) in self.loader.mappings:
            for k in self.results:
                if lbound < k < ubound:
                    if self.loader.dynamic:
                        offset = k - self.loader.getlibbase(label.split("/")[-1])
                        symbname = getfnname(label.split(" ")[-1], offset)
                        console.print(
                            f'{offset:08x} - [MI = {self.mivals[hex(k)]:.2f}] \t at {symbname if symbname else "??":<30} {label.split("/")[-1]}'
                        )
                    else:
                        symbname = getfnname(label.split(" ")[-1], k)
                        console.print(
                            f'{k:08x} [MI={self.mivals[hex(k)]:.2f}] \t at {symbname if symbname else "??":<30} {label.split("/")[-1]}'
                        )

    def finalize(self):
        return self.results
