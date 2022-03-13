import multiprocessing
from typing import List

from microsurf.pipeline.tracetools.Trace import MemTraceCollection
from tqdm import tqdm

from ..pipeline.Stages import (
    BinaryLoader,
    DistributionAnalyzer,
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
        self.ITER_COUNT = 40

    def run(self):
        import time

        starttime = time.time()

        memWatcherFixed = MemWatcher(binaryLoader=self.loader)
        memWatcherRnd = MemWatcher(binaryLoader=self.loader)
        log.info("Running stage Leak Confirm")

        jobs = []
        manager = multiprocessing.Manager()
        tracesFixed = manager.dict()
        tracesRandom = manager.dict()
        # TODO let the user define how many cores.
        nbCores = (
            1 if multiprocessing.cpu_count() == 1 else multiprocessing.cpu_count() - 1
        )
        for i in range(self.ITER_COUNT):
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
        assert len(fixedTraceCollection.possibleLeaks) == 0
        del tracesFixed
        rndTraceCollection = MemTraceCollection(tracesRandom.values())
        del tracesRandom

        rndTraceCollection.prune()  # populates .possibleLeaks

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
