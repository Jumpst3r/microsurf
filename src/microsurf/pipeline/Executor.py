import multiprocessing
from capstone import CS_ARCH_ARM
from ..utils.logger import getConsole, getLogger
from ..pipeline.LeakageModels import hamming
from typing import List
from ..pipeline.Stages import (
    BinaryLoader,
    DistributionAnalyzer,
    FindMemOps,
    MemWatcher,
    LeakageClassification,
)
from tqdm import tqdm

log = getLogger()
console = getConsole()


class PipeLineExecutor:
    def __init__(self, loader: BinaryLoader) -> None:
        self.loader = loader
        self.results: List[int] = []

    def run(self):
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
        FIXED_ITER_CNT = 10
        # TODO let the user define how many cores.
        nbCores = 4
        for i in range(FIXED_ITER_CNT):
            pfixed = multiprocessing.Process(target=memWatcherFixed.exec, args=(self.loader.fixedArg, i, tracesFixed))
            jobs.append(pfixed)
            prand = multiprocessing.Process(target=memWatcherRnd.exec, args=(self.loader.rndArg, i, tracesRandom))
            jobs.append(prand)

        log.info(f"Buffered {len(jobs)} jobs")
        for i in range(0, len(jobs), nbCores):
            batch = []
            for j in jobs[i:i+nbCores]:
                batch.append(j)
                j.start()
            for j in batch: j.join()

        memWatcherFixed.traces += tracesFixed.values()
        memWatcherRnd.traces += tracesRandom.values()
        fixedTraceCollection = memWatcherFixed.finalize()
        rndTraceCollection = memWatcherRnd.finalize()

        distAnalyzer = DistributionAnalyzer(
            fixedTraceCollection, rndTraceCollection, self.loader
        )
        distAnalyzer.exec()
        possibleLeaks = distAnalyzer.finalize()

        degenerateCases = (
            set()
        )  # traces which, for non-deterministic reasons, do not contain meaningful info
        for idx, t in enumerate(rndTraceCollection.traces):
            for leak in possibleLeaks:
                if len(t.trace[leak]) == 0:
                    degenerateCases.add(idx)
        rndTraceCollection.remove(degenerateCases)
        for idx, t in enumerate(rndTraceCollection.traces):
            for leak in possibleLeaks:
                assert len(t.trace[leak]) > 0

        lc = LeakageClassification(
            rndTraceCollection, self.loader, possibleLeaks, self.loader.leakageModel
        )
        lc.exec()
        res = lc.finalize()
        self.mivals = res
        log.info(f"Ignoring {len(possibleLeaks) - len(res)} leaks with low score")
        log.info(f"Indentified {len(res)} leak with good MI score:")
        self.results = [int(k, 16) for k in res.keys()]
        console.rule("results")
        for j in self.results:
            log.info(j)
        # Pinpoint where the leak occured - for dyn. bins report only the offset:
        for (
            lbound,
            ubound,
            perms,
            label,
            container,
        ) in self.loader.QLEngine.mem.get_mapinfo():
            for k in self.results:
                if lbound < k < ubound:
                    if self.loader.dynamic:
                        log.info(
                            f'{k-self.loader.QLEngine.mem.get_lib_base(label.split("/")[-1]):08x} - [MI = {self.mivals[hex(k)]:.2f}] {label.split("/")[-1]}'
                        )
                    else:
                        log.info(
                            f'{k:08x} - [MI = {self.mivals[hex(k)]:.2f}] {label.split("/")[-1]}'
                        )

    def finalize(self):
        return self.results
