from capstone import CS_ARCH_ARM
from ..utils.logger import getConsole, getLogger
from ..pipeline.LeakageModels import identity
from typing import List
from ..pipeline.Stages import (
    BinaryLoader,
    DistributionAnalyzer,
    FindMemOps,
    MemWatcher,
    LeakageClassification,
)

log = getLogger()
console = getConsole()


class PipeLineExecutor:
    def __init__(self, loader: BinaryLoader) -> None:
        self.loader = loader
        self.results: List[int] = []

    def run(self):
        isARCH = False
        if self.loader.md.arch == CS_ARCH_ARM:
            isARCH = True
            memOpFinder = FindMemOps(binaryLoader=self.loader)
            memOpFinder.exec(self.loader.fixedArg)
            possibleLeaks = memOpFinder.finalize()
            memCheckStage_leak = MemWatcher(binaryLoader=self.loader, archPCs=possibleLeaks)
        else:
            memCheckStage_leak = MemWatcher(
                binaryLoader=self.loader
        )
        log.info("Running stage Leak Detection")

        # run with varying secrets, hooks every mem op
        for _ in range(10):
            memCheckStage_leak.exec(self.loader.rndArg)

        memTraceCollection = memCheckStage_leak.finalize()
        oldleaks = memTraceCollection.possibleLeaks

        memCheckStage_detect1 = MemWatcher(
            binaryLoader=self.loader, archPCs= possibleLeaks if isARCH else None
        )
        memCheckStage_detect2 = MemWatcher(
            binaryLoader=self.loader, archPCs= possibleLeaks if isARCH else None
        )
        log.info("Running stage Leak Confirm")

        # run multiple times with a fixed secret
        FIXED_ITER_CNT = 100
        for _ in range(FIXED_ITER_CNT):
            memCheckStage_detect1.exec(self.loader.fixedArg)

        fixedTraceCollection = memCheckStage_detect1.finalize()

        # run multiple times with random secrets
        for _ in range(FIXED_ITER_CNT):
            memCheckStage_detect2.exec(self.loader.rndArg)

        rndTraceCollection = memCheckStage_detect2.finalize()

        distAnalyzer = DistributionAnalyzer(
            fixedTraceCollection, rndTraceCollection, self.loader
        )
        distAnalyzer.exec()
        possibleLeaks = distAnalyzer.finalize()
        for e in possibleLeaks:
            assert e in oldleaks
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
            rndTraceCollection, self.loader, possibleLeaks, identity
        )
        lc.exec()
        res = lc.finalize()
        self.mivals = res
        log.info(f"Ignoring {len(possibleLeaks) - len(res)} leaks with low score")
        log.info(f"Indentified {len(res)} leak with good MI score:")
        for ip in res.keys():
            log.info(f"[{ip}] [MI score: {res[ip]:.2f}] ")
        self.results = [int(k, 16) for k in res.keys()]

    def finalize(self):
        return self.results
