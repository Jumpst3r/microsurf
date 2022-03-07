import random

from capstone import *
from capstone.arm_const import *
from capstone.x86_const import *
from qiling import *
from qiling.const import *
from utils.logger import getConsole, getLogger
from pipeline.LeakageModels import identity, hamming

from pipeline.Stages import (
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
        self.results = {}

    def run(self):

        memCheckStage_leak = FindMemOps(binaryLoader=self.loader)

        log.info(f"Running stage Leak Detection")

        # run with varying secrets, hooks every mem op
        for _ in range(10):
            memCheckStage_leak.exec(self.loader.rndArg)

        memTraceCollection = memCheckStage_leak.finalize()
        oldleaks = memTraceCollection.possibleLeaks
        memCheckStage_detect1 = MemWatcher(
            binaryLoader=self.loader, memTraceCollection=memTraceCollection
        )
        memCheckStage_detect2 = MemWatcher(
            binaryLoader=self.loader, memTraceCollection=memTraceCollection
        )
        log.info(f"Running stage Leak Confirm")

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
        self.results = possibleLeaks
        for e in possibleLeaks:
            assert e in oldleaks
        degenerateCases = (
            set()
        )  # traces which, for non-deterministic reasons, do not contain meaningful info
        for idx, t in enumerate(rndTraceCollection.traces):
            for l in possibleLeaks:
                if len(t.trace[l]) == 0:
                    degenerateCases.add(idx)
        rndTraceCollection.remove(degenerateCases)
        for idx, t in enumerate(rndTraceCollection.traces):
            for l in possibleLeaks:
                assert len(t.trace[l]) > 0

        lc = LeakageClassification(
            rndTraceCollection, self.loader, possibleLeaks, identity
        )
        lc.exec()
        res = lc.finalize()
        self.mivals = res
        log.info(f"Ignoring {len(possibleLeaks) - len(res)} leaks with low score")
        log.info(f"Indentified {len(res)} leak with good MI score:")
        for ip in res.keys():
            log.info(f"[{ip}] [MI score: {res[ip]:.2f}] {self.loader.asm[ip]} ")
        self.results = [int(k, 16) for k in res.keys()]

    def finalize(self):
        return self.results
