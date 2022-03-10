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
            memCheckStage_leak = MemWatcher(
                binaryLoader=self.loader, archPCs=possibleLeaks
            )
        else:
            memCheckStage_leak = MemWatcher(binaryLoader=self.loader)

        log.info("Running stage Leak Detection")
        for i in range(2):
            # log.info(f'--{i}/{10}')
            memCheckStage_leak.exec(self.loader.rndArg)

        memCheckStage_leak.finalize()
        memCheckStage_detect1 = MemWatcher(
            binaryLoader=self.loader, archPCs=possibleLeaks if isARCH else None
        )
        memCheckStage_detect2 = MemWatcher(
            binaryLoader=self.loader, archPCs=possibleLeaks if isARCH else None
        )
        log.info("Running stage Leak Confirm")

        # run multiple times with a fixed secret
        FIXED_ITER_CNT = 40
        for i in tqdm(range(FIXED_ITER_CNT)):
            # log.info(f'--{i}/{FIXED_ITER_CNT}')
            memCheckStage_detect1.exec(self.loader.fixedArg)

        fixedTraceCollection = memCheckStage_detect1.finalize()

        # run multiple times with random secrets
        for i in tqdm(range(FIXED_ITER_CNT)):
            # log.info(f'--{i}/{FIXED_ITER_CNT}')
            memCheckStage_detect2.exec(self.loader.rndArg)

        rndTraceCollection = memCheckStage_detect2.finalize()

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
