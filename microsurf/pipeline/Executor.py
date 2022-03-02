import random

from capstone import *
from capstone.arm_const import *
from capstone.x86_const import *
from qiling import *
from qiling.const import *
from utils.logger import getConsole, getLogger
from yaspin import yaspin

from pipeline.Stages import BinaryLoader, DistributionAnalyzer, FindMemOps, MemWatcher

log = getLogger()
console = getConsole()


class PipeLineExecutor:
    def __init__(self, loader: BinaryLoader) -> None:
        self.loader = loader
        self.results = {}
        self.secrets = [random.randint(0x00, 0xFF) for _ in range(10)]

    def run(self):

        memCheckStage_leak = FindMemOps(binaryLoader=self.loader)

        log.info(f"Running stage Leak Detection")

        # run with varying secrets, hooks every mem op
        for i, arg in enumerate(self.secrets):
            with yaspin(
                text=f"Executing Leak Detection ({i}/{len(self.secrets)})", timer=True
            ):
                memCheckStage_leak.exec(secret=str(arg))

        memTraceCollection = memCheckStage_leak.finalize()
        memCheckStage_detect1 = MemWatcher(
            binaryLoader=self.loader, memTraceCollection=memTraceCollection
        )
        memCheckStage_detect2 = MemWatcher(
            binaryLoader=self.loader, memTraceCollection=memTraceCollection
        )
        log.info(f"Running stage Leak Confirm")
        log.info(f"Collecting fixed secret traces")

        # run multiple times with a fixed secret
        FIXED_ITER_CNT = 10
        for idx, i in enumerate(range(FIXED_ITER_CNT)):
            with yaspin(
                text=f"Executing Leak Confirm [fixed] ({idx}/{FIXED_ITER_CNT})",
                timer=True,
            ):
                memCheckStage_detect1.exec(secret=str(0))

        fixedTraceCollection = memCheckStage_detect1.finalize()

        log.info(f"Collecting variable secret traces")
        # run multiple times with random secrets

        for idx, i in enumerate(range(FIXED_ITER_CNT)):
            with yaspin(
                text=f"Executing Leak Confirm [random] ({idx}/{FIXED_ITER_CNT})",
                timer=True,
            ):
                memCheckStage_detect2.exec(secret=str(random.randint(0x00, 0xFF)))

        rndTraceCollection = memCheckStage_detect2.finalize()
        distAnalyzer = DistributionAnalyzer(
            fixedTraceCollection, rndTraceCollection, self.loader
        )
        log.info("Filtering false positives")
        distAnalyzer.exec()
        self.results = distAnalyzer.finalize()

        log.info(f"Indentified {len(self.results)} leaks:")
        for ip in self.results:
            log.info(f"[{hex(ip)}] {self.loader.asm[hex(ip)]}")

    def finalize(self):
        return self.results
