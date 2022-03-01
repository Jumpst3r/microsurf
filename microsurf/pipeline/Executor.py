
import random

from capstone import *
from capstone.arm_const import *
from capstone.x86_const import *
from qiling import *
from qiling.const import *
from utils.logger import getConsole, getLogger
from yaspin import yaspin

from pipeline.Stages import BinaryLoader, DistributionAnalyzer, MemTracer

log = getLogger()
console = getConsole()

class PipeLineExecutor:
    def __init__(self, loader: BinaryLoader) -> None:
        self.loader = loader
        self.results = {}
        self.secrets = [random.randint(0x00,0xff) for _ in range(20)]
        
    def run(self):

        memCheckStage_leak = MemTracer(binaryLoader=self.loader, coarse=True)

        log.info(f"Running stage Leak Detection")

        # run with varying secrets, hooks every mem op
        for i,arg in enumerate(self.secrets):
            with yaspin(text=f"Executing Leak Detection ({i}/{len(self.secrets)})", timer=True):
                memCheckStage_leak.exec(secret=str(arg))
    
        possible_leaks = memCheckStage_leak.finalize()
        memCheckStage_detect1 = MemTracer(binaryLoader=self.loader, coarse=False, possibleLeaks=possible_leaks)
        memCheckStage_detect2 = MemTracer(binaryLoader=self.loader, coarse=False, possibleLeaks=possible_leaks)
        
        log.info(f"Running stage Leak Confirm")
        log.info(f"Collecting fixed secret traces")

        # run multiple times with a fixed secret
        FIXED_ITER_CNT = 30
        for idx,i in enumerate(range(FIXED_ITER_CNT)):
            with yaspin(text=f"Executing Leak Confirm [fixed] ({idx}/{FIXED_ITER_CNT})", timer=True):
                memCheckStage_detect1.exec(secret=str(0))

        fixedTraceCollection = memCheckStage_detect1.finalize()
       
        log.info(f"Collecting variable secret traces")
         # run multiple times with random secrets

        for idx,i in enumerate(range(FIXED_ITER_CNT)):
            with yaspin(text=f"Executing Leak Confirm [random] ({idx}/{FIXED_ITER_CNT})", timer=True):
                memCheckStage_detect2.exec(secret=str(random.randint(0x00,0xff)))

        rndTraceCollection = memCheckStage_detect2.finalize()
        distAnalyzer = DistributionAnalyzer(fixedTraceCollection, rndTraceCollection, possible_leaks, self.loader)
        log.info("Filtering false positives")
        distAnalyzer.exec()
        self.results = distAnalyzer.finalize()

        log.info(f"Indentified {len(self.results)} leaks:")
        for ip in self.results:
            log.info(f"[{hex(ip)}] {self.loader.asm[hex(ip)]}")

    def finalize(self):
        return self.results        



