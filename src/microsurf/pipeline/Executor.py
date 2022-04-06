import glob

import pickle
from typing import List

import ray
import torch

from microsurf.utils.report import ReportGenerator

from ..pipeline.Stages import (BinaryLoader, DistributionAnalyzer,
                               LeakageClassification)
from ..utils.elf import getCodeSnippet, getfnname
from ..utils.logger import getConsole, getLogger

log = getLogger()
console = getConsole()


class PipeLineExecutor:
    def __init__(self, loader: BinaryLoader) -> None:
        self.loader = loader
        self.results: List[int] = []
        self.ITER_COUNT = 500
        self.multiprocessing = True

    def run(self, detector):
        log.info(f"CUDA ? -> {torch.cuda.is_available()}")
        if not ray.is_initialized():
            ray.init()
        import time

        starttime = time.time()

        log.info("Identifying possible leak locations")
        tracesRnd = detector.recordTracesRandom(5)

        possibleLeaks = tracesRnd.possibleLeaks

        log.info("Checking for non determinism")
        tracesFixed = detector.recordTracesFixed(5)
        deterministic = detector.isDeterministic(tracesFixed)

        if not deterministic and self.loader.deterministic:
            log.warn(
                "Detected non deterministic behavior even though we are hooking sources of randomness !"
            )
        elif not deterministic and not self.loader.deterministic:
            log.info(
                "Non deterministic execution obeserved, consider setting deterministic=True"
            )
        elif deterministic:
            log.info("Execution appears to be deterministic, reducing trace count.")

        log.info(f"Running stage Leak Confirm ({len(possibleLeaks)} possible leaks)")

        #t_rand = detector.recordTracesRandom(self.ITER_COUNT, pcList=possibleLeaks)
        #t_rand.toDisk('camellia-enc-500-x64.pickle')

        with open("camellia-enc-500-x64.pickle", "rb") as f:
            t_rand = pickle.load(f)

        if not deterministic:
            t_fixed = detector.recordTracesFixed(self.ITER_COUNT, pcList=possibleLeaks)
        else:
            t_fixed = None

        if not deterministic:
            log.info("Filtering stochastic events")
            distAnalyzer = DistributionAnalyzer(
                t_fixed, t_rand, self.loader, deterministic
            )
            distAnalyzer.exec()
            possibleLeaks = distAnalyzer.finalize()

        log.info("Rating leaks")
        lc = LeakageClassification(t_rand, self.loader, possibleLeaks)
        self.KEYLEN = lc.KEYLEN
        lc.exec()
        res = lc.finalize()
        self.mivals = res
        self.results = [int(k, 16) for k in res.keys()]
        console.rule(f"MI results")
        self.MDresults = []
        # Pinpoint where the leak occured - for dyn. bins report only the offset:
        for (
            lbound,
            ubound,
            _,
            label,
            container,
        ) in self.loader.mappings:
            for k in self.results:
                if lbound < k < ubound:
                    path = (
                        container
                        if container
                        else glob.glob(
                            f'{self.loader.rootfs}/**/*{label.split(" ")[-1]}'
                        )[0]
                    )
                    if self.loader.dynamic:
                        offset = k - self.loader.getlibbase(label)
                        symbname = (
                            getfnname(path, offset)
                            if ".so" in label or self.loader.dynamic
                            else getfnname(path, k)
                        )
                        source = (
                            getCodeSnippet(path, offset)
                            if ".so" in label or self.loader.dynamic
                            else getCodeSnippet(path, k)
                        )

                        mivals = self.mivals[hex(k)]
                        console.print(
                            f'{offset:#08x} - [MI = {mivals[1]:.2f}] \t at {symbname if symbname else "??":<30} {label}'
                        )
                        self.MDresults.append(
                            {
                                "runtime Addr": k,
                                "offset": f"{offset:#08x}",
                                "MI score": mivals[1],
                                "Leakage model": "neural-learnt",
                                "Function": f'{symbname if symbname else "??":}',
                                "src": source,
                            }
                        )
                    else:
                        symbname = getfnname(path, k)
                        source = getCodeSnippet(path, k)
                        mivals = self.mivals[hex(k)]
                        console.print(
                            f'{k:#08x} -[MI = {mivals[1]:.2f}]  \t at {symbname if symbname else "??":<30} {label}'
                        )
                        self.MDresults.append(
                            {
                                "runtime Addr": k,
                                "offset": f"{k:#08x}",
                                "MI score": mivals[1],
                                "Leakage model": "neural-learnt",
                                "Function": f'{symbname if symbname else "??":}',
                                "Object": f'{path.split("/")[-1]}',
                                "src": source,
                            }
                        )
       

    def generateReport(self):
        if not self.MDresults:
            log.info("no results - no file.")
            return
        rg = ReportGenerator(
            results=self.resultsDFTotal,
            loader=self.loader,
            keylen=self.KEYLEN,
        )
        rg.saveMD()

    def finalize(self):
        return self.results
