import glob
import multiprocessing

import pickle
from typing import List
from uuid import uuid4

import ray
import torch
import pandas as pd

from microsurf.utils.report import ReportGenerator

from ..pipeline.Stages import BinaryLoader, DistributionAnalyzer, LeakageClassification
from ..utils.elf import getCodeSnippet, getfnname
from ..utils.logger import getConsole, getLogger

log = getLogger()
console = getConsole()


class PipeLineExecutor:
    def __init__(self, loader: BinaryLoader) -> None:
        self.loader = loader
        self.results: List[int] = []
        self.ITER_COUNT = 100
        self.multiprocessing = True

    def run(self, detector):
        if not ray.is_initialized():
            ray.init(num_cpu=multiprocessing.cpu_count() - 1)
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

        if detector.randomTraces:
            with open(detector.randomTraces, "rb") as f:
                t_rand = pickle.load(f)
            log.info(f"loaded traces from {detector.randomTraces}")
        else:
            t_rand = detector.recordTracesRandom(self.ITER_COUNT, pcList=possibleLeaks)
            if detector.saveTraces:
                path = f"{self.loader.reportDir}/assets/trace_rand_{uuid4()}.pickle"
                log.info(f"saved random traces to {path}")
                t_rand.toDisk(path)

        if not deterministic:
            if detector.fixedTraces:
                with open(detector.fixedTraces, "rb") as f:
                    t_fixed = pickle.load(f)
                log.info(f"loaded traces from {detector.fixedTraces}")

            else:
                t_fixed = detector.recordTracesFixed(self.ITER_COUNT, pcList=possibleLeaks)
                if detector.saveTraces:
                    path = f"{self.loader.reportDir}/assets/trace_fixed_{uuid4()}.pickle"
                    log.info(f"saved fixed traces to {path}")
                    t_fixed.toDisk(path)

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
                        source, path = (
                            getCodeSnippet(path, offset)
                            if ".so" in label or self.loader.dynamic
                            else getCodeSnippet(path, k)
                        )

                        mival = self.mivals[hex(k)]
                        console.print(
                            f'{offset:#08x} - [MI = {mival:.2f}] \t at {symbname if symbname else "??":<30} {label}'
                        )
                        self.MDresults.append(
                            {
                                "runtime Addr": k,
                                "offset": f"{offset:#08x}",
                                "MI score": mival,
                                "Leakage model": "neural-learnt",
                                "Symbol Name": f'{symbname if symbname else "??":}',
                                "src": source,
                                "Path": path
                            }
                        )
                    else:
                        symbname = getfnname(path, k)
                        source, path = getCodeSnippet(path, k)
                        mival = self.mivals[hex(k)]
                        console.print(
                            f'{k:#08x} -[MI = {mival:.2f}]  \t at {symbname if symbname else "??":<30} {label}'
                        )
                        self.MDresults.append(
                            {
                                "runtime Addr": k,
                                "offset": f"{k:#08x}",
                                "MI score": mival,
                                "Leakage model": "neural-learnt",
                                "Symbol Name": f'{symbname if symbname else "??":}',
                                "Object": f'{path.split("/")[-1]}',
                                "src": source,
                                "Path": path
                            }
                        )
        endtime = time.time()
        self.loader.runtime = time.strftime(
            "%H:%M:%S", time.gmtime(endtime - starttime)
        )
        log.info(f"total runtime: {self.loader.runtime}")

    def generateReport(self):
        if not self.MDresults:
            log.info("no results - no file.")
            return
        else:
            self.resultsDFTotal = pd.DataFrame.from_dict(self.MDresults)
        rg = ReportGenerator(
            results=self.resultsDFTotal,
            loader=self.loader,
            keylen=self.KEYLEN,
        )
        rg.saveMD()

    def finalize(self):
        return self.results
