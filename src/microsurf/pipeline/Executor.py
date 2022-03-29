import glob
import logging
import multiprocessing
import sys
from typing import List

import numpy as np
import ray
import torch
from microsurf.pipeline.tracetools.Trace import (MemTrace, MemTraceCollection,
                                                 MemTraceCollectionFixed,
                                                 MemTraceCollectionRandom)
from microsurf.utils.report import ReportGenerator
from rich.progress import track
from sklearn.ensemble import RandomTreesEmbedding
from tqdm import tqdm

from ..pipeline.Stages import (BinaryLoader, DistributionAnalyzer,
                               LeakageClassification, LeakageRegression,
                               MemWatcher)
from ..utils.elf import getCodeSnippet, getfnname
from ..utils.logger import RayFilter, getConsole, getLogger

log = getLogger()
console = getConsole()


class PipeLineExecutor:
    def __init__(self, loader: BinaryLoader) -> None:
        self.loader = loader
        self.results: List[int] = []
        self.ITER_COUNT = 250
        self.multiprocessing = True

    def run(self, detector):
        log.debug(f"CUDA ? -> {torch.cuda.is_available()}")
        if not ray.is_initialized():
            ray.init()
        import time

        starttime = time.time()

        log.info("Identifying possible leak locations")
        tracesRnd = detector.recordTracesRandom(10)
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

        log.info("Running stage Leak Confirm")

        t_rand = detector.recordTracesRandom(500, pcList=possibleLeaks)

        if not deterministic:
            t_fixed = detector.recordTracesFixed(500, pcList=possibleLeaks)
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
                            if ".so" in label
                            else getfnname(path, k)
                        )
                        source = (
                            getCodeSnippet(path, offset)
                            if ".so" in label
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
        import pandas as pd

        self.resultsDF = pd.DataFrame.from_dict(self.MDresults)
        if len(self.resultsDF) == 0:
            log.info("No leaks found")
            return
        console.rule("Regression on high MI leaks")
        log.info("Trying to learn secret-trace mappings for high (>=0.1) MI leaks")
        dropped = []
        for idx, x in self.resultsDF.sort_values(
            by=["MI score"], ascending=False
        ).iterrows():
            if x[["MI score"]].values[0] < 0.1:
                dropped.append(idx)
        self.resultsDF.drop(dropped, inplace=True)
        if True or len(self.resultsDF) == 0:
            log.info("no leaks with sufficient MI to attempt regression.")
            self.resultsDFTotal = pd.DataFrame.from_dict(self.MDresults)
            # self.resultsDFTotal.drop(columns=["runtime Addr"], inplace=True)
            self.resultsDF = None
            self.generateReport()
            exit(0)
        log.info(f"gathering extra traces at {len(self.resultsDF)} locations")
        regressionTargets = self.resultsDF[["runtime Addr"]].values.tolist()
        regressionTargets = [i for sl in regressionTargets for i in sl]
        resultsRnd = []
        memWatchersRand = [
            MemWatcher.remote(
                binPath_id,
                args_id,
                rootfs_id,
                ignoredObjects_id,
                mappings_id,
                deterministic=deterministic_id,
                locations=regressionTargets,
            )
            for _ in range(NB_CORES)
        ]
        for _ in tqdm(range(0, 2 * self.ITER_COUNT, NB_CORES)):
            [m.exec.remote(secret=self.loader.rndArg()[0]) for m in memWatchersRand]
            futuresRnd = [m.getResults.remote() for m in memWatchersRand]
            res = ray.get(futuresRnd)
            resultsRnd += [r[0] for r in res]
        ray.shutdown()
        regressionTracesTrain = MemTraceCollection(
            resRnd
        )  # increase sample size by reusing previously collected traces
        regressionTracesTest = MemTraceCollection(
            rndTraceCollection.get(regressionTargets)
        )

        regressor = LeakageRegression(
            regressionTracesTrain,
            regressionTracesTest,
            self.loader,
            regressionTargets,
            self.mivals,
        )
        regressor.exec()
        res = regressor.finalize()
        self.resultsDF["Linear regression score"] = [a[0] for a in res.values()]
        self.resultsDF["Prediction accuracy"] = [a[1] for a in res.values()]
        self.resultsDFTotal = pd.DataFrame.from_dict(self.MDresults)
        self.resultsDFTotal.drop(columns=["runtime Addr"], inplace=True)
        self.resultsDF.drop(columns=["runtime Addr"], inplace=True)
        endtime = time.time()
        self.loader.runtime = time.strftime(
            "%H:%M:%S", time.gmtime(endtime - starttime)
        )

    def generateReport(self):
        if not self.MDresults:
            log.info("no results - no file.")
            return
        rg = ReportGenerator(
            results=self.resultsDFTotal,
            resultsReg=self.resultsDF,
            loader=self.loader,
            keylen=self.KEYLEN,
        )
        rg.saveMD()

    def finalize(self):
        return self.results
