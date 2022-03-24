import glob
import logging
import multiprocessing
import sys
from typing import List
from matplotlib.style import available
import numpy as np
import ray
import torch
from sklearn.ensemble import RandomTreesEmbedding
from microsurf.pipeline.tracetools.Trace import MemTrace, MemTraceCollection
from tqdm import tqdm

from microsurf.utils.report import ReportGenerator

from ..pipeline.Stages import (
    BinaryLoader,
    DistributionAnalyzer,
    LeakageClassification,
    MemWatcher,
    LeakageRegression,
)
from ..utils.elf import getfnname
from ..utils.logger import getConsole, getLogger, RayFilter

log = getLogger()
console = getConsole()


class PipeLineExecutor:
    def __init__(self, loader: BinaryLoader) -> None:
        self.loader = loader
        self.results: List[int] = []
        self.ITER_COUNT = 100
        self.multiprocessing = True

    def run(self):
        log.debug(f"CUDA ? -> {torch.cuda.is_available()}")
        if not ray.is_initialized():
            ray.init()
        import time

        starttime = time.time()

        log.info("Identifying possible leak locations")

        log.info("Estimating whether multiprocessing is worth it")

        start_time = time.time()
        INI_CNT = 10
        memWatchers = [
            MemWatcher.remote(
                self.loader.binPath,
                self.loader.args,
                self.loader.rootfs,
                self.loader.ignoredObjects,
                self.loader.mappings,
            )
            for _ in range(INI_CNT)
        ]
        [m.exec.remote(secret=self.loader.rndArg()[0]) for m in memWatchers]
        futures = [m.getResults.remote() for m in memWatchers]
        res = ray.get(futures)
        mt = MemTraceCollection([r[0] for r in res])
        emutime = np.mean([r[1] for r in res])
        end_time = time.time()
        [ray.kill(m) for m in memWatchers]
        mt.prune()
        NB_CORES = (
            multiprocessing.cpu_count() - 1 if multiprocessing.cpu_count() > 2 else 1
        )
        if (emutime * INI_CNT) < (end_time - start_time):
            log.warning("multiprocessing overhead too large, switching to sequencial.")
            ray.shutdown()
            ray.init(local_mode=True, logging_level=logging.CRITICAL)
            sys.stdout = RayFilter(sys.stdout)
            sys.stderr = RayFilter(sys.stderr)
            self.multiprocessing = False
            NB_CORES = 1
        else:
            log.info(f"Enabled multiprocessing using {NB_CORES} (v)cores.")
        log.info(f"Identified {len(mt.possibleLeaks)} candidates")

        log.info("Checking for non determinism")
        memWatchers = [
            MemWatcher.remote(
                self.loader.binPath,
                self.loader.args,
                self.loader.rootfs,
                self.loader.ignoredObjects,
                self.loader.mappings,
                locations=mt.possibleLeaks,
                deterministic=self.loader.deterministic,
            )
            for _ in range(INI_CNT)
        ]
        [m.exec.remote(secret=self.loader.fixedArg()[0]) for m in memWatchers]
        futures = [m.getResults.remote() for m in memWatchers]
        res = ray.get(futures)
        [ray.kill(m) for m in memWatchers]

        mt2 = MemTraceCollection([r[0] for r in res])

        deterministic = True
        for t in mt2.traces:
            for t2 in mt2.traces:
                for (k1, v1), (k2, v2) in zip(t.trace.items(), t2.trace.items()):
                    if k1 != k2 or v1 != v2:
                        deterministic = False

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

        if len(mt.possibleLeaks) > 1000:
            log.warning("!! this is a rare bug that I cannot track down !!")

        log.info("Running stage Leak Confirm")

        if self.multiprocessing:
            log.info(f"batching {2*self.ITER_COUNT} jobs across {NB_CORES} cores")

        resFixed = []
        resRnd = []
        binPath_id = ray.put(self.loader.binPath)
        args_id = ray.put(self.loader.args)
        rootfs_id = ray.put(self.loader.rootfs)
        ignoredObjects_id = ray.put(self.loader.ignoredObjects)
        mappings_id = ray.put(self.loader.mappings)
        deterministic_id = ray.put(self.loader.deterministic)
        possibleLeaks_id = ray.put(mt.possibleLeaks)
        memWatchers = [
            MemWatcher.remote(
                binPath_id,
                args_id,
                rootfs_id,
                ignoredObjects_id,
                mappings_id,
                deterministic=deterministic_id,
                locations=possibleLeaks_id,
            )
            for _ in range(NB_CORES)
        ]
        for _ in tqdm(range(0, self.ITER_COUNT, NB_CORES)):

            [m.exec.remote(secret=self.loader.fixedArg()[0]) for m in memWatchers]
            futuresFixed = [m.getResults.remote() for m in memWatchers]
            res = ray.get(futuresFixed)
            resFixed += [r[0] for r in res]
            [m.exec.remote(secret=self.loader.rndArg()[0]) for m in memWatchers]
            futuresRnd = [m.getResults.remote() for m in memWatchers]
            res = ray.get(futuresRnd)
            resRnd += [r[0] for r in res]

        rndTraceCollection = MemTraceCollection(resRnd)
        fixedTraceCollection = MemTraceCollection(resFixed)

        rndTraceCollection.prune()  # populates .possibleLeaks
        log.info("Filtering stochastic events")
        distAnalyzer = DistributionAnalyzer(
            fixedTraceCollection, rndTraceCollection, self.loader, deterministic
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
        log.info("Rating leaks")
        lc = LeakageClassification(rndTraceCollection, self.loader, possibleLeaks)
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
                        mivals = list(self.mivals[hex(k)].items())
                        console.print(
                            f'{offset:#08x} - [MI ({mivals[0][0]}) = {mivals[0][1]:.2f}] \t at {symbname if symbname else "??":<30} {label}'
                        )
                        self.MDresults.append(
                            {
                                "runtime Addr": k,
                                "offset": f"{offset:#08x}",
                                "MI score": mivals[0][1],
                                "Leakage model": mivals[0][0],
                                "Function": f'{symbname if symbname else "??":}',
                            }
                        )
                    else:
                        symbname = getfnname(path, k)
                        mivals = list(self.mivals[hex(k)].items())
                        console.print(
                            f'{k:#08x} -[MI ({mivals[0][0]}) = {mivals[0][1]:.2f}]  \t at {symbname if symbname else "??":<30} {label}'
                        )
                        self.MDresults.append(
                            {
                                "runtime Addr": k,
                                "offset": f"{k:#08x}",
                                "MI score": mivals[0][1],
                                "Leakage model": mivals[0][0],
                                "Function": f'{symbname if symbname else "??":}',
                                "Object": f'{path.split("/")[-1]}',
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
        if len(self.resultsDF) == 0:
            log.info("no leaks with sufficient MI to attempt regression.")
            self.resultsDFTotal = pd.DataFrame.from_dict(self.MDresults)
            self.resultsDFTotal.drop(columns=["runtime Addr"], inplace=True)
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
