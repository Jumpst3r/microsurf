import glob
import multiprocessing
from typing import List
import ray
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
from ..utils.logger import getConsole, getLogger

log = getLogger()
console = getConsole()


class PipeLineExecutor:
    def __init__(self, loader: BinaryLoader) -> None:
        self.loader = loader
        self.results: List[int] = []
        self.ITER_COUNT = 40

    def run(self):
        if not ray.is_initialized(): ray.init()
        import time

        starttime = time.time()

        log.info("Identifying possible leak locations")

        memWatchers = [
            MemWatcher.remote(
                self.loader.binPath,
                self.loader.args,
                self.loader.rootfs,
                self.loader.ignoredObjects,
                self.loader.mappings,
            )
            for _ in range(2)
        ]
        [m.exec.remote(secret=self.loader.rndArg()[0]) for m in memWatchers]
        futures = [m.getResults.remote() for m in memWatchers]
        mt = MemTraceCollection(ray.get(futures))
        [ray.kill(m) for m in memWatchers]
        mt.prune()

        log.info(f"Identified {len(mt.possibleLeaks)} candidates")
        if len(mt.possibleLeaks) > 1000:
            log.warn("!! this is a rare bug that I cannot track down !!")

        log.info("Running stage Leak Confirm")

        NB_CORES = (
            multiprocessing.cpu_count() // 2 if multiprocessing.cpu_count() > 1 else 1
        )

        resultsRnd = []
        resultsfixed = []
        log.info(f"batching {2*self.ITER_COUNT} jobs across {NB_CORES} cores")
        for _ in tqdm(range(0, self.ITER_COUNT, NB_CORES)):
            memWatchersFixed = [
                MemWatcher.remote(
                    self.loader.binPath,
                    self.loader.args,
                    self.loader.rootfs,
                    self.loader.ignoredObjects,
                    self.loader.mappings,
                    deterministic=self.loader.deterministic,
                    locations=mt.possibleLeaks,
                )
                for _ in range(NB_CORES)
            ]
            [m.exec.remote(secret=self.loader.fixedArg()[0]) for m in memWatchersFixed]
            futuresfixed = [m.getResults.remote() for m in memWatchersFixed]
            resultsfixed += ray.get(futuresfixed)
            [ray.kill(m) for m in memWatchersFixed]
            memWatchersRand = [
                MemWatcher.remote(
                    self.loader.binPath,
                    self.loader.args,
                    self.loader.rootfs,
                    self.loader.ignoredObjects,
                    self.loader.mappings,
                    deterministic=self.loader.deterministic,
                    locations=mt.possibleLeaks,
                )
                for _ in range(NB_CORES)
            ]
            [m.exec.remote(secret=self.loader.rndArg()[0]) for m in memWatchersRand]
            futuresRnd = [m.getResults.remote() for m in memWatchersRand]
            resultsRnd += ray.get(futuresRnd)
            [ray.kill(m) for m in memWatchersRand]

        rndTraceCollection = MemTraceCollection(resultsRnd)
        fixedTraceCollection = MemTraceCollection(resultsfixed)
        rndTraceCollection.prune()  # populates .possibleLeaks
        ray.stop()
        log.info("Filtering stochastic events")
        distAnalyzer = DistributionAnalyzer(
            fixedTraceCollection, rndTraceCollection, self.loader
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
        lc = LeakageClassification(
            rndTraceCollection, self.loader, possibleLeaks, self.loader.leakageModel
        )
        lc.exec()
        res = lc.finalize()
        self.mivals = res
        self.results = [int(k, 16) for k in res.keys()]
        endtime = time.time()
        self.loader.runtime = time.strftime(
            "%H:%M:%S", time.gmtime(endtime - starttime)
        )
        console.rule(f"results (took {self.loader.runtime})")
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
                        console.print(
                            f'{offset:#08x} - [MI = {self.mivals[hex(k)]:.2f}] \t at {symbname if symbname else "??":<30} {label}'
                        )
                        self.MDresults.append(
                            {
                                "runtime Addr": k,
                                "offset": f"{offset:#08x}",
                                "MI score": self.mivals[hex(k)],
                                "Function": f'{symbname if symbname else "??":}',
                            }
                        )
                    else:
                        symbname = getfnname(path, k)
                        console.print(
                            f'{k:#08x} [MI={self.mivals[hex(k)]:.2f}] \t at {symbname if symbname else "??":<30} {label}'
                        )
                        self.MDresults.append(
                            {
                                "runtime Addr": k,
                                "offset": f"{k:#08x}",
                                "MI score": self.mivals[hex(k)],
                                "Function": f'{symbname if symbname else "??":}',
                                "Object": f'{path.split("/")[-1]}',
                            }
                        )
        import pandas as pd

        self.resultsDF = pd.DataFrame.from_dict(self.MDresults)
        if len(self.resultsDF) == 0:
            log.info("No leaks found, exiting")
            exit(0)
        console.rule("Regression on high MI leaks")
        log.info("Trying to learn secret-trace mappings for high (>=0.4) MI leaks")
        dropped = []
        for idx, x in self.resultsDF.sort_values(
            by=["MI score"], ascending=False
        ).iterrows():
            if x[["MI score"]].values[0] < 0.4:
                dropped.append(idx)
        self.resultsDF.drop(dropped, inplace=True)
        log.info(f"gathering extra traces at {len(self.resultsDF)} locations")
        regressionTargets = self.resultsDF[["runtime Addr"]].values.tolist()
        regressionTargets = [i for sl in regressionTargets for i in sl]
        resultsRnd = []
        for _ in tqdm(range(0, 10, NB_CORES)):
            memWatchersRand = [
                MemWatcher.remote(
                    self.loader.binPath,
                    self.loader.args,
                    self.loader.rootfs,
                    self.loader.ignoredObjects,
                    self.loader.mappings,
                    deterministic=self.loader.deterministic,
                    locations=regressionTargets,
                )
                for _ in range(NB_CORES)
            ]
            [m.exec.remote(secret=self.loader.rndArg()[0]) for m in memWatchersRand]
            futuresRnd = [m.getResults.remote() for m in memWatchersRand]
            resultsRnd += ray.get(futuresRnd)
            [ray.kill(m) for m in memWatchersRand]
        ray.shutdown()
        regressionTraces = MemTraceCollection(
            resultsRnd + rndTraceCollection.get(regressionTargets)
        )  # increase sample size by reusing previously collected traces
        regressionTraces.prune()
        regressor = LeakageRegression(
            regressionTraces, self.loader, regressionTargets, self.loader.leakageModel
        )
        regressor.exec()
        res = regressor.finalize()
        self.resultsDF["Linear regression score"] = res.values()
        self.resultsDFTotal = pd.DataFrame.from_dict(self.MDresults)
        self.resultsDFTotal.drop(columns=["runtime Addr"], inplace=True)
        self.resultsDF.drop(columns=["runtime Addr"], inplace=True)

    def generateReport(self):
        if not self.MDresults:
            log.info("no results - no file.")
            return
        rg = ReportGenerator(
            results=self.resultsDFTotal, resultsReg=self.resultsDF, loader=self.loader
        )
        rg.saveMD()

    def finalize(self):
        return self.results
