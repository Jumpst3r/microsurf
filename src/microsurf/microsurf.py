"""
Microsurf: An architecture independent dynamic side channel detection framework.
The microsurd module is intended to be import and cannot be executed.
It exposes the SCDetector class.
Usage: from microsurf import SCDetector

refer to the class SCDetector documentation for further information.
"""

__all__ = ['SCDetector']
__author__ = "Nicolas Dutly"
__version__ = "0.0.0a"

import glob
import time
from typing import List

from .pipeline.DetectionModules import Detector
from .pipeline.Stages import LeakageClassification
from .utils.elf import getfnname, getCodeSnippet
from .utils.logger import getConsole, getLogger
from .utils.report import ReportGenerator

console = getConsole()
log = getLogger()


class SCDetector:
    def __init__(self, modules: List[Detector], itercount=500):
        self.modules = modules
        self.ITER_COUNT = itercount
        if not modules:
            log.error("module list must contain at least one module")
            exit(1)
        self.loader = modules[0].loader
        self.results = {}
        self.starttime = None
        self.MDresults = []

    def exec(self):
        self.starttime = time.time()
        # first capture a small number of traces to identify possible leak locations.
        for module in self.modules:
            log.info(f"module {str(module)}")
            # Find possible leaks
            collection, _ = module.recordTraces(5)
            # Collect one trace to get assembly code
            _, asm = module.recordTraces(1, pcList=collection.possibleLeaks, getAssembly=True)
            rndTraces, _ = module.recordTraces(self.ITER_COUNT, pcList=collection.possibleLeaks)
            lc = LeakageClassification(rndTraces, module.loader, module.miThreshold)
            self.KEYLEN = lc.KEYLEN
            lc.analyze()
            self.results[str(module)] = (lc.results, asm)

        if self.results:
            self._formatResults()
            self.generateReport()


    def _formatResults(self):
        for (
                lbound,
                ubound,
                _,
                label,
                container,
        ) in self.loader.mappings:
            for (module, v) in self.results.items():
                (dic, asm) = v
                for leakAddr in dic:
                    k = int(leakAddr, 16)
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
                            source, srcpath, ln = (
                                getCodeSnippet(path, offset)
                                if ".so" in label or self.loader.dynamic
                                else getCodeSnippet(path, k)
                            )

                            mival, nhits, samples = dic[hex(k)]
                            console.print(
                                f'{offset:#08x} - [MI = {mival:.2f}] \t at {symbname if symbname else "??":<30} {label}'
                            )
                            asmsnippet = f'[{hex(offset)}]' + asm[leakAddr].split(']')[1]
                            self.MDresults.append(
                                {
                                    "runtime Addr": k,
                                    "offset": f"{offset:#08x}",
                                    "MI score": mival,
                                    "Leakage model": "neural-learnt",
                                    "Symbol Name": f'{symbname if symbname else "??":}',
                                    "Object Name": f'{path.split("/")[-1]}',
                                    "Num of hits per trace": nhits,
                                    "Number of traces in which leak was observed": samples,
                                    "src": source,
                                    "asm": asmsnippet,
                                    "Source Path": f"{srcpath}:{ln}",
                                    "Detection Module": str(module)
                                }
                            )
                        else:
                            symbname = getfnname(path, k)
                            source, srcpath, ln = getCodeSnippet(path, k)
                            mival, nhits, samples = dic[hex(k)]
                            console.print(
                                f'{k:#08x} -[MI = {mival:.2f}]  \t at {symbname if symbname else "??":<30} {label}'
                            )
                            asmsnippet = f'[{hex(k)}]' + asm[leakAddr].split(']')[1]
                            self.MDresults.append(
                                {
                                    "runtime Addr": k,
                                    "offset": f"{k:#08x}",
                                    "MI score": mival,
                                    "Leakage model": "neural-learnt",
                                    "Symbol Name": f'{symbname if symbname else "??":}',
                                    "Object Name": f'{path.split("/")[-1]}',
                                    "Num of hits per trace": nhits,
                                    "Number of traces in which leak was observed": samples,
                                    "src": source,
                                    "asm": asmsnippet,
                                    "Source Path": f"{srcpath}:{ln}",
                                    "Detection Module": str(module),
                                }
                            )
        endtime = time.time()
        self.loader.runtime = time.strftime(
            "%H:%M:%S", time.gmtime(endtime - self.starttime)
        )
        log.info(f"total runtime: {self.loader.runtime}")

    def generateReport(self):
        if not self.MDresults:
            log.info("no results - no file.")
            return
        else:
            import pandas as pd
            rg = ReportGenerator(
                results=pd.DataFrame.from_dict(self.MDresults),
                loader=self.loader,
                keylen=self.KEYLEN,
                itercount=self.ITER_COUNT,
                threshold=min([m.miThreshold for m in self.modules])
            )
        rg.saveMD()
