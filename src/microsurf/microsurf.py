"""
Microsurf: An architecture independent dynamic side channel detection framework.
The microsurd module is intended to be import and cannot be executed.
It exposes the SCDetector class.
Usage: from microsurf import SCDetector

refer to the class SCDetector documentation for further information.
"""

__all__ = ["SCDetector"]
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
    def __init__(self, modules: List[Detector], itercount=1000, addrList=None):
        self.modules = modules
        self.ITER_COUNT = itercount
        self.addrList = addrList
        if addrList is None:
            self.quickscan = True
            log.info("mode: Quickscan (addrList=None).")
        elif len(addrList) == 0:
            log.info("mode: Full scan (addrList=[])")
            self.quickscan = False
        elif len(addrList) > 0:
            log.info(f"mode: Selective scan (addrList={[hex(k) for k in self.addrList]})")
            self.quickscan = False

        if not modules:
            log.error("module list must contain at least one module")
            exit(1)
        self.loader = modules[0].loader
        self.results = {}
        self.starttime = None
        self.MDresults = []

    def exec(self):
        self.starttime = time.time()
        for module in self.modules:
            console.rule(f"module {str(module)}")
            # first capture a small number of traces to identify possible leak locations.
            collection, asm = module.recordTraces(5)
            if not collection.possibleLeaks:
                log.info(f"module {str(module)} returned no possible leaks")
                continue
            if 'mem' in str(module):
                # for performance reasons we need to get the assembly on a separate run for the memwatcher
                _, asm = module.recordTraces(1, pcList=collection.possibleLeaks)
            self.results[str(module)] = (collection.results, asm)
            if self.addrList:
                # check if the provided addresses were indeed found, if not, raise an error
                for addr in self.addrList[:]:
                    if hex(addr) not in collection.results:
                        log.warning(f'provided address {hex(addr)} was not detected as a possible leak - retry or '
                                    f'check address. Ignoring for now.')
                        self.addrList.remove(addr)

            log.info(f"Identified {len(collection.results)} possible leaks")
            # If requested, analyze the leaks for MI estimates and key bit dependencies
            if not self.quickscan:
                log.info(f"performing in-depth analysis for {len(self.addrList) if self.addrList else len(collection.results)}/{len(collection.results)} leaks")
                rndTraces, _ = module.recordTraces(
                    self.ITER_COUNT, pcList=self.addrList if self.addrList else collection.possibleLeaks
                )

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

                            mival = dic[hex(k)]
                            asmsnippet = (
                                f"[{hex(offset)}]" + asm[leakAddr].split("|")[1]
                            )
                            # log.info(f'runtime Addr: {hex(k)}, offset: {offset:#08x}, symbol name: {symbname}')
                            self.MDresults.append(
                                {
                                    "Runtime Addr": hex(k),
                                    "offset": f"{offset:#08x}",
                                    "MI score": mival,
                                    "Leakage model": "neural-learnt",
                                    "Symbol Name": f'{symbname if symbname else "??":}',
                                    "Object Name": f'{path.split("/")[-1]}',
                                    "src": source,
                                    "asm": asmsnippet,
                                    "Source Path": f"{srcpath}:{ln}",
                                    "Detection Module": str(module),
                                }
                            )
                        else:
                            symbname = getfnname(path, k)
                            source, srcpath, ln = getCodeSnippet(path, k)
                            mival = dic[hex(k)]
                            asmsnippet = f"[{hex(k)}]" + asm[leakAddr].split("|")[1]
                            self.MDresults.append(
                                {
                                    "Runtime Addr": hex(k),
                                    "offset": f"{k:#08x}",
                                    "MI score": mival,
                                    "Leakage model": "neural-learnt",
                                    "Symbol Name": f'{symbname if symbname else "??":}',
                                    "Object Name": f'{path.split("/")[-1]}',
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
                itercount=self.ITER_COUNT,
                threshold=min([m.miThreshold for m in self.modules]),
                quickscan=self.quickscan,
                addrList=self.addrList,
            )
        rg.saveMD()
