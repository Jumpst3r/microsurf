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
import os
import time
from typing import List, Union

import pandas as pd

from .pipeline.DetectionModules import Detector
from .pipeline.Stages import LeakageClassification
from .pipeline.tracetools.Trace import MARK
from .utils.elf import getfnname, getCodeSnippet
from .utils.logger import getConsole, getLogger
from .utils.report import ReportGenerator

console = getConsole()
log = getLogger()


class SCDetector:
    """
    The SCDetector class is used to perform side channel detection analysis.

    Args:
        modules: List of detection modules to run.
        itercount: Number of traces per module to collect when estimating key bit dependencies.
        addrList: List of addresses for which to perform detailed key bit dependency estimates. If
            None, no estimates will be performed. If an empty list is passed, estimates will be generated for
            all leaks. To selectively perform estimates on given leaks, pass a list of runtime addresses as integers.
            The runtime addresses can be taken from the generated reports (Run first with addrList=None and then
            run a second time on addresses of interest as found in the report.)
    """

    def __init__(self, modules: List[Detector], itercount: int = 1000, addrList: Union[None, List[int]] = None):
        self.modules = modules
        self.ITER_COUNT = itercount
        self.addrList = addrList
        if addrList is None:
            self.quickscan = True
        elif len(addrList) == 0:
            self.quickscan = False
        elif len(addrList) > 0:
            self.quickscan = False

        if not modules:
            log.error("module list must contain at least one module")
            exit(0)
        self.loader = modules[0].loader
        self.results = {}
        self.starttime = None
        self.MDresults = []
        self.initTraceCount = 3

    def exec(self):
        """
        Perform the side channel analysis using the provided modules, saving the results to 'results'.
        """
        self.starttime = time.time()
        for module in self.modules:
            console.log(f"module {str(module)}")
            # first capture a small number of traces to identify possible leak locations.
            collection, asm = module.recordTraces(self.initTraceCount, getAssembly=False)
            if not collection.possibleLeaks:
                log.info(f"module {str(module)} returned no possible leaks")
                continue
            self.results[str(module)] = (collection.results, asm)
            if self.addrList:
                # check if the provided addresses were indeed found, if not, raise an error
                for addr in self.addrList[:]:
                    if hex(addr) not in collection.results:
                        log.warning(
                            f"provided address {hex(addr)} was not detected as a possible leak - retry or "
                            f"check address. Ignoring for now."
                        )

            log.info(f"Identified {len(collection.results)} possible leaks")
            # If requested, analyze the leaks for MI estimates and key bit dependencies
            if not self.quickscan:
                log.info(
                    f"performing in-depth analysis for {len(self.addrList) if self.addrList else len(collection.results)}/{len(collection.results)} leaks"
                )
                rndTraces, _ = module.recordTraces(
                    self.ITER_COUNT,
                    pcList=self.addrList if self.addrList else collection.possibleLeaks,
                )
                lc = LeakageClassification(rndTraces, module.loader, module.miThreshold)
                self.KEYLEN = lc.KEYLEN
                lc.analyze()
                self.results[str(module)] = (lc.results, asm)
        if not self.results:
            endtime = time.time()
            runtime = time.strftime("%H:%M:%S", time.gmtime(endtime - self.starttime))
            log.info(f"total runtime: {runtime}")
            return

        if self.results:
            log.info("Generating report - this might take a while.")
            self._formatResults()
            self._generateReport()

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
                        if self.loader.dynamic and label not in self.loader.binPath.name:
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
                            try:
                                asmsnippet = (
                                        f"[{hex(offset)}]" + asm[leakAddr].split("|")[1]
                                )
                            except KeyError:
                                asmsnippet = "n/a"
                            # log.info(f'runtime Addr: {hex(k)}, offset: {offset:#08x}, symbol name: {symbname}')
                            self.MDresults.append(
                                {
                                    "Runtime Addr": hex(k),
                                    "offset": f"{offset:#08x}",
                                    "MI score": mival,
                                    "Comment": MARK[k] if k in MARK else "none",
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
                            try:
                                asmsnippet = f"[{hex(k)}]" + asm[leakAddr].split("|")[1]
                            except KeyError:
                                asmsnippet = "n/a"
                            self.MDresults.append(
                                {
                                    "Runtime Addr": hex(k),
                                    "offset": f"{k:#08x}",
                                    "MI score": mival,
                                    "Comment": MARK[k] if k in MARK else "none",
                                    "Symbol Name": f'{symbname if symbname else "??":}',
                                    "Object Name": f'{path.split("/")[-1]}',
                                    "src": source,
                                    "asm": asmsnippet,
                                    "Source Path": f"{srcpath}:{ln}",
                                    "Detection Module": str(module),
                                }
                            )
        from rich import print as pprint
        endtime = time.time()
        self.loader.runtime = time.strftime(
            "%H:%M:%S", time.gmtime(endtime - self.starttime)
        )
        log.info(f"total runtime: {self.loader.runtime}")
        self.DF = pd.DataFrame.from_dict(self.MDresults)
        console.rule('Results', style="magenta")
        pprint(self.DF.loc[:, ['Runtime Addr', "offset", 'Comment', 'Symbol Name', 'Detection Module']])
        console.rule(style="magenta")

    def _generateReport(self):
        if "PYTEST_CURRENT_TEST" in os.environ:
            log.info("Testing, no report generated.")
            return
        if not self.MDresults:
            log.info("no results - no file.")
            return
        else:
            rg = ReportGenerator(
                results=self.DF,
                loader=self.loader,
                itercount=self.ITER_COUNT,
                threshold=min([m.miThreshold for m in self.modules]),
                quickscan=self.quickscan,
                addrList=self.addrList,
            )
        rg.saveMD()
