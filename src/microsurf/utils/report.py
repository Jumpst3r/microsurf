import markdown

from datetime import datetime
from pathlib import Path

import numpy as np
import pandas
import pandas as pd

from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.logger import getLogger

log = getLogger()


class ReportGenerator:
    def __init__(
            self,
            results: pandas.DataFrame,
            loader: BinaryLoader,
            itercount: int,
            threshold: int,
            quickscan: bool,
            addrList: list,
    ) -> None:
        self.results = results
        self.mdString = ""
        self.loader = loader
        self.datetime = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        self.itercount = itercount
        self.threshold = threshold
        self.quickscan = quickscan
        self.addrList = addrList

    def generateHeaders(self):
        self.mdString += f"# Microsurf Analysis Results\n\n"
        self.mdString += f"__Run at__: {self.datetime} \n\n"
        self.mdString += f"__Elapsed time (analysis)__: {self.loader.runtime} \n\n"
        self.mdString += f"__Elapsed time (single run emulation)__: {self.loader.emulationruntime} \n\n"
        if self.quickscan:
            self.mdString += f"__Total leak count__: {len(self.results)} \n\n"
        else:
            self.mdString += f"__Number of leak locations to investigate (selective scan)__: {len(self.addrList)} \n\n"
            self.mdString += (
                f"__Provided leak locations:__: {[hex(k) for k in self.addrList]} \n\n"
            )
        if not self.quickscan:
            self.mdString += f"__MI threshold__: {self.threshold} \n\n"
            self.mdString += f"__Leaks with MI score > {self.threshold}__: {len(self.results[self.results['MI score'] > self.threshold])} \n\n"
            self.mdString += f"__mean/stdev MI score accross leaks with > threshold MI__: {self.results[self.results['MI score'] > self.threshold]['MI score'].mean():.2f} ± {self.results[self.results['MI score'] > self.threshold]['MI score'].std() if self.results[self.results['MI score'] > self.threshold]['MI score'].std() != np.nan else 0:.2f}\n\n"
        self.mdString += (
            f"__Binary__: `{self.loader.binPath}`\n >{self.loader.filemagic} \n\n"
        )
        self.mdString += f"__Args__: `{self.loader.args}` \n\n"
        self.mdString += f"__Emulation root__: `{self.loader.rootfs}` \n\n"
        if self.quickscan:
            self.columns = [
                "Runtime Addr",
                "offset",
                "Detection Module",
                "Comment",
                "Symbol Name",
                "Object Name",
                "Source Path",
            ]
        else:
            self.columns = [
                "Runtime Addr",
                "offset",
                "MI score",
                "Detection Module",
                "Comment",
                "Symbol Name",
                "Object Name",
                "Source Path",
            ]

    def generateResults(self):
        self.mdString += "__Table of contents:__\n\n"
        self.mdString += "[TOC] \n\n"
        self.mdString += "## Overview by function name\n"
        countByFunc = (
            self.results.groupby("Symbol Name")
                .size()
                .reset_index(name="Leak Count")
                .sort_values(by=["Leak Count"], ascending=False)
        )
        ax = countByFunc.set_index("Symbol Name").plot.pie(
            y="Leak Count", figsize=(6, 4), colormap="Blues_r", legend=False
        )
        memdf = (
            self.results.where(self.results['Detection Module'] == 'Secret dep. mem. operation (R/W)').groupby(
                "Symbol Name")
                .size()
                .reset_index(name="Memory Leak Count")
                .sort_values(by=["Memory Leak Count"], ascending=False)
        )
        cfdf = (
            self.results.where(self.results['Detection Module'] == 'Secret dep. CF').groupby(
                "Symbol Name")
                .size()
                .reset_index(name="CF Leak Count")
                .sort_values(by=["CF Leak Count"], ascending=False)
        )
        mergedDF = pd.merge(memdf, cfdf, how='outer')
        mergedDF.fillna(0, inplace=True)
        with open(f"/tmp/summary.json", "w") as f:
            f.writelines(mergedDF.loc[:,["CF Leak Count", "Memory Leak Count"]].sum().to_json())
       
        fig = ax.get_figure()
        fig.savefig(f"{self.loader.resultDir}/assets/functions.png", dpi=300)
        #self.mdString += f'\n\n <img align="right" src="assets/functions.png" width=300 /> \n\n'
        self.mdString += mergedDF.to_markdown(index=False)
        self.mdString += "\n\n"
        significant = self.results[
            self.results["MI score"] > self.threshold
            ].sort_values(by=["MI score"], ascending=False, inplace=False)
        if self.quickscan:
            # quickscan case - show all details for every leak
            significant = self.results[self.results["MI score"] == -1].sort_values(
                by=["MI score"], ascending=False, inplace=False
            )
        if len(significant) > 0:
            snames = set(
                list(significant.loc[:, ["Symbol Name"]].to_dict("list").values())[0]
            )
            for s in snames:
                self.mdString += f"### Leaks for {s}\n\n"
                symbdf = significant[significant["Symbol Name"] == s]
                for i in range(len(symbdf)):
                    row = symbdf[i: i + 1]
                    if len(row) == 0:
                        break
                    self.mdString += row.loc[
                                     :,
                                     self.columns,
                                     ].to_markdown(index=False)
                    self.mdString += "\n\nSource code snippet\n\n"
                    src = row[["src"]].values[0][0]
                    if len(src) == 0:
                        self.mdString += "\n```\nn/a\n```"
                    else:
                        self.mdString += "```C\n"
                        for l in src:
                            self.mdString += l
                            self.mdString += '\n'
                        self.mdString += "\n```\n"
                    self.mdString += "\n\nLeaking instruction\n\n"
                    src = row[["asm"]].values[0][0]
                    self.mdString += "```\n"
                    self.mdString += src
                    self.mdString += "\n```\n"
                    if not self.quickscan:
                        self.mdString += "\nKey bit dependencies (estimated):"
                        if Path(
                                f"{self.loader.resultDir}/assets/saliency-map-{row[['Runtime Addr']].values[0][0]}.png"
                        ).is_file():
                            self.mdString += f"\n\n![saliency map](assets/saliency-map-{row[['Runtime Addr']].values[0][0]}.png)\n\n"
                        else:
                            self.mdString += "\n\n MI not significant enough to estimate dependencies. \n\n"

        if not self.quickscan:
            self.mdString += "\n\n ### All Leaks, sorted by MI\n\n"
            self.mdString += (
                self.results.loc[
                :,
                self.columns,
                ]
                    .sort_values(by=["MI score"], ascending=False)
                    .to_markdown(index=False)
            )

    def saveMD(self):
        self.generateHeaders()
        self.generateResults()
        with open(f"{self.loader.resultDir}/results.md", "w") as f:
            f.writelines(self.mdString)
            log.info(f"Markdown report saved: {f.name} !")
        html = markdown.markdown(self.mdString,  extensions=['markdown.extensions.tables', 'markdown.extensions.toc', 'markdown.extensions.fenced_code'])
        with open(f"{self.loader.resultDir}/results.html", "w") as f:
            f.writelines(html)
            log.info(f"HTML report saved: {f.name} !")
        with open(f"{self.loader.resultDir}/results.json", "w") as f:
            f.writelines(self.results.loc[:, ['Runtime Addr', "offset", 'Comment', 'Symbol Name', 'Detection Module', 'Object Name']].to_json())
            log.info(f"json report saved: {f.name} !")
