from collections import defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.logger import getLogger

log = getLogger()


class ReportGenerator:
    def __init__(
        self,
        results: pandas.DataFrame,
        loader: BinaryLoader,
        keylen: int,
    ) -> None:
        self.results = results
        self.mdString = ""
        self.loader = loader
        self.datetime = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        self.keylen = keylen

    def generateHeaders(self):
        self.mdString += f"# Microsurf Analysis Results \n\n"
        self.mdString += f"__Run at__: {self.datetime} \n\n"
        self.mdString += f"__Elapsed time (analysis)__: {self.loader.runtime} \n\n"
        self.mdString += f"__Elapsed time (single run emulation)__: {self.loader.emulationruntime} \n\n"
        self.mdString += f"__Total leaks (data)__: {len(self.results)} \n\n"
        self.mdString += f"__Leaks with MI score > 0.2 __: {len(self.results[self.results['MI score'] > 0.2])} \n\n"
        self.mdString += f"__mean/stdev MI score accross leaks with > 0.2 MI __: {self.results[self.results['MI score'] > 0.2]['MI score'].mean():.2f} ± {self.results[self.results['MI score'] > 0.2]['MI score'].std() if self.results[self.results['MI score'] > 0.2]['MI score'].std() != np.nan else 0:.2f}\n\n"
        self.mdString += (
            f"__Binary__: `{self.loader.binPath}`\n >{self.loader.filemagic} \n\n"
        )
        self.mdString += f"__Args__: `{self.loader.args}` \n\n"
        self.mdString += f"__Emulation root__: `{ self.loader.rootfs}` \n\n"

    def generateResults(self):
        self.mdString += "## Results\n\n"

        significant = self.results[self.results['MI score'] > 0.2].sort_values(by=["MI score"], ascending=False, inplace=False)
        if len(significant) > 0:
            self.mdString += "### Leaks with MI > 0.2\n\n"
            for i in range(len(significant)):
                row = significant[i:i+1]
                if len(row) == 0:
                    break
                self.mdString += row.loc[
                    :, ["offset", "MI score", "Leakage model", "Symbol Name", "Path"]
                ].to_markdown(index=False)
                self.mdString += "\n\nSource code snippet\n\n"
                src = row[["src"]].values[0][0]
                if len(src) == 0:
                    self.mdString += "\n```\nn/a\n```"
                else:
                    self.mdString += "```C\n"
                    for l in src:
                        self.mdString += l
                    self.mdString += "\n```\n"
                self.mdString += "\nKey bit dependencies (estimated):"
                if Path(f"{self.loader.reportDir}/assets/saliency-map-{hex(row[['runtime Addr']].values[0][0])}.png").is_file():
                    self.mdString += f"\n\n![saliency map](assets/saliency-map-{hex(row[['runtime Addr']].values[0][0])}.png)\n\n"
                else:
                    self.mdString += (
                        "\n\n MI not significant enough to estimate dependencies. \n\n"
                    )
        self.mdString += "\n ### Grouped by function name\n\n"
        self.mdString += (
            self.results.groupby("Symbol Name")
            .size()
            .reset_index(name="Leak Count")
            .sort_values(by=["Leak Count"], ascending=False)
            .to_markdown(index=False)
        )

        self.mdString += "\n ### All Leaks, sorted by MI\n\n"
        self.mdString += (
            self.results.loc[:, ["offset", "MI score", "Leakage model", "Symbol Name"]]
            .sort_values(by=["MI score"], ascending=False)
            .to_markdown(index=False)
        )

    def saveMD(self):
        self.generateHeaders()
        self.generateResults()
        with open(f"{self.loader.reportDir}/results.md", "w") as f:
            f.writelines(self.mdString)
        log.info(f"Saved results to {f.name}")
