from collections import defaultdict
from pathlib import Path
import pandas
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.logger import getLogger
from datetime import datetime


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
        self.mdString += f"## Metadata \n\n"
        self.mdString += f"__Run at__: {self.datetime} \n\n"
        self.mdString += f"__Elapsed time (analysis)__: {self.loader.runtime} \n\n"
        self.mdString += f"__Elapsed time (single run emulation)__: {self.loader.emulationruntime} \n\n"
        self.mdString += f"__Total leaks (data)__: {len(self.results)} \n\n"
        self.mdString += (
            f"__Binary__: `{self.loader.binPath}`\n >{self.loader.filemagic} \n\n"
        )
        self.mdString += f"__Args__:`{self.loader.args}` \n\n"
        self.mdString += f"__Deterministic__:`{self.loader.deterministic}` \n\n"
        self.mdString += f"__Emulation root__:`{ self.loader.rootfs}` \n\n"

    def generateResults(self):
        self.mdString += "## Results\n\n"

        self.mdString += "### Top 5, sorted by MI\n\n"
        for i in range(5):
            row = self.results.sort_values(by=["MI score"], ascending=False)[i : i + 1]
            if len(row) == 0:
                continue
            self.mdString += row.loc[
                :, ["offset", "MI score", "Leakage model", "Function"]
            ].to_markdown(index=False)
            self.mdString += "\n\nSource code snippet:\n\n"
            src = row[["src"]].values[0][0]
            if len(src) == 0:
                self.mdString += "\n```\nn/a\n```"
            else:
                self.mdString += "```C\n"
                for l in src:
                    self.mdString += l
                self.mdString += "\n```\n"
            self.mdString += "\nKey bit dependencies (estimated):"
            if Path.is_file(
                f"saliency-map-{hex(row[['runtime Addr']].values[0][0])}.png"
            ):
                self.mdString += f"\n\n![saliency map](assets/saliency-map-{hex(row[['runtime Addr']].values[0][0])}.png)\n\n"
            else:
                self.mdString += (
                    "\n\n MI not significant enough to estimate dependencies. \n\n"
                )
        self.mdString += "\n ### Grouped by function name\n\n"
        self.mdString += (
            self.results.groupby("Function")
            .size()
            .reset_index(name="Leak Count")
            .sort_values(by=["Leak Count"], ascending=False)
            .to_markdown(index=False)
        )

        self.mdString += "\n ### All Leaks, sorted by MI\n\n"
        self.mdString += (
            self.results.loc[:, ["offset", "MI score", "Leakage model", "Function"]]
            .sort_values(by=["MI score"], ascending=False)
            .to_markdown(index=False)
        )

    def saveMD(self):
        self.generateHeaders()
        self.generateResults()
        with open(f"{self.loader.reportDir}/results.md", "w") as f:
            f.writelines(self.mdString)
        log.info(f"Saved results to {f.name}")
