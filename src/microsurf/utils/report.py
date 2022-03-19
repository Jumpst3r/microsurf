import pandas
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.logger import getLogger
from datetime import datetime

log = getLogger()


class ReportGenerator:
    def __init__(
        self,
        results: pandas.DataFrame,
        resultsReg: pandas.DataFrame,
        loader: BinaryLoader,
    ) -> None:
        self.results = results
        self.resultsReg = resultsReg
        self.mdString = ""
        self.loader = loader
        self.datetime = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

    def generateHeaders(self):
        self.mdString += f"# Microsurf Analysis Results \n"
        self.mdString += f"## Metadata \n"
        self.mdString += f"__Run at__: {self.datetime} \n"
        self.mdString += f"__Elapsed time (analysis)__: {self.loader.runtime} \n"
        self.mdString += f"__Elapsed time (single run emulation)__: {self.loader.emulationruntime} \n"
        self.mdString += (
            f"__Binary__\n`{self.loader.binPath}`\n >{self.loader.filemagic} \n\n"
        )
        self.mdString += f"__Args__\n`{self.loader.args}` \n"
        self.mdString += f"__Deterministic__\n`{self.loader.deterministic}` \n"
        self.mdString += f"__Emulation root__\n`{ self.loader.rootfs}` \n"
        self.mdString += (
            f"__Leakage model__\n`{ str(self.loader.leakageModel).split(' ')[1]}` \n"
        )

    def generateResults(self):
        self.mdString += "## Results\n"
        self.mdString += "### Top 5, sorted by MI\n"
        self.mdString += self.results.sort_values(by=["MI score"], ascending=False)[
            :5
        ].to_markdown(index=False)
        self.mdString += "\n ### Grouped by function name\n"
        self.mdString += (
            self.results.groupby("Function")
            .size()
            .reset_index(name="Leak Count")
            .sort_values(by=["Leak Count"], ascending=False)
            .to_markdown(index=False)
        )
        if self.resultsReg is not None:
            self.mdString += "\n ### Regression results for leaks with MI > 0.4\n"
            self.mdString += "The [linear regression score](https://en.wikipedia.org/wiki/Coefficient_of_determination) is always in a [0,1] interval, with 1 indicating a perfect linear dependency between the memory read locations and L(secret) with L being the chosen leakage model.\n"
            self.mdString += self.resultsReg.sort_values(
                by=["Linear regression score"], ascending=False
            ).to_markdown(index=False)
            self.mdString += "\n"

        self.mdString += "\n ### All Leaks, sorted by MI\n"
        self.mdString += self.results.sort_values(
            by=["MI score"], ascending=False
        ).to_markdown(index=False)

    def saveMD(self):
        self.generateHeaders()
        self.generateResults()
        with open(f"results.md", "w") as f:
            f.writelines(self.mdString)
        log.info(f"Saved results to {f.name}")
