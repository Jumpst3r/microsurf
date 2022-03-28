from collections import defaultdict
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
        keylen: int,
    ) -> None:
        self.results = results
        self.resultsReg = resultsReg
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
        self.mdString += (
            f"__Binary__: `{self.loader.binPath}`\n >{self.loader.filemagic} \n\n"
        )
        self.mdString += f"__Args__:`{self.loader.args}` \n\n"
        self.mdString += f"__Deterministic__:`{self.loader.deterministic}` \n\n"
        self.mdString += f"__Emulation root__:`{ self.loader.rootfs}` \n\n"

    def generateResults(self):
        self.mdString += "## Results\n\n"

        if self.resultsReg is not None:
            if len(self.resultsReg[self.resultsReg["Prediction accuracy"] > 0.5]) > 0:
                self.mdString += "### Executive summary\n\n"
                self.mdString += f'Identified {len(self.resultsReg[self.resultsReg["Prediction accuracy"] > 0.5])} bits with prediction score > 0.5 \n\n'
                bitVals = (
                    self.resultsReg[self.resultsReg["Prediction accuracy"] > 0.5]
                    .loc[:, ["Leakage model", "Prediction accuracy"]]
                    .to_dict("index")
                )
                bitRes = defaultdict(list)
                for _, dic in bitVals.items():
                    bitNr = str(list(dic.values())[0]).split("-")[0]
                    predScore = list(dic.values())[1]
                    bitRes[bitNr].append(predScore)
                for k in bitRes:
                    bitRes[k] = max(bitRes[k])
                # do something cool here, expected number of traces for leakfree vs our vals.

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
            self.mdString += f"\n\n![saliency map](assets/saliency-map-{hex(row[['runtime Addr']].values[0][0])}.png)\n\n"
        self.mdString += "\n ### Grouped by function name\n\n"
        self.mdString += (
            self.results.groupby("Function")
            .size()
            .reset_index(name="Leak Count")
            .sort_values(by=["Leak Count"], ascending=False)
            .to_markdown(index=False)
        )
        if self.resultsReg is not None:
            if len(self.resultsReg[self.resultsReg["Linear regression score"] > 0]) > 0:
                self.mdString += "\n ### Regression results for leaks with MI > 0.1\n\n"
                self.mdString += "The [regression score](https://en.wikipedia.org/wiki/Coefficient_of_determination) is always in a [0,1] interval, with 1 indicating a perfect linear dependency between the memory read locations and L(secret) with L being the chosen leakage model.\n"
                self.mdString += (
                    self.resultsReg[self.resultsReg["Linear regression score"] > 0]
                    .loc[:, self.resultsReg.columns != "Prediction accuracy"]
                    .sort_values(by=["Linear regression score"], ascending=False)
                    .to_markdown(index=False)
                )
                self.mdString += "\n"
            if len(self.resultsReg[self.resultsReg["Prediction accuracy"] > 0]) > 0:
                self.mdString += "\n ### Bitwise prediction scores \n\n"
                self.mdString += "The prediction score is the accuracy in predicting a given bit value.\n"
                self.mdString += (
                    self.resultsReg[self.resultsReg["Prediction accuracy"] > 0]
                    .loc[:, self.resultsReg.columns != "Linear regression score"]
                    .sort_values(by=["Prediction accuracy"], ascending=False)
                    .to_markdown(index=False)
                )
                self.mdString += "\n"

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
