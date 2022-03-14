from typing import Dict, List
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.logger import getLogger
from tomark import Tomark
from datetime import datetime

log = getLogger()


class ReportGenerator:
    def __init__(
        self,
        results: List[Dict[str, str]],
        time: str,
        loader: BinaryLoader,
    ) -> None:
        self.results = results
        self.mdString = ""
        self.loader = loader
        self.datetime = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

    def generateHeaders(self):
        self.mdString += f"# Microsurf Analysis Results (run: {self.datetime})\n"
        self.mdString += f"## Metadata \n"
        self.mdString += (
            f"### Binary\n`{self.loader.binPath}`\n >{self.loader.filemagic} \n\n"
        )
        self.mdString += f"__Args__\n`{self.loader.args}` \n"
        self.mdString += f"__Deterministic__\n`{self.loader.deterministic}` \n"
        self.mdString += f"__Emulation root__\n`{ self.loader.rootfs}` \n"
        self.mdString += f"__Sample secret__\n`{ self.loader.rndArg()[0]}` \n"
        self.mdString += (
            f"__Leakage model__\n`{ str(self.loader.leakageModel).split(' ')[1]}` \n"
        )

    def generateResults(self):
        self.mdString += "## Results \n"
        self.mdString += Tomark.table(self.results)

    def saveMD(self):
        self.generateHeaders()
        self.generateResults()
        with open(f"results.md", "w") as f:
            f.writelines(self.mdString)
        log.info(f"Saved results to {f.name}")
