"""
Microsurf: An architecture independent dynamic side channel detection framework
@author nicolas
"""

from typing import Any, Callable
from .pipeline.Executor import PipeLineExecutor
from .pipeline.Stages import BinaryLoader
from .utils.logger import getConsole, getLogger
import argparse
from pyfiglet import figlet_format

console = getConsole()
log = getLogger()

"""
Mostly used for test suite binaries (./bin <secret> )
"""


def main():

    parser = argparse.ArgumentParser(
        description="Microsurf: An architecture independent dynamic side channel analysis framework"
    )
    parser.add_argument(
        "--binary",
        metavar="PATH",
        type=str,
        required=True,
        help="path to the target binary",
    )
    parser.add_argument(
        "--sc",
        type=str,
        choices=["data", "cf"],
        required=True,
        help="analyze for data or control flow SCs",
    )
    parser.add_argument(
        "--norandom",
        action="store_true",
        required=False,
        help="Force deterministic execution by controlling possible sources of randomness",
    )
    args = parser.parse_args()

    console.print(figlet_format("microSurf", font="slant") + "v0.0.0.0")
    console.rule(f"[b]binary target:[/b] {args.binary}")
    log.info(f"Anaylzing: {args.sc} side channels")

    binLoader = BinaryLoader(
        path=args.binary,
        args=["@"],
        dryRunOnly=False,
        deterministic=args.norandom,
    )

    pipeline = PipeLineExecutor(loader=binLoader)
    pipeline.run()


if __name__ == "__main__":
    main()


class SCDetector:
    """The SCDetector class can be used to detect side channels in generic applications

    Args:
        binPath: Path to the target binary
        args: List of arguments to pass to the binary. For a secret argument,
            substitute the value of the argument with @ (for example, ['--encrypt', '<privkeyfile>']
            would become ['--encrypt', '@'] ). Only one argument can be defined as secret.
        randGen: A function that generates random bytes in the format
            expected by the target binary. The SCDetector class will save these bytes
            to a temporary file and substitute the secret placeholder ('@') with the path to the file
        deterministic: Force deterministic execution by hooking relevant syscalls
        asFile: Specifies whether the target binary excepts the secret to be read from a file.
            If false, the secret will be passed directly as an argument
        jail: Specifies the a directory to which the binary will be jailed during emulation.
            For dynamic binaries, the user must ensure that the appropriate shared objects are present.
        leakageModel: (Callable[[str], Any]): Function which applies a leakage model to the secret.
            Example under microsurf.pipeline.LeakageModels
    """

    def __init__(
        self,
        binPath: str,
        args: list[str],
        randGen: Callable[[], str],
        deterministic: bool,
        asFile: bool,
        jail: str,
        leakageModel: Callable[[str], Any],
    ) -> None:
        self.binPath = binPath
        self.args = args
        self.randGen = randGen
        self.deterministic = deterministic
        self.asFile = asFile
        self.rootfs = jail
        self.leakageModel = leakageModel
        self._validate()

    def _validate(self):
        resrnd = set()
        for _ in range(10):
            resrnd.add(self.randGen())
        if len(resrnd) != 10:
            raise ValueError("Provided random function does not produce random output.")
        count = 0
        # Check that we only have a single secret marker
        for arg in self.args:
            count += arg.count("@")
        if count > 1:
            log.error(
                f"Only a single secret marker can be included in the argument list ({self.args})"
            )
            exit(1)
        self.bl = BinaryLoader(
            path=self.binPath,
            args=self.args,
            dryRunOnly=True,
            deterministic=self.deterministic,
            rndGen=self.randGen,
            asFile=self.asFile,
            jail=self.rootfs,
            leakageModel=self.leakageModel,
        )

    def exec(self):
        """Runs the side channel detection analysis"""
        pipeline = PipeLineExecutor(loader=self.bl)
        pipeline.run()
