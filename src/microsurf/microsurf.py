"""
Microsurf: An architecture independent dynamic side channel detection framework
@author nicolas
"""

from typing import Any, Callable
from .pipeline.Executor import PipeLineExecutor
from .pipeline.Stages import BinaryLoader
from .utils.logger import getConsole, getLogger
from pathlib import Path

console = getConsole()
log = getLogger()


class SCDetector:
    """The SCDetector class can be used to detect secret dependent memory accesses in generic applications

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
            Optional for static binaries, defaults to a tmp directory.
        sharedObjects: List of shared libraries to trace. For example ['libssl.so.1.1', 'libcrypto.so.1.1'].
            Defaults to None, tracing only the target binary. Only applicable to dynamic binaries.
        resultsDir: Directory to which the markdown report will be saved, created if not not already existing.
    """

    def __init__(
        self,
        binPath: str,
        args: list[str],
        randGen: Callable[[], str],
        deterministic: bool,
        asFile: bool,
        sharedObjects: list[str] = [],
        jail: str = None,
        resultsDir: str = 'results'
    ) -> None:
        self.binPath = binPath
        self.args = args
        self.randGen = randGen
        self.deterministic = deterministic
        self.asFile = asFile
        self.rootfs = jail
        self.sharedObjects = sharedObjects
        self.resultsDir = resultsDir
        self._validate()

        Path(self.resultsDir + '/assets').mkdir(parents=True, exist_ok=True)


    def _validate(self):
        resrnd = set()
        for _ in range(10):
            resrnd.add(self.randGen())
        if len(resrnd) < 5:
            log.error(
                f"Provided random function not random enough (got {len(resrnd)} repeated values in 10 invocation."
            )
            exit(1)
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
            sharedObjects=self.sharedObjects,
            reportDir=self.resultsDir
        )

    def exec(self, report=False):
        """Executes the side channel analysis (secret dependent memory accesses).

        Args:
            report: Generates a markdown report. Defaults to False.

        Returns:
            A list of leak locations, as integers (IP values).
            For dynamic objects, the offsets are reported.
        """
        pipeline = PipeLineExecutor(loader=self.bl)
        pipeline.run()
        if report:
            pipeline.generateReport()
        return pipeline.finalize()
