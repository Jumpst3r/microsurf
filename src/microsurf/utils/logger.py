import logging
import warnings

from rich.console import Console
from rich.logging import RichHandler

warnings.filterwarnings("ignore")

LOGGING_LEVEL = logging.INFO

logging.basicConfig(
    level="INFO",
    format="[%(name)s]  %(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(
            rich_tracebacks=True,
        )
    ],
)


def getLogger():
    logger = logging.getLogger("MICROSURF")
    logger.setLevel(LOGGING_LEVEL)
    return logger


def getQilingLogger():
    logger = logging.getLogger("EMULATOR")
    logger.setLevel(LOGGING_LEVEL)
    return logger


def getConsole():
    return Console()
