import logging
import warnings

from rich.console import Console
from rich.logging import RichHandler

warnings.filterwarnings("ignore")

QILING_VERBOSE = 0
LOGGING_LEVEL = logging.INFO


def getLogger():
    root = logging.getLogger()
    root.setLevel(LOGGING_LEVEL)
    FORMAT = "%(message)s"
    logging.basicConfig(
        level="INFO",
        format=FORMAT,
        datefmt="[%X]",
        handlers=[
            RichHandler(
                rich_tracebacks=True,
            )
        ],
    )

    return logging.getLogger("rich")


def getQillingLogger():
    logger = logging.getLogger("Qiling")
    logger.setLevel(logging.WARNING)
    FORMAT = "%(message)s"
    logging.basicConfig(
        level="WARNING",
        format=FORMAT,
        datefmt="[%X]",
    )

    return logger


def getConsole():
    return Console()
