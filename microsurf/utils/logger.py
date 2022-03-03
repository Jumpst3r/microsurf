import logging

LOGGING_LEVEL = logging.INFO

from rich.logging import RichHandler
from rich.console import Console

import warnings

warnings.filterwarnings("ignore")


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
    l = logging.getLogger("asdf")
    l.setLevel(logging.WARNING)
    FORMAT = "%(message)s"
    logging.basicConfig(
        level="WARNING",
        format=FORMAT,
        datefmt="[%X]",
    )

    return l


def getConsole():
    return Console()
