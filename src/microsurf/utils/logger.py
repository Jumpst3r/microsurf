import logging
import warnings

from rich.console import Console
from rich.logging import RichHandler

warnings.filterwarnings("ignore")

LOGGING_LEVEL = logging.DEBUG

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

'''
In serial mode ray will output actor names, polluting the output.
This filters out any ray messages.
'''
class RayFilter(object):
    def __init__(self, stream):
        self.stream = stream

    def __getattr__(self, attr_name):
        return getattr(self.stream, attr_name)

    def write(self, data):
        if ":actor_name:" in data:
            return
        self.stream.write(data)
        self.stream.flush()

    def flush(self):
        self.stream.flush()