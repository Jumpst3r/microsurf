import logging
import os
import warnings

from rich.console import Console
from rich.logging import RichHandler

warnings.filterwarnings("ignore")

if 'DEBUG' in os.environ:
    LOGGING_LEVEL = logging.DEBUG
else:
    LOGGING_LEVEL = logging.INFO

banner = '''        &&                   
                    &&&      &&&&&      
                      /&&&&&& &&&&      
                      &&&&&&&&&&            Microsurf:  The Cross-Architecture Side Channel Detection Framework              
                   &&&&&&&&&&  (&&&     
                   &&&&&&&        &&&&      v.0.0-dev
                  &&&&  &&&&&           
             &&&&&&&      &&&           
         /&&&&,          *&&&           
..             ,.        &&&*           
         .....    ..     &&&            
     ...     ...     ..  &&.    
 .......              .. '''

logging.basicConfig(
    level="INFO",
    format="[%(name)s]  %(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(
            rich_tracebacks=True,
            show_path=True,
            show_level=False
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


"""
In serial mode ray will output actor names, polluting the output.
This filters out any ray messages.
"""


class RayFilter(object):
    def __init__(self, stream):
        self.stream = stream

    def __getattr__(self, attr_name):
        return getattr(self.stream, attr_name)

    def write(self, data):
        if ":actor_name:" or "pid=" in data:
            return
        self.stream.write(data)
        self.stream.flush()

    def flush(self):
        self.stream.flush()
