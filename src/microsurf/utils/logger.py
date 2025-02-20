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
                   &&&&&&&        &&&&      v.1.0
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
            show_path=False,
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
