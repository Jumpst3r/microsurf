"""
Microsurf: An architecture independent dynamic side channel detection framework
@author nicolas
"""

from qiling import *
from qiling.const import *
from capstone import *
from capstone.x86_const import *
from capstone.arm_const import *
from pipeline.Executor import *
from pipeline.tracetools import *
from utils.logger import getConsole, getLogger
import argparse
from pyfiglet import figlet_format

def main():
    console = getConsole()
    log = getLogger()

    parser = argparse.ArgumentParser(description="Microsurf: An architecture independent dynamic side channel analysis framework")
    parser.add_argument('--binary', metavar='PATH',type=str, required=True, help='path to the target binary')
    parser.add_argument('--sc',type=str, choices= ['data', 'cf'], required=True ,help='analyze for data or control flow SCs')
    args = parser.parse_args()
    
    console.print(figlet_format('microSurf', font='slant') + 'v0.0.0.0')
    console.rule(f"[b]binary target:[/b] {args.binary}")
    log.info(f"Anaylzing: {args.sc} side channels")
    
    binLoader = BinaryLoader(path=args.binary, args=["1"], dryRunOnly=False)

    pipeline = PipeLineExecutor(loader=binLoader)
    pipeline.run()


if __name__ == "__main__":
    main()
