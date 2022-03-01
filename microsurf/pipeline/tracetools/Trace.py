
from qiling import *
from qiling.const import *
from capstone import *
from capstone.x86_const import *
from capstone.arm_const import *
import json
from collections import defaultdict
from utils.logger import getConsole, getLogger

log = getLogger()
console = getConsole()


class MemTrace:
    def __init__(self, secret) -> None:
        self.secret = secret
        self.trace = defaultdict(set)

    def add(self, ip, memaddr):
        self.trace[ip].add(memaddr)

    def remove(self, keys):
        for k in keys:
            self.trace.pop(k)


class MemTraceCollection:
    def __init__(self, traces: list[MemTrace], caller, prune=False):
        self.traces = traces
        # FIXME Bad design
        self.caller = caller
        self.possibleLeaks = set()
        if prune:
            self.prune()

    #FIXME trace prunning for non deterministic CFs
    def prune(self):
        commonItems = set()
        for t in self.traces:
            for k1,v1 in t.trace.items():
                common = 1
                for t2 in self.traces:
                    if t.secret == t2.secret:
                        continue
                    if k1 in t2.trace and t2.trace[k1] == v1:
                        common += 1
                if common == len(self.traces):
                    commonItems.add(k1)
                    common = 0
        for t in self.traces:
            t.remove(commonItems)
            for k in t.trace.keys():
                self.possibleLeaks.add(k)
        
        log.info(f"pruned {len(commonItems)} non secret dependent addresses")
        log.info(f"{len(self.possibleLeaks)} possible leaks")

    
    def jsonRep(self):
        _traceList = []
        for t in self.traces:
            _trace = {}
            _trace['secret'] = t.secret
            _evidence = []
            for k,v in t.trace.items():
                _evObj = {}
                _evObj["IP"] = hex(k)
                _evObj["opstr"] = self.caller.asm[hex(k)]
                _evObj["memAddr"] = [e for e in v]
                _evidence.append(_evObj)
                
            _trace["evidence"] = _evidence
            _traceList.append(_trace)

        jdict = {"stage":"Memtracer", "traces": _traceList}
        
        return json.dumps(jdict, indent=4)

    def __len__(self):
        return len(self.traces)




