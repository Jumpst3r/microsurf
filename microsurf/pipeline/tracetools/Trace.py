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
        self.trace = defaultdict(list)

    def add(self, ip, memaddr):
        self.trace[ip].append(memaddr)

    def remove(self, keys):
        for k in keys:
            self.trace.pop(k)


class MemTraceCollection:
    def __init__(self, traces: list[MemTrace], caller):
        self.traces = traces
        # FIXME Bad design
        self.caller = caller
        self.possibleLeaks = set()
        self.prune()
        # for t in traces:
        #    for k in t.trace.keys():
        #        self.possibleLeaks.add(k)

    def prune(self):
        commonItems = set()
        for t in self.traces:
            for k1, v1 in t.trace.items():
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

    def remove(self, indices):
        for index in sorted(indices, reverse=True):
            del self.traces[index]

    def jsonRep(self):
        _traceList = []
        for t in self.traces:
            _trace = {}
            _trace["secret"] = t.secret
            _evidence = []
            for k, v in t.trace.items():
                _evObj = {}
                _evObj["IP"] = hex(k)
                _evObj["opstr"] = self.caller.asm[hex(k)]
                _evObj["memAddr"] = [e for e in v]
                _evidence.append(_evObj)

            _trace["evidence"] = _evidence
            _traceList.append(_trace)

        jdict = {"stage": "Memtracer", "traces": _traceList}

        return json.dumps(jdict, indent=4)

    def __len__(self):
        return len(self.traces)
