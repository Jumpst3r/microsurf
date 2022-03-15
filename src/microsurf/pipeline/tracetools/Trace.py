from typing import Dict, List, Set
from collections import defaultdict
from microsurf.utils.logger import getConsole, getLogger

log = getLogger()
console = getConsole()


class MemTrace:
    def __init__(self, secret) -> None:
        self.secret = secret
        self.trace: Dict[int, List[int]] = defaultdict(list)

    def add(self, ip, memaddr):
        self.trace[ip].append(memaddr)

    def remove(self, keys):
        for k in keys:
            self.trace.pop(k)


class MemTraceCollection:
    def __init__(self, traces: list[MemTrace]):
        self.traces = traces
        self.possibleLeaks: Set[int] = set()

    def prune(self):
        commonItems = set()
        for t in self.traces:
            for k1, v1 in t.trace.items():
                common = 1
                occurs = 1
                for t2 in self.traces:
                    if t.secret == t2.secret:
                        continue
                    if k1 in t2.trace and t2.trace[k1] == v1:
                        common += 1
                    if k1 not in t2.trace:
                        occurs += 1
                if common == len(self.traces):
                    commonItems.add(k1)

        log.info(f"pruned {len(commonItems)} entries")
        for t in self.traces:
            if len(commonItems) > 0:
                t.remove(commonItems)
                for k in t.trace.keys():
                    self.possibleLeaks.add(k)

    def remove(self, indices):
        for index in sorted(indices, reverse=True):
            del self.traces[index]

    def __len__(self):
        return len(self.traces)
