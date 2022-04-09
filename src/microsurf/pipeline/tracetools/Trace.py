import pickle
from typing import Dict, List, Set
from collections import defaultdict

from microsurf.utils.logger import getConsole, getLogger
import pandas as pd

log = getLogger()
console = getConsole()


class MemTrace:
    """Represents a single Memory Trace object.

    Initialized with a secret, trace items are then
    added by calling the .add(ip, memaddr) method.

    Args:
        secret: The secret that was used when the trace
        was recorded.
    """

    def __init__(self, secret) -> None:
        self.secret = secret
        self.trace: Dict[int, List[int]] = defaultdict(list)

    def add(self, ip, memaddr):
        """Adds an element to the current trace.
        Note that several target memory addresses
        can be added to the same PC by calling the
        function repeatedly.

        Args:
            ip: The instruction pointer / PC which caused
            the memory read
            memaddr: The target address that was read.
        """
        self.trace[ip].append(memaddr)

    def remove(self, keys: List[int]):
        """Removes a set of PCs from the given trace

        Args:
            keys: The set of PCs to remove
        """
        for k in keys:
            self.trace.pop(k)


class MemTraceCollection:
    """A generic MemorTraceCollection object.

    Args:
        traces: The traces that make up the collection.
    """

    def __init__(self, traces: list[MemTrace]):
        self.traces = traces
        self.possibleLeaks: Set[int] = set()

    def remove(self, indices: List[int]):
        """Remove a set of PCs/IPs from all traces in
        the collection.

        Args:
            indices: List of PCs to remove.
        """
        for index in sorted(indices, reverse=True):
            del self.traces[index]

    def get(self, indices: List[int]) -> List[MemTrace]:
        """Returns all memory traces which contain the
        specified PCs

        Args:
            indices: List of PCs

        Returns:
            List of memory traces which contain the
        specified PCs
        """
        res = []
        for index in indices:
            for t in self.traces:
                if index in t.trace:
                    res.append(t)
        return res

    def toDisk(self, path: str):
        with open(path, "wb") as f:
            pickle.dump(self, f)

    def __len__(self):
        return len(self.traces)


class MemTraceCollectionFixed(MemTraceCollection):
    """Creates a Memory trace collection object.
    The secrets of the individual traces must be fixed.

    Args:
        traces: List of memory traces
    """

    def __init__(self, traces: list[MemTrace]):
        super().__init__(traces)
        secrets = set()
        for t in self.traces:
            secrets.add(t.secret)
        assert len(secrets) == 1


class MemTraceCollectionRandom(MemTraceCollection):
    """Creates a Memory trace collection object.
    The secrets of the individual traces must be random.

    Args:
        traces: List of memory traces
    """

    def __init__(self, traces: list[MemTrace]):
        super().__init__(traces)
        self.possibleLeaks: Set[int] = set()
        self.buildDataFrames()


    def buildDataFrames(self):
        """Build a dictionary of dataframes, indexed by leak adress.
        T[leakAddr] = df with rows indexing the executions and columns the addresses accessed.
        The first column contains the secret.
        """
        perLeakDict = {}
        leakAddrs = [list(a.trace.keys()) for a in self.traces]
        leakAddrs = [i for l in leakAddrs for i in l] # flatten
        from rich.progress import track
        for l in track(leakAddrs, description="analyzing traces"):
            row = []
            for trace in self.traces:
                if l not in trace.trace: continue
                entry = []
                entry.append(trace.secret)
                entry += trace.trace[l]
                row.append(entry)
            f = pd.DataFrame(row)
            f = f.set_index(0)
            f.drop(f.std()[f.std() == 0].index, axis=1, inplace=True)
            if len(f.columns) and len(set(list(f.index.values))) > 1:
                perLeakDict[l] = f
        self.traces = perLeakDict
        self.possibleLeaks = list(self.perLeakTrace.keys())
        log.info(f"Identified {len(self.possibleLeaks)} leaks")
