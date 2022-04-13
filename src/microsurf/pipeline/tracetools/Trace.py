import pickle
from collections import defaultdict
from typing import Dict, List, OrderedDict, Set

import numpy as np
import pandas as pd
from microsurf.utils.logger import getConsole, getLogger

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

    def __len__(self):
        return len(self.trace)


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
        addrs = [list(a.trace.keys()) for a in self.traces]
        addrs = set([i for l in addrs for i in l]) # flatten
        self.secretDepCF = []
        from rich.progress import track
        for l in track(addrs, description="analyzing traces"):
            row = []
            hits = []
            numhits = 0
            for trace in self.traces:
                if l not in trace.trace: continue
                entry = []
                entry.append(int(trace.secret, 16))
                entry += trace.trace[l]
                numhits = max(numhits, len(trace.trace[l]))
                hits.append(len(trace.trace[l]))
                row.append(entry)
            colnames = ['secret'] + [str(i) for i in range(numhits)]
            f = pd.DataFrame(row, columns=colnames)
            f = f.set_index('secret')
            f.drop(f.std()[f.std() == 0].index, axis=1, inplace=True)
            if len(f.columns):
                f.insert(loc=0, column='hits', value=hits)
                perLeakDict[l] = f
                if f.isnull().any().any():
                    # inconsistent number of times that leakAddr was hit => prob secret. dep. CF 
                    self.secretDepCF.append(l)
                perLeakDict[l].dropna(axis=0, inplace=True)
        if self.secretDepCF:
            log.warning(f"probable secret dep CF detected, number of leaks may vary between executions !")
        self.traces = perLeakDict
        self.possibleLeaks = list(self.traces.keys())
        log.debug(f"{len(self.secretDepCF)} locations contain missing values")
        for leak,v in self.traces.items():
            log.debug(f"stats for {hex(leak)}")
            log.debug(f"-num traces: {len(v.values)}")
            log.debug(f"-num columns: {len(v.values[0])}")
            # log.debug(f"-proportion of missing row values: \n{v.isnull().mean(axis=1)}")
        log.info(f"Identified {len(self.possibleLeaks)} leaks")


class PCTrace:
    """Represents a single Program Counter (PC) Trace object.

    Initialized with a secret, trace items are then
    added by calling the .add(ip) method.

    Args:
        secret: The secret that was used when the trace
        was recorded.
    """

    def __init__(self, secret) -> None:
        self.secret = secret
        self.trace: OrderedDict[int,int] = OrderedDict()

    def add(self, ip):
        """Adds an element to the current trace.
        Note that several target memory addresses
        can be added to the same PC by calling the
        function repeatedly.

        Args:
            ip: The instruction pointer / PC which caused
            the memory read
        """
        self.trace[ip] = 1
    
    def remove(self, keys: List[int]):
        """Removes a set of PCs from the given trace

        Args:
            keys: The set of PCs to remove
        """
        for k in keys:
            self.trace.pop(k)

    def __len__(self):
        return len(self.trace)


class PCTraceCollection:
    """A generic PCTraceCollection object.

    Args:
        traces: The traces that make up the collection.
    """

    def __init__(self, traces: list[PCTrace]):
        self.traces = traces
        self.possibleLeaks: Set[int] = set()

    def toDisk(self, path: str):
        with open(path, "wb") as f:
            pickle.dump(self, f)

    def __len__(self):
        return len(self.traces)


class PCTraceCollectionFixed(PCTraceCollection):
    """Creates a PC trace collection object.
    The secrets of the individual traces must be fixed.

    Args:
        traces: List of memory traces
    """

    def __init__(self, traces: list[PCTrace]):
        super().__init__(traces)
        secrets = set()
        for t in self.traces:
            secrets.add(t.secret)
        assert len(secrets) == 1

    def deterministic(self):
        """Determines whether the traces in the collection
        have identical control flow

        Returns:
            True if all traces have the same CF, False otherwise
        """
        mat = np.array([list(t.trace.keys()) for t in self.traces], dtype=np.uint64)
        return len(np.unique(mat, axis=0)) == 1


class PCTraceCollectionRandom(PCTraceCollection):
    """Creates a PC trace collection object.
    The secrets of the individual traces must be random.

    Args:
        traces: List of memory traces
    """

    def __init__(self, traces: list[PCTrace]):
        super().__init__(traces)
        self.possibleLeaks: Set[int] = set()
        self.buildDataFrames()


    def buildDataFrames(self):
        log.info("not yet imlemented")
