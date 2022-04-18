from email.policy import default
import itertools
import pickle
from collections import Counter, defaultdict
from typing import Dict, List, OrderedDict, Set
import cdifflib as dfl
from rich.progress import track
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
        self.trace: List[int] = []
        self.posDict = defaultdict(list)

    def add(self, ip):
        """Adds an element to the current trace.
        Note that several target memory addresses
        can be added to the same PC by calling the
        function repeatedly.

        Args:
            ip: The instruction pointer / PC which caused
            the memory read
        """
        self.trace.append(ip)
        self.posDict[ip].append(len(self.trace) - 1)
    
    def remove(self, keys: List[int]):
        pass

    def __len__(self):
        return len(self.trace)

    def __getitem__(self, item):
         return self.trace[item]


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

    def deterministic(self):
        """Determines whether the traces in the collection
        have identical control flow

        Returns:
            True if all traces have the same CF, False otherwise
        """
        lengths = set([len(t) for t in self.traces])
        if len(lengths) > 1:
            return False
        mat = np.array([list(t.trace.keys()) for t in self.traces], dtype=np.uint64)
        return len(np.unique(mat, axis=0)) == 1

    def getmaxlen(self):
        """Returns the maximal trace length.

        Returns:
            the maximal trace length.
        """
        return max([len(t) for t in self.traces])  
    
    def __len__(self):
        return len(self.traces)

    def __getitem__(self, item):
         return list(self.traces[item].trace.keys())


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
        perLeakDict = {}
        maxlen = self.getmaxlen()
        mat = np.zeros((1,maxlen))

        for t1,t2 in itertools.combinations(self.traces, r=2):
            seq = dfl.CSequenceMatcher(None, t1.trace, t2.trace)
            blocks = list(seq.get_matching_blocks())
            for s1,s2,length in blocks:
                mat[0,s1:s1+length] += 1
                mat[0,s2:s2+length] += 1
        mat[mat == 0] = np.max(mat)
        candidates = np.flatnonzero(mat != np.amax(mat))

        D = defaultdict(int)
        for c, cn in zip(candidates, candidates[1:]):
            print(f"candidate {c}, mat[c]={mat[0,c]}")
            if mat[0,c] != mat[0,cn]:
                for t in self.traces:
                    if c < len(t):
                        D[t[c]] += 1
        self.possibleLeaks = list(D.keys())

        for l in track(self.possibleLeaks, description="analyzing traces"):
            row = []
            hits = []
            maxhit = 0
            for trace in self.traces:
                if l not in trace.posDict: continue
                entry = []
                entry.append(int(trace.secret, 16))
                elist = []
                for a in trace.posDict[l]:
                    try:
                        elist.append(trace[a+1])
                    except IndexError as e:
                        # -1 as a marker for end of prog
                        elist.append(-1)
                entry += elist
                numhits = len(trace.posDict[l])
                hits.append(numhits)
                maxhit = max(maxhit, numhits)
                row.append(entry)
            colnames = ['secret'] + [str(i) for i in range(maxhit)]
            f = pd.DataFrame(row, columns=colnames)
            f = f.set_index('secret')
            f.drop(f.std()[f.std() == 0].index, axis=1, inplace=True)
            if len(f.columns):
                f.insert(loc=0, column='hits', value=hits)
                perLeakDict[l] = f
                perLeakDict[l].dropna(axis=0, inplace=True)
        self.df = perLeakDict
        self.possibleLeaks = list(self.df.keys())
        log.info(f"Identified {len(self.df)} leaks")

