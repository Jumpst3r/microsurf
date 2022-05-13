import pickle
from collections import defaultdict
from typing import Dict, List, Set, Tuple

import pandas as pd
from rich.progress import track

from microsurf.utils.logger import getConsole, getLogger

log = getLogger()
console = getConsole()


class Trace:
    def __init__(self, secret) -> None:
        self.secret = secret
        self.trace = None

    def add(self, *args):
        pass

    def __getitem__(self, item):
        pass


class TraceCollection:
    def __init__(self, traces: list[Trace]):
        self.traces = traces
        self.possibleLeaks: set[int] = set()

    def toDisk(self, path: str):
        with open(path, "wb") as f:
            pickle.dump(self, f)

    def __len__(self):
        return len(self.traces)

    def __getitem__(self, item):
        return self.traces[item]


class MemTrace(Trace):
    """Represents a single Memory Trace object.

    Initialized with a secret, trace items are then
    added by calling the .add(ip, memaddr) method.

    Args:
        secret: The secret that was used when the trace
        was recorded.
    """

    def __init__(self, secret) -> None:
        super().__init__(secret)
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

    def __getitem__(self, item):
        return self.trace[item]


class MemTraceCollection(TraceCollection):
    """Creates a Memory trace collection object.
    The secrets of the individual traces must be random.

    Args:
        traces: List of memory traces
    """

    def __init__(self, traces: list[MemTrace], possibleLeaks=None):
        super().__init__(traces)
        self.secretDepCF = None
        self.possibleLeaks = possibleLeaks
        self.results = {}
        self.DF = None
        self.buildDataFrames()

    def buildDataFrames(self):
        """Build a dictionary of dataframes, indexed by leak adress.
        T[leakAddr] = df with rows indexing the executions and columns the addresses accessed.
        The first column contains the secret.
        """
        perLeakDict = {}
        addrs = [list(a.trace.keys()) for a in self.traces]
        addrs = set([i for l in addrs for i in l])  # flatten
        log.debug(f"recorded {len(addrs)} distinct IPs making memory reads")
        for l in track(addrs, description="analyzing memory read traces"):
            row = []
            numhits = 0
            for trace in self.traces:
                if l not in trace.trace:
                    continue
                entry = [trace.secret]
                entry += trace.trace[l]
                numhits = max(numhits, len(trace.trace[l]))
                row.append(entry)
            cols = [str(i) for i in range(numhits)]
            colnames = ["secret"] + cols
            f = pd.DataFrame(row, columns=colnames, dtype=object)
            ffilter_stdev = f.loc[:, f.columns != 'secret'].std()
            f.drop(ffilter_stdev[ffilter_stdev == 0].index, axis=1, inplace=True)
            f.dropna(axis=0, inplace=True)
            if len(f.columns) > 1 and len(f.index) > 1:
                perLeakDict[l] = f
        self.DF = perLeakDict
        for k in self.DF.keys():
            self.results[hex(k)] = -1
        self.possibleLeaks = set(self.DF.keys())


class PCTrace(Trace):
    """Represents a single Program Counter (PC) Trace object.

    Initialized with a secret, trace items are then
    added by calling the .add(ip) method.

    Args:
        secret: The secret that was used when the trace
        was recorded.
    """

    def __init__(self, secret) -> None:
        super().__init__(secret)
        self.trace: List[Tuple[int, int]] = []

    def add(self, range):
        """Adds an element to the current trace.
        Note that several target memory addresses
        can be added to the same PC by calling the
        function repeatedly.

        Args:
            range: the start / end PC of the instruction block (as a tuple)
        """
        self.trace.append(range)

    def __len__(self):
        return len(self.trace)

    def __getitem__(self, item):
        return self.trace[item]


MARK = dict()


class PCTraceCollection(TraceCollection):
    """Creates a PC trace collection object.
    The secrets of the individual traces must be random.

    Args:
        traces: List of memory traces
    """

    def __init__(self, traces: list[PCTrace], possibleLeaks=None, flagVariableHitCount=False):
        super().__init__(traces)
        self.flagVariableHitCount = flagVariableHitCount
        self.results = {}
        if possibleLeaks:
            self.possibleLeaks = possibleLeaks
        else:
            self.possibleLeaks: Set[int] = set()
        self.DF = None
        if not self.possibleLeaks:
            self.find_secret_dep_nodes()
        self.buildDataFrames()

    def buildDataFrames(self):
        global MARK
        if not self.possibleLeaks:
            self.possibleLeaks = []
            for k in MARK:
                self.possibleLeaks.append(k)
        perLeakDict = {}
        for l in track(self.possibleLeaks, description="analyzing PC traces"):
            row = []
            numhits = 0
            secrets = []
            skipcolcheck = False
            for t in self.traces:
                secrets.append(t.secret)
                entry = [t.secret]
                for idx, e in enumerate(t):
                    if e == l:
                        if idx + 1 < len(t):
                            entry.append(t[idx + 1])
                numhits = max(numhits, len(entry) - 1)
                row.append(entry)
            colnames = ["secret"] + [str(i) for i in range(numhits)]
            f = pd.DataFrame(row, columns=colnames, dtype=object)
            if MARK[l] != "secret dep. branch":
                # in the secret dependent hit count case, record the number of hits per secret.
                f = f.loc[:, f.columns != 'secret'].count(axis=1).to_frame()
                f.insert(0, "secret", secrets)
                skipcolcheck = True
            ffilter_stdev = f.loc[:, f.columns != 'secret'].std()
            f.drop(ffilter_stdev[ffilter_stdev == 0].index, axis=1, inplace=True)
            f.dropna(axis=0, inplace=True)
            if (len(f.columns) > 1 or skipcolcheck) and len(f.index) > 1:
                perLeakDict[l] = f
        self.DF = perLeakDict
        self.possibleLeaks = self.DF.keys()
        for k in self.possibleLeaks:
            self.results[hex(k)] = -1

    def find_secret_dep_nodes(self):
        T = defaultdict(lambda: defaultdict(list))
        global MARK

        for t in self.traces:
            for idx, v in enumerate(t):
                if idx + 1 < len(t):
                    T[v][t].append(t[idx + 1])
        for k, v in T.items():
            normVec = list(v.values())[0]
            for vec in v.values():
                if len(vec) == len(normVec):
                    if normVec and vec != normVec:
                        MARK[k] = "secret dep. branch"
                else:
                    a = normVec if len(normVec) < len(vec) else vec
                    b = normVec if len(normVec) > len(vec) else vec
                    if b[: len(a)] == a:
                        if self.flagVariableHitCount:
                            MARK[k] = "secret dep. hit count"
        return
