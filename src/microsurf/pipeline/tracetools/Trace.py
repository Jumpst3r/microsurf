import itertools

import networkx as nx
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

    def add(self, *args):
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
    """A generic MemoryTraceCollection object.

    Args:
        traces: The traces that make up the collection.
    """

    def __init__(self, traces: list[MemTrace]):
        super().__init__(traces)


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
        self.secretDepCF = None
        self.possibleLeaks: Set[int] = set()
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
        for l in track(addrs, description="analyzing traces"):
            row = []
            hits = []
            numhits = 0
            for trace in self.traces:
                if l not in trace.trace:
                    continue
                entry = [int(trace.secret, 16)]
                entry += trace.trace[l]
                numhits = max(numhits, len(trace.trace[l]))
                hits.append(len(trace.trace[l]))
                row.append(entry)
            colnames = ["secret"] + [str(i) for i in range(numhits)]
            f = pd.DataFrame(row, columns=colnames)
            f = f.set_index("secret")
            f.drop(f.std()[f.std() == 0].index, axis=1, inplace=True)
            if len(f.columns):
                f.insert(loc=0, column="hits", value=hits)
                perLeakDict[l] = f
                perLeakDict[l].dropna(axis=0, inplace=True)
        self.DF = perLeakDict
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
        self.trace: List[Tuple[int,int]] = []

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


class PCTraceCollection(TraceCollection):
    """A generic PCTraceCollection object.

    Args:
        traces: The traces that make up the collection.
    """

    def __init__(self, traces: list[PCTrace]):
        super().__init__(traces)

    def toDisk(self, path: str):
        with open(path, "wb") as f:
            pickle.dump(self, f)

    def __len__(self):
        return len(self.traces)

    def __getitem__(self, item):
        return list(self.traces[item].trace)


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

    def __init__(self, traces: list[PCTrace], possibleLeaks=None):
        super().__init__(traces)
        self.possibleLeaks: Set[int] = set()
        self.DF = None
        self.possibleLeaks = possibleLeaks
        self.buildCFGraph()
        self.buildDataFrames()

    def buildDataFrames(self):
        marked = nx.get_node_attributes(self.G, 'color')
        for v in self.G.nodes:
            if v in marked:
                log.info(v[1])

    def buildCFGraph(self):
        G = nx.MultiDiGraph()

        edgecolors = ['black', 'red', 'beige', 'orange', 'blue']
        for idx, t in enumerate(self.traces):
            for i in range(len(t)-1):
                # hex for debugging and greping offsets, change later
                G.add_edge((hex(t[i][0]), hex(t[i][1])), (hex(t[i+1][0]), hex(t[i+1][1])), secret=t.secret ,color=edgecolors[idx])
        for v in G.nodes:
            hitcount = defaultdict(lambda: defaultdict(int))
            for (_,tgt,di) in G.out_edges(nbunch=v, data=True):
                hitcount[tgt][di['secret']] += 1
            # more than one target node
            if len(hitcount.keys()) > 1:
                # C1: do the target nodes have differing secret sets ?
                secretSets = ((frozenset(l for l in list(hitcount[x].keys())) for x in hitcount))
                secretSets = set(secretSets)
                # C2: if they have the same secrets, do all targets have the same secret ?
                hitSets = ((frozenset(l for l in list(hitcount[x].values())) for x in hitcount))
                hitSets = set(hitSets)

                if len(hitSets) > 1 or len(secretSets) > 1:
                    # mark block as possibly secret dep.
                    G.nodes[v]['color'] = 'red'

        self.G = G
        nx.nx_pydot.write_dot(G, 'graph.dot')

