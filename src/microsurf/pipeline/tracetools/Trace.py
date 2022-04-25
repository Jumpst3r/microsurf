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
        self.buildCFGraph()
        self.buildDataFrames()

    def buildDataFrames(self):
        marked = nx.get_node_attributes(self.G, 'color')
        self.possibleLeaks = []
        self.res = {}
        for v in self.G.nodes:
            if v in marked and marked[v] == 'red':
                self.possibleLeaks.append(v)
                self.res[v[1]] = (1,0,0)
        log.error(len(self.possibleLeaks))
        for (_,e) in self.possibleLeaks:
            log.error(e)
        exit()


    def buildCFGraph(self):
        G = nx.MultiDiGraph()

        edgecolors = ['black', 'red', 'blue', 'orange']
        for idx, t in enumerate(self.traces):
            for i in range(len(t)-1):
                # hex for debugging and greping offsets, change later
                G.add_edge((hex(t[i][0]), hex(t[i][1])), (hex(t[i+1][0]), hex(t[i+1][1])), secret=t.secret ,color=edgecolors[idx])

        nx.set_node_attributes(G, 0, 'visited')
        for idx, trace in enumerate(self.traces):
            for id, t in enumerate(trace):
                block_c = (hex(t[0]), hex(t[1]))
                G.nodes[block_c]['visited'] = 1
                self._check_self_loops(G, block_c)
                self._check_state(G, block_c)

        self.G = G
        nx.nx_pydot.write_dot(G, 'graph.dot')

    def _check_self_loops(self, G, block_c):
        if block_c[0] == block_c[1]: return
        loops = defaultdict(int)
        for (_, tgt, di) in G.out_edges(nbunch=block_c, data=True):
            if tgt == block_c:
                loops[di['secret']] += 1
        if loops:
            hitSets = (frozenset(l for l in list(loops.values())))
            if len(hitSets) > 1:
                G.nodes[block_c]['color'] = 'orange'
                # log.error("SDCF")

    def _check_state(self, G, block_c):
        if block_c[0] == block_c[1]: return
        outgoing_edges = []
        incomming_edges = []
        # ignore loops
        tgtnodes = defaultdict(lambda: defaultdict(int))
        for (_, tgt, di) in G.out_edges(nbunch=block_c, data=True):
            if tgt != block_c:
                outgoing_edges.append((tgt, di))
                tgtnodes[tgt][di['secret']] = 1
        keysetglobal = set()
        for t,v in tgtnodes.items():
            keyset = set()
            for secret in v:
                keyset.add(secret)
            keysetglobal.add(frozenset(keyset))
        if len(keysetglobal) > 1:
            G.nodes[block_c]['color'] = 'red'

        for (src, _, di) in G.in_edges(nbunch=block_c, data=True):
            if src != block_c:
                incomming_edges.append((src, di))

        # any outgoing edges to previously visited nodes ?
        for (tgt, di) in outgoing_edges[:]:
            if G.nodes[tgt]['visited']:
                edgepruned = False
                # pop an incomming edge of the same secret:
                # (provided it was visited)

                for src, d in incomming_edges[:]:
                    if d['secret'] == di['secret'] and G.nodes[src]['visited']:
                        try:
                            incomming_edges.remove((src,d))
                            edgepruned = True
                        except ValueError:
                            pass
                        break
                if edgepruned:
                    # pop this outgoing edge:
                    outgoing_edges.remove((tgt, di))

        # check that all remaining incomming secrets are routed equally:
        if incomming_edges and outgoing_edges:
            assert len(incomming_edges) == len(outgoing_edges)
            tgset = set()
            hitcount = defaultdict(lambda: defaultdict(int))
            for (tgt, di) in outgoing_edges:
                tgset.add(tgt)
                hitcount[tgt][di['secret']] += 1
            if len(tgset) > 1:
                anomaly = False
                keysetglobal = set()
                for _,v in hitcount.items():
                    keyset = set()
                    count = -1
                    for k2,v2 in v.items():
                        keyset.add(k2)
                        if count == -1:
                            count = v2
                        elif count != v2:
                            anomaly = True
                    keysetglobal.add(frozenset(keyset))
                if anomaly or len(keysetglobal) > 1:
                    G.nodes[block_c]['color'] = 'red'

