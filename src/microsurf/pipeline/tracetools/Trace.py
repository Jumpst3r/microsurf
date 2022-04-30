import itertools

import networkx as nx
import pickle
from collections import defaultdict, Counter
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
        for l in track(addrs, description="building dataframe"):
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
        if possibleLeaks:
            self.possibleLeaks = possibleLeaks
        else:
            self.possibleLeaks: Set[int] = set()
        self.DF = None
        if not self.possibleLeaks:
            self.buildCFGraph()
        self.buildDataFrames()

    def buildDataFrames(self):
        if not self.possibleLeaks:
            marked = nx.get_node_attributes(self.G, 'color')
            self.possibleLeaks = []
            for v in self.G.nodes:
                if v in marked and marked[v] == 'red':
                    self.possibleLeaks.append(v)
                    log.info(f"preliminary: {v[1]}")

        perLeakDict = {}
        for l in self.possibleLeaks:
            row = []
            hits = []
            numhits = 0
            for t in self.traces:
                entry = [int(t.secret, 16)]
                for idx, e in enumerate(t):
                    e = (hex(e[0]), hex(e[1]))
                    if e == l:
                        if idx+1 < len(t):
                            entry.append(t[idx+1][0])
                numhits = max(numhits, len(entry) - 1)
                hits.append(1)
                row.append(entry)
            colnames = ["secret"] + [str(i) for i in range(numhits)]
            f = pd.DataFrame(row, columns=colnames)
            f = f.set_index("secret")
            f.drop(f.std()[f.std() == 0].index, axis=1, inplace=True)
            if len(f.columns):
                f.insert(loc=0, column="hits", value=hits)
                perLeakDict[int(l[1], 16)] = f
                perLeakDict[int(l[1], 16)].dropna(axis=0, inplace=True)
        self.DF = perLeakDict



    def buildCFGraph(self):
        G = nx.MultiDiGraph()
        edgecolors = ['black', 'red', 'blue', 'orange']
        self.colordict = {}
        for idx, t in enumerate(self.traces):
            for i in range(len(t)-1):
                # hex for debugging and greping offsets, change later
                u = (hex(t[i][0]), hex(t[i][1]))
                v = (hex(t[i+1][0]), hex(t[i+1][1]))
                out = G.out_edges(nbunch=u, data=True)
                addedge = True
                for e in out:
                    src, tgt, di = e
                    if tgt == v and di['secret'] == t.secret:
                        di['count'] += 1
                        addedge=False
                if addedge:
                    G.add_edge(u,v, secret=t.secret ,color=edgecolors[idx], count=0)
                    self.colordict[t.secret] = edgecolors[idx]
        log.debug(f"CF graph before pruning: {nx.info(G)}")
        self._remove_consistent_loops(G)
        #self._contract_nodes(G, self.traces[0])
        log.debug(f"CF graph after pruning: {nx.info(G)}")
        # remove self loops with consistent iteration count for every secret
        # contract edges which link two linear blocks [b1]->[b2]
        for v in track(G.nodes, description="analyzing control flow graph"):
            self._check_self_loops(G, v)
            self._check_state(G, v)
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
        for (src, tgt, di) in G.out_edges(nbunch=block_c, data=True):
            if tgt != src:
                outgoing_edges.append((tgt, di))
                tgtnodes[tgt][di['secret']] = di['count']
        keysetglobal = set()
        for t,v in tgtnodes.items():
            keyset = set()
            for secret, count in v.items():
                keyset.add(secret)
            keysetglobal.add(frozenset(keyset))
        log.info(f'{keysetglobal} - len = {len(keysetglobal)}')
        if len(keysetglobal) > 1:
            G.nodes[block_c]['color'] = 'red'
        return

    def _contract_nodes(self, G, t):
        to_contract = [[]]
        for i in range(len(t) - 1):
            v = (hex(t[i][0]), hex(t[i][1]))
            if v not in G.nodes: continue
            if len(list(G.neighbors(v))) > 1:
                continue
            elif len(list(G.neighbors(v))) == 1:
                isrc = None
                for src, dst in G.in_edges(nbunch=v):
                    isrc = src
                    break
                if not isrc:
                    continue
                if not to_contract[-1] or isrc in to_contract[-1][-1]:
                    to_contract[-1].append((isrc,v))
                else:
                    to_contract.append([(isrc,v)])

        to_contract_clean = []
        for e in to_contract:
            row = []
            for s in e:
                for x in s:
                    if x not in row: row.append(x)
            to_contract_clean.append(row)
        for e in to_contract_clean:
            for endofchain in range(1, len(e)):
                try:
                    nx.contracted_nodes(G, e[0],  e[endofchain], self_loops=False, copy=False)
                except Exception:
                    break
        if e[0] in G.nodes:
            # clean up any duplicate edges caused by node contractions
            edges = defaultdict(int)
            if len(list(G.neighbors(e[0]))) == 1:
                neigbour = list(G.neighbors(e[0]))[0]
                oedges = list(G.out_edges(nbunch=e[0], data=True))
                for e in oedges[:]:
                    src,tgt,di = e
                    edges[di['secret']] += 1
                    G.remove_edge(src, tgt)
                    print('removed edges')
                for k in edges:
                    G.add_edge(e[0], neigbour, secret=k, count=edges[k], color=self.colordict[k])



    def _remove_consistent_loops(self, G):
        for v in G.nodes:
            secrets = []
            selfloops = []
            outgoing_edges = G.out_edges(nbunch=v, data=True)
            for src,tgt,di in outgoing_edges:
                if tgt == src:
                    secrets.append(di['secret'])
                    selfloops.append((src,tgt))
            if len(set(Counter(secrets).values())) == 1:
                for edge in selfloops:
                    G.remove_edge(*edge)

