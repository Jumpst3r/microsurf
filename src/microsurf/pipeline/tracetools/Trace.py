import numpy as np
import pickle
from collections import defaultdict
from typing import Dict, List, Set
from enum import Enum

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


MARKMEM = dict()


class MemTraceCollection(TraceCollection):
    """Creates a Memory trace collection object.
    The secrets of the individual traces must be random.

    Args:
        traces: List of memory traces
    """

    def __init__(self, traces: list[MemTrace], possibleLeaks=None, granularity=1):
        super().__init__(traces)
        self.secretDepCF = None
        self.possibleLeaks = possibleLeaks
        self.granularity = granularity
        self.results = {}
        self.DF = None
        # if the granularity is coarser than one byte, mask the lower bytes acordingly
        if self.granularity > 1:
            self.maskAddresses()

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
            secrets = []
            numhits = 0
            for trace in self.traces:
                if l not in trace.trace:
                    continue
                entry = []
                secrets.append(trace.secret)
                entry += trace.trace[l]
                numhits = max(numhits, len(trace.trace[l]))
                row.append(entry)
            if not row:
                continue
            maxlen = max([len(i) for i in row])
            nparr = np.zeros((len(row), maxlen), dtype=int)

            for i in range(nparr.shape[0]):
                nparr[i, :len(row[i])] = row[i]
            # building dataframes is expensive. So do some prelim checks with np.
            # skip df creation in it fails
            # The emulator has a quick of marking pop instructions as mem reads, this filters that case:
            if nparr.shape[1] > 800 and len(np.unique(nparr)) <= 2:
                continue
            uniqueRows, indices = np.unique(nparr, axis=0, return_index=True)
            secrets = np.array(secrets)[indices]
            # remove columns with zero variance
            mask = np.std(uniqueRows, axis=0) > 0
            uniqueRows = uniqueRows.T[mask].T
            uniqueRows = np.where(uniqueRows == 0, np.nan, uniqueRows)
            nanmask = ~np.isnan(uniqueRows).any(axis=1)
            uniqueRows = uniqueRows[nanmask]
            secrets = secrets[nanmask]
            if uniqueRows.shape[0] < 3 or uniqueRows.shape[1] < 1:
                continue
            f = pd.DataFrame(uniqueRows)
            f.insert(0, 'secret', secrets)
            perLeakDict[l] = f
        self.DF = perLeakDict
        for k in self.DF.keys():
            self.results[hex(k)] = -1
        self.possibleLeaks = set(self.DF.keys())
        if len(self.possibleLeaks) == 0:
            log.info("Memory Op Anonymity Set:")
            for trace in self.traces:
                log.info(hex(trace.secret))

    def maskAddresses(self):
        mask = 2 ** (4 * (self.granularity - 1)) - 1
        for t in self.traces:
            trace = t.trace
            for k in trace.keys():
                trace[k] = [e ^ (e & mask) for e in trace[k]]


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
        self.trace: List[int] = []

    def add(self, range):
        """Adds an element to the current trace.
        Note that several target memory addresses
        can be added to the same PC by calling the
        function repeatedly.

        Args:
            range: the start / end PC of the instruction block (as a tuple)
        """
        self.trace.append(range)

    def finalize(self):
        self.indexDict = defaultdict(list)
        for idx, e in enumerate(self.trace):
            self.indexDict[e].append(idx)

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
        global MARK
        MARK = dict()  # reset global variable
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
            for t in self.traces:
                entry = []
                if l not in t.indexDict:
                    continue
                else:
                    secrets.append(t.secret)
                indices = t.indexDict[l]

                for i in indices:
                    if i + 1 < len(t):
                        entry.append(t[i + 1])
                numhits = max(numhits, len(entry))
                row.append(entry)
            if not row:
                continue
            maxlen = max(len(r) for r in row)

            if MARK[l] != "secret dep. branch":
                f = pd.DataFrame(row, dtype=object)
                # in the secret dependent hit count case, record the number of hits per secret.
                f = f.count(axis=1).to_frame()
                f.insert(0, "secret", secrets)
            else:
                # building dataframes is expensive. So do some prelim checks with np.
                # skip df creation in it fails
                nparr = np.zeros((len(row), maxlen), dtype=int)
                for i in range(nparr.shape[0]):
                    nparr[i, :len(row[i])] = row[i]
                    # building dataframes is expensive. So do some prelim checks with np.
                    # skip df creation in it fails
                # uniqueRows, indices = np.unique(nparr, axis=0, return_index=True)
                secrets = np.array(secrets)  # [indices]
                # remove columns with zero variance
                uniqueRows = nparr
                mask = np.std(uniqueRows, axis=0) > 0
                uniqueRows = uniqueRows.T[mask].T
                uniqueRows = np.where(uniqueRows == 0, np.nan, uniqueRows)
                nanmask = ~np.isnan(uniqueRows).any(axis=1)
                uniqueRows = uniqueRows[nanmask]
                secrets = secrets[nanmask]
                if uniqueRows.shape[0] < 2 or uniqueRows.shape[1] < 1:
                    continue
                else:
                    f = pd.DataFrame(uniqueRows)
                    f.insert(0, "secret", secrets)
            perLeakDict[l] = f
        self.DF = perLeakDict
        self.possibleLeaks = self.DF.keys()
        if len(self.possibleLeaks) == 0:
            log.info("Control Flow Anonymity Set:")
            for trace in self.traces:
                log.info(hex(trace.secret))
        for k in self.possibleLeaks:
            self.results[hex(k)] = -1

    def find_merge(self, indices):
        length = len(indices)

        # indices = [indices[i] + 1 for i in range(0, length)]

        merge_point = [self.traces[i][indices[i]] for i in range(0, length)]
        potential_index = [indices.copy() for i in range(0, length)]

        class Status(Enum):
            RUNNING = 1
            MERGE_FOUND = 2
            OUT_OF_INDEX = 3

        merge_found = [[Status.RUNNING for _ in range(0, length)] for _ in range(0, length)]

        for i in range(0, length):
            merge_found[i][i] = Status.MERGE_FOUND

        while any(merge_found[i][j] == Status.RUNNING for i in range(0, length) for j in range(0, length)):
            for candidate in range(0, length):
                for other_candidate in range(0, length):
                    # skip combinations that have already been found or out of index
                    if merge_found[candidate][other_candidate] == Status.RUNNING:
                        index = potential_index[candidate][other_candidate]
                        if self.traces[other_candidate][index] == merge_point[candidate]:
                            # found merge
                            merge_found[candidate][other_candidate] = Status.MERGE_FOUND
                        else:
                            # did not yet find merge point
                            # increment index
                            if index + 1 < len(self.traces[other_candidate]):
                                potential_index[candidate][other_candidate] += 1
                            else:
                                merge_found[candidate][other_candidate] = Status.OUT_OF_INDEX
                if all(merge_found[candidate][i] == Status.MERGE_FOUND for i in range(0, length)):
                    # found all merge points
                    if any(self.traces[i][potential_index[candidate][i]] != merge_point[candidate] for i in range(0, length)):
                        print("huh???")
                    return potential_index[candidate]
            
        # raise "Could not find merge point"
        return [len(self.traces[i]) for i in range(0, length)]
        
            

    def find_secret_dep_nodes(self):
        T = defaultdict(lambda: defaultdict(list))
        global MARK

        indices = [0 for _ in range(0, len(self.traces))]
        # print(indices)
        # print([len(self.traces[i]) for i in range(0, len(self.traces))])
        while all(indices[i] < len(self.traces[i]) for i in range(0, len(self.traces))):
            value = self.traces[0][indices[0]]
            if any(self.traces[0][indices[0]-1] != self.traces[i][indices[i]-1] for i in range(0, len(indices))):
                print("\n\n\t\tthis should not happen")
                print(f"{[hex(self.traces[i][indices[i]-1]) for i in range (0, len(indices))]}")
                print(f"{[hex(self.traces[i][indices[i]-0]) for i in range (0, len(indices))]}")
                print("huh3")
            if any(value != self.traces[k][indices[k]] for k in range(0, len(self.traces))):
                MARK[self.traces[0][indices[0]-1]] = "secret dep. branch"
                # Split found
                # looking for merge at this point
                indices = self.find_merge(indices).copy()
                if any(indices[i] >= len(self.traces[i]) for i in range(0, len(indices))):
                    # Reached the end of the trace
                    break
            for i in range(0, len(indices)):
                indices[i] += 1

        return
