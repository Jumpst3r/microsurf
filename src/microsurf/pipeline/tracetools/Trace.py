import pickle
from typing import Dict, List, Set
from collections import defaultdict
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

    def prune(self) -> None:
        """Automatically prunes the trace collection:
        Iterates pairwise over all traces, if they have differing secrets but
        the same list of memory accesses for a given PC, remove the PC from both traces.

        Calling .prune() populates the field .possibleLeaks which contains:
        Every PC for which different secrets resulted in different memory accesses.
        Note that these may not automatically be directly secret dependent and may
        be due to inherent non-determinism.

        """
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
        for idx, t in enumerate(self.traces):
            for leak in self.possibleLeaks:
                if len(t.trace[leak]) == 0:
                    t.trace.pop(leak)
