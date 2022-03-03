"""
Hijacks common sources of entropy in order to force determinism.
Deterministic execution makes side channel trace analysis easier but possibly reduces coverage.
TODO Add tests to check how well this works on different platforms !
"""

from qiling.os.mapper import QlFsMappedObject
from utils.logger import getLogger

log = getLogger()

"""
Possible sources of randomness in on most unix like systems:
- /dev/urandom
- /dev/random
- /dev/arandom
"""


class device_random(QlFsMappedObject):
    def read(self, size):
        return b"\xAA"

    def fstat(self):
        return -1

    def close(self):
        return 0
