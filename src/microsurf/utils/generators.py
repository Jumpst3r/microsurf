import os
import random
import sys


def getRandomHexKeyFunction(keylen: int):
    """get a generator which creates random hexadecimal keys of a given length, using the urandom module.

    Returns:
        A function which generates string representation of the created keys.
    """
    return lambda: _genRandomHexKey(keylen)


def urandom_from_random(rng, length):
    if length == 0:
        return b""
    integer = rng.getrandbits(length * 8)
    result = integer.to_bytes(length, sys.byteorder)
    return result


rnd = random.Random(4)


def _genRandomHexKey(keylen: int) -> str:
    kbytes = keylen // 8
    rbytes = os.urandom(kbytes)
    rbytes = urandom_from_random(rnd, kbytes)
    return f"{int.from_bytes(rbytes, byteorder='big'):0{kbytes * 2}x}"


def genRandInt() -> str:
    """Generates a random integer in [0,300). Useful for testing.

    Returns:
        The string representation of the generated integer.
    """
    return str(random.randint(0, 300))
