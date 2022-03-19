import os
import random

def getRandomHexKeyFunction(keylen: int):
    """get a generator which creates random hexadecimal keys of a given length, using the urandom module.

    Returns:
        A function which generates string representation of the created keys.
    """
    return lambda : _genRandomHexKey(keylen)

def _genRandomHexKey(keylen: int) -> str:
    kbytes = keylen // 8
    rbytes = os.urandom(kbytes)
    return f"{int.from_bytes(rbytes, byteorder='big'):x}"

def genRandInt() -> str:
    """Generates a random integer in [0,300). Useful for testing.

    Returns:
        The string representation of the generated integer.
    """
    return str(random.randint(0,300))