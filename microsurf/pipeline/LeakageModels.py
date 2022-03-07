import numpy as np


def identity(secret):
    return np.array(secret)


def hamming(secret):
    if isinstance(secret, str):
        secret = int(secret)

    return np.array(bin(secret).count("1"))
