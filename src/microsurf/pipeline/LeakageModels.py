import numpy as np


def identity(secret) -> np.array:
    return np.array(secret)


def hamming(secret) -> np.array:
    if isinstance(secret, str):
        # secret decimal
        try:
            secret = int(secret)
        # secret hexadecimal
        except ValueError:
            secret = int(secret, 16)
    return np.array(bin(secret).count("1"))
