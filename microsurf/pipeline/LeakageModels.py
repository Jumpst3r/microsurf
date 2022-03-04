import numpy as np


def identity(secret):
    return np.array(secret)


def hamming(secret):
    return np.array(bin(secret).count("1"))
