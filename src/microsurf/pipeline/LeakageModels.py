from typing import Any
import numpy as np


def identity(secret) -> Any:
    return np.array(secret)


def hamming(secret) -> Any:
    if isinstance(secret, str):
        # secret decimal
        try:
            secret = int(secret)
        # secret hexadecimal
        except ValueError:
            secret = int(secret, 16)
    return np.array(bin(secret).count("1"))
