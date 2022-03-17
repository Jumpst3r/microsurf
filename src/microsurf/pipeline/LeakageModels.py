from typing import Any
import numpy as np


def identity(secret) -> np.ndarray:
    if isinstance(secret, str):
        try:
            secret = int(secret)
        except ValueError:
            secret = int(secret, 16)
    return np.array(secret)


def hamming(secret: str) -> np.ndarray:
    """Computes the hamming distance of the secret

    Args:
        secret: A base 10 or base 16 string representation
            of the secret

    Returns:
        a numpy array containing the hamming distance
        of the secret.
    """
    if isinstance(secret, str):
        # secret decimal
        try:
            secret = int(secret)
        # secret hexadecimal
        except ValueError:
            secret = int(secret, 16)
    return np.array(bin(secret).count("1"))
