from typing import Any
import numpy as np


class identity:
    def __call__ (self, secret) -> np.ndarray:
        if isinstance(secret, str):
            try:
                secret = int(secret)
            except ValueError:
                secret = int(secret, 16)
        return np.array(secret)

    def __str__ (self):
        return 'Identity'


class hamming:
    def __call__ (self, secret) -> np.ndarray:
        """Computes the hamming distance of the secret

        Args:
            secret: A base 10 or base 16 string representation
                of the secret

        Returns:
            a numpy array containing the hamming distance
            of the secret.
        """
        if isinstance(secret, str) or isinstance(secret, int):
            # secret decimal
            try:
                secret = int(secret)
            # secret hexadecimal
            except ValueError:
                secret = int(secret, 16)
            return np.array(bin(secret).count("1"))

    def __str__ (self):
        return 'Hamming'    

CRYPTO_MODELS = [identity(), hamming()]