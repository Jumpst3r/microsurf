import numpy as np


class identity:
    def __call__(self, secret) -> np.ndarray:
        if isinstance(secret, str):
            try:
                secret = int(secret)
            except ValueError:
                secret = int(secret, 16)
        return np.array(secret)

    def __str__(self):
        return "identity"


class hamming:
    def __call__(self, secret) -> np.ndarray:
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
            return np.array(bin(secret)[2:].count("1"))

    def __str__(self):
        return "hamming"


class bitval:
    def __init__(self, pos) -> None:

        self.pos = pos

    def __call__(self, secret) -> np.ndarray:
        """Return the value of the nth bit (LSB)

        Args:
            secret: A base 16 string representation
                of the secret

        Returns:
            a numpy array containing the value of the nth bit.
        """
        if isinstance(secret, str) or isinstance(secret, int):
            try:
                return np.array(bin(secret)[2:][::-1][self.pos])
            except IndexError as e:
                return 0
            except TypeError:
                return np.array(bin(int(secret, 16))[2:][::-1][self.pos])

    def __str__(self):
        return f"{self.pos}-th bit value"


def getCryptoModels(keylen=0):
    basemodels = [identity(), hamming()]
    if keylen:
        return basemodels + [bitval(i) for i in range(keylen)]
    return basemodels


CRYPTO_MODELS = [identity(), hamming()]
