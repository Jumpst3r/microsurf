import os
import tempfile
from xmlrpc.client import boolean

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

from microsurf.utils.logger import getLogger

log = getLogger()


class SecretGenerator:
    """
    Template class used to implement custom secret generators.

    Args:
        keylen: Length of the key.
        asFile: Whether the class implements an on-disk generator.
    """
    def __init__(self, keylen: int, asFile: boolean):
        self.keylen = keylen
        self.asFile = asFile

    
    def __call__(self, *args, **kwargs) -> str:
        """
        The __call__ function defines the behavior implemented when calling the secret generator.
        This function must create a fresh secret every time it is called

        returns:
            A string representation of the secret: path to file for on-disk secret or encoded secret.
        """    
        pass

    def getSecret(self) -> int:
        """
        Returns a numerical representation of the secret. The key-bit dependency analysis will be performed on the return value of this function.
        """
        pass

    """
    String representation of the secret for debugging purposes.
    """ 
    def __str__(self) -> str:
        return f"generated secret key (secret={hex(self.getSecret())})"

class RSAPrivKeyGenerator(SecretGenerator):
    """
    Generates RSA privat keys with PEM encoding, PKCS8 and no encryption. The key are written to disk (`/tmp/microsurf_key_gen_**.key`).
    
        Args:
            keylen: The length of the private key in bits.
    """
    def __init__(self, keylen:int):
        # we pass asFile=True because our secrets are loaded from disk (RSA priv key)
        super().__init__(keylen, asFile=True)

    def __call__(self, *args, **kwargs):
        self.pkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.keylen
        )
        kbytes = self.pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        tempfile.tempdir = '/tmp'
        keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_key_gen", suffix=".key").name
        with open(keyfile, 'wb') as f:
            f.write(kbytes)
        return keyfile

    def getSecret(self) -> int:
        return self.pkey.private_numbers().p


class DSAPrivateKeyGenerator(SecretGenerator):
    """
    Generates DSA privat keys with PEM encoding, PKCS8 and no encryption. The key are written to disk (`/tmp/microsurf_key_gen_**.key`).
        
        Args:
            keylen: The length of the private key in bits.
    """
    def __init__(self, keylen:int):
        super().__init__(keylen, asFile=True)

    def __call__(self, *args, **kwargs) -> str:
        self.pkey = dsa.generate_private_key(self.keylen)
        kbytes = self.pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        tempfile.tempdir = '/tmp'
        keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_key_gen", suffix=".key").name
        with open(keyfile, 'wb') as f:
            f.write(kbytes)
        return keyfile

    def getSecret(self) -> int:
        return self.pkey.private_numbers().x

class ECDSAPrivateKeyGenerator(SecretGenerator):
    """
    Generates ECDSA privat keys with PEM encoding, PKCS8 and no encryption (SECP256K1). The key are written to disk (`/tmp/microsurf_key_gen_**.key`).
        
        Args:
            keylen: The length of the private key in bits.
    """
    def __init__(self, keylen:int):
        super().__init__(keylen, asFile=True)

    def __call__(self, *args, **kwargs) -> str:
        self.pkey =  ec.generate_private_key(ec.SECP256K1())
        kbytes = self.pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        tempfile.tempdir = '/tmp'
        keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_key_gen", suffix=".key").name
        with open(keyfile, 'wb') as f:
            f.write(kbytes)
        return keyfile

    def getSecret(self) -> int:
        return self.pkey.private_numbers().private_value


class hex_key_generator(SecretGenerator):
    """
    Generates a hexadecimal secret string. Not saved to file (directly substituted in the argument list).

        Args:
            keylen: The length of the key in bits.
    """
    def __init__(self, keylen:int):
        super().__init__(keylen, asFile=False)

    def __call__(self, *args, **kwargs) -> str:
        self.hexstr = f"{int.from_bytes(os.urandom(self.keylen // 8), byteorder='big'):0{self.keylen // 8 * 2}x}"
        return self.hexstr

    def getSecret(self) -> int:
        return int(self.hexstr, 16)


class hex_file(SecretGenerator):
    """
    Generates a binary file. Good for use when evaluating constant time proprieties of hashing functions.

        Args:
            keylen: The length of the file in bits.
    """
    def __init__(self, keylen:int):
        super().__init__(keylen, asFile=True)

    def __call__(self, *args, **kwargs) -> str:
        self.hexstr = f"{int.from_bytes(os.urandom(self.keylen // 8), byteorder='big'):0{self.keylen // 8 * 2}x}"
        keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_input_gen", suffix=".input").name
        with open(keyfile, 'w') as f:
            f.writelines(self.hexstr)
        return keyfile

    def getSecret(self) -> int:
        return int(self.hexstr, 16)
