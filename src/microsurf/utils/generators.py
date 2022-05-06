import os
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class SecretGenerator:
    def __init__(self, keylen):
        self.keylen = keylen

    def __call__(self, *args, **kwargs) -> str:
        pass

    def getSecret(self) -> int:
        pass

    def __str__(self):
        return f"generated secret key (secret={hex(self.getSecret())})"


class RSAPrivKeyGenerator(SecretGenerator):

    def __init__(self, keylen):
        super().__init__(keylen)

    def __call__(self, *args, **kwargs) -> str:
        self.pkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.keylen
        )
        kbytes = self.pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        tempfile.tempdir = '/tmp'
        keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_key_gen", suffix=".tmpkey")
        with open(keyfile, 'wb') as f:
            f.write(kbytes)
        return keyfile.name

    def getSecret(self) -> int:
        return self.pkey.private_numbers().d


class mbedTLS_hex_key_generator(SecretGenerator):
    def __init__(self, keylen):
        super().__init__(keylen)

    def __call__(self, *args, **kwargs) -> str:
        self.hexstr = f"{int.from_bytes(os.urandom(self.keylen // 8), byteorder='big'):0{self.keylen // 8 * 2}x}"
        return f'hex:{self.hexstr}'

    def getSecret(self) -> int:
        return int(self.hexstr, 16)


class openssl_hex_key_generator(SecretGenerator):
    def __init__(self, keylen):
        super().__init__(keylen)

    def __call__(self, *args, **kwargs) -> str:
        self.hexstr = f"{int.from_bytes(os.urandom(self.keylen // 8), byteorder='big'):0{self.keylen // 8 * 2}x}"
        return self.hexstr

    def getSecret(self) -> int:
        return int(self.hexstr, 16)
