import os
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa

from microsurf.utils.logger import getLogger

log = getLogger()


class SecretGenerator:
    def __init__(self, keylen, asFile):
        self.keylen = keylen
        self.asFile = asFile

    def __call__(self, *args, **kwargs) -> str:
        pass

    def getSecret(self) -> int:
        pass

    def __str__(self):
        return f"generated secret key (secret={hex(self.getSecret())})"

class RSAPrivKeyGenerator(SecretGenerator):

    def __init__(self, keylen):
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
        keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_key_gen", suffix=".der").name
        with open(keyfile, 'wb') as f:
            f.write(kbytes)
        return keyfile

    def getSecret(self) -> int:
        return self.pkey.private_numbers().p


class bearSSL_RSAPrivKeyGenerator(SecretGenerator):

    def __init__(self, keylen):
        # the beartls driver expects 1024 bit keys, passed as hex arguments:
        # ./test_rsa p q dp dq iq
        assert keylen == 1024
        super().__init__(keylen, asFile=False)

    def __call__(self, *args, **kwargs):
        self.pkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.keylen
        )
        args = f"{hex(self.pkey.private_numbers().p)[2:]} " \
               f"{hex(self.pkey.private_numbers().q)[2:]} " \
               f"{hex(self.pkey.private_numbers().dmp1)[2:]} " \
               f"{hex(self.pkey.private_numbers().dmq1)[2:]} " \
               f"{hex(self.pkey.private_numbers().iqmp)[2:]}".split(' ')

        return args

    def getSecret(self) -> int:
        return self.pkey.private_numbers().q


class mbedTLS_hex_key_generator(SecretGenerator):
    # we pass asFile=True because our secrets are directly included as command line arguments (hex strings)
    def __init__(self, keylen):
        super().__init__(keylen, asFile=False)

    def __call__(self, *args, **kwargs) -> str:
        self.hexstr = f"{int.from_bytes(os.urandom(self.keylen // 8), byteorder='big'):0{self.keylen // 8 * 2}x}"
        return f'hex:{self.hexstr}'

    def getSecret(self) -> int:
        return int(self.hexstr, 16)


class dsa_privkey_generator(SecretGenerator):
    # we pass asFile=True because our secrets are directly included as command line arguments (hex strings)
    def __init__(self, keylen):
        super().__init__(keylen, asFile=True)

    def __call__(self, *args, **kwargs) -> str:
        self.pkey = dsa.generate_private_key(self.keylen)
        kbytes = self.pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        tempfile.tempdir = '/tmp'
        keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_key_gen", suffix=".tmpkey").name
        with open(keyfile, 'wb') as f:
            f.write(kbytes)
        return keyfile

    def getSecret(self) -> int:
        return self.pkey.private_numbers().x


class hex_key_generator(SecretGenerator):
    # we pass asFile=True because our secrets are directly included as command line arguments (hex strings)
    def __init__(self, keylen):
        super().__init__(keylen, asFile=False)

    def __call__(self, *args, **kwargs) -> str:
        self.hexstr = f"{int.from_bytes(os.urandom(self.keylen // 8), byteorder='big'):0{self.keylen // 8 * 2}x}"
        return self.hexstr

    def getSecret(self) -> int:
        return int(self.hexstr, 16)


# define an input file to hash.
class hex_file(SecretGenerator):
    def __init__(self, keylen):
        super().__init__(keylen, asFile=True)

    def __call__(self, *args, **kwargs) -> str:
        self.hexstr = f"{int.from_bytes(os.urandom(self.keylen // 8), byteorder='big'):0{self.keylen // 8 * 2}x}"
        keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_input_gen", suffix=".input").name
        with open(keyfile, 'w') as f:
            f.writelines(self.hexstr)
        return keyfile

    def getSecret(self) -> int:
        # returns the secret as an integer
        return int(self.hexstr, 16)
