
import logging
logger = logging.getLogger(__name__)

import getpass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

MD5_OID = x509.ObjectIdentifier('1.2.840.113549.2.5')
SHA256_OID = x509.ObjectIdentifier('2.16.840.1.101.3.4.2.1')
SHA512_OID = x509.ObjectIdentifier('2.16.840.1.101.3.4.2.3')

def oid2DigestAlgorithm(digestAlgorithm):
    if isinstance(digestAlgorithm, str):
        oid = digestAlgorithm
    elif isinstance(digestAlgorithm, x509.ObjectIdentifier):
        oid = digestAlgorithm.dotted_string
    else:
        oid = digestAlgorithm.algorithm.dotted_string
    if oid == '1.2.840.113549.2.5':
        return hashes.MD5()
    elif oid == '2.16.840.1.101.3.4.2.1':
        return hashes.SHA256()
    elif oid == '2.16.840.1.101.3.4.2.3':
        return hashes.SHA512()
    else:
        raise ValueError('Unknown algorithm %s' % digestAlgorithm)

class SignerEngine:

    def __init__(self, certificates=[]):
        self.padding = padding.PKCS1v15()
        self.digest_algorithm = SHA512_OID
        # self.certificates = certificates
        
    def set_padding(self, padding):
        self.padding = padding

    def set_digest_algorithm(self, digest_algorithm):
        if not isinstance(digest_algorithm, x509.ObjectIdentifier):
            raise TypeError("x509.ObjectIdentifier required, received {}".format(type(digest_algorithm)))

        self.digest_algorithm = digest_algorithm
        
    def sign(self, data):
        raise NotImplementedError

class PrivateKeySignerEngine(SignerEngine):

    def __init__(self, private_key=None, certificates=[]):
        super().__init__()
        self.private_key = private_key
        self.certificates = certificates

    def load_private_key(self, private_key_bytes=None, private_key_path=None):
        if not private_key_bytes:
            if private_key_path:
                private_key_bytes = open(private_key_path, 'rb').read()
            else:
                raise NotImplementedError("Needed data form private_key")
                
        while True:
            password = getpass.getpass('Contraseña para la clave privada: ')
            if len(password):
                password = password.encode('utf8')
            else:
                password = None
            try:
                private_key = serialization.load_pem_private_key(private_key_bytes, password)
                break
            except TypeError:
                sys.stderr.write('La clave privada está protegida por contraseña\n')
            except ValueError:
                sys.stderr.write('La contraseña es incorrecta\n')
            continue

        self.private_key = private_key

    def sign(self, data, padding=None, digest_algorithm=None, preshared=False):
        logger.debug("TBS: {}".format(data))

        if not padding:
            padding = self.padding

        if not digest_algorithm:
            digest_algorithm = self.digest_algorithm

        digest_engine = oid2DigestAlgorithm(digest_algorithm)

        if preshared:
            digest_engine = Prehashed(digest_engine)
        
        result = self.private_key.sign(
            data,
            padding=padding,
            algorithm=digest_engine)
        return result

# Damn, Prehashed takes an argument!!!
# Notes:
# class Prehashed:
#     def __init__(self, algorithm: hashes.HashAlgorithm):
#        if not isinstance(algorithm, hashes.HashAlgorithm):
#             raise TypeError("Expected instance of HashAlgorithm.")
#
#        self._algorithm = algorithm
#        self._digest_size = algorithm.digest_size

#    @property
#    def digest_size(self) -> int:
#        return self._digest_size

# El problema es que ya no se soporta ni MD5 ni SHA1.

# Cómo firmar con clave privada?

# En vault tenemos:

# Note: using hash_algorithm=none requires setting prehashed=true and signature_algorithm=pkcs1v15. This generates a PKCSv1_5_NoOID signature rather than the PKCSv1_5_DERnull signature type usually created. See RFC 3447 Section 9.2.
# En la versión de cryptography que estamos usando aún funcionan
# MD5 y SHA1, aparentemente.

# El problema va a estar entonces en Vault, que ya no hace MD5.
# Bueno, quizá no pase nada.
