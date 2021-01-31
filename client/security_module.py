import os
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from cryptography import x509
from cryptography.x509.oid import NameOID


#import PyKCS11

CHACHA20 = "ChaCha20"
AES128 = "AES-128"
TRIDES = "3DES"

ECB = "ECB"
CBC = "CBC"
GCM = "GCM"

SHA256 = "SHA256"
SHA512 = "SHA512"
BLAKE2 = "BLAKE2"


class Criptography:

    def __init__(self):
        self._ciphers = {CHACHA20: {"block_cipher": False, "ks": 32, "bs": None, "modes": []},
            AES128: {"block_cipher": True, "ks": 16, "bs": 16, "modes": [ECB, CBC, GCM]},
            TRIDES: {"block_cipher": True, "ks": 8, "bs": 8, "modes": [ECB, CBC]}}

    @property
    def cipher_suite(self):
        return self._ciphers

    @property
    def modes(self):
        return [ECB, CBC, GCM]

    @property
    def digest_algorithms(self):
        return [SHA256, SHA512, BLAKE2]

    @property
    def ciphers(self):
        return list(self._ciphers.keys())

    def supported_ciphers(self, algorithm):
        if not algorithm in self.ciphers:
            raise Exception(f"Cipher Algorithm {algorithm} not supported")

    def supported_modes(self, algorithm, mode):
        self.supported_ciphers(algorithm)
        modes = self._ciphers[algorithm]["modes"]
        if modes != []:
            if mode == "None":
                raise Exception("No mode was provided")
            if not mode in modes:
                raise Exception(f"Mode {mode} isn't supported by the algorithm {algorithm}")
    
    def supported_digest_algorithms(self, digest_algorithm):
        if not digest_algorithm in self.digest_algorithms:
            raise Exception(f"Hash Algorithm {digest_algorithm} not found")

    def get_key(self, key, algorithm):
        ks = self._ciphers[algorithm]["ks"]
        return key[:ks]

    def get_mode(self, mode, algorithm, encrypt=True, parameters=None):
        self.supported_modes(algorithm, mode)
        if mode == ECB:
            return modes.ECB(), None
        elif mode == CBC:
            if encrypt:
                iv = os.urandom(self._ciphers[algorithm]["bs"])
            else:
                if parameters == None or parameters[0] == None:
                    raise Exception("No IV was provided for the CBC mode")
                iv = parameters[0]
            return modes.CBC(iv), iv
        elif mode == GCM:
            if encrypt:
                iv = os.urandom(12)
                return modes.GCM(iv), iv
            else:
                if parameters == None or parameters[0] == None or parameters[1] == None:
                    raise Exception("No IV or Tag was provided for the GCM mode")
                iv, tag = parameters
                return modes.GCM(iv, tag), parameters
        elif mode == "None":
            return None, None

    def get_algorithm(self, algorithm, mode, key, encrypt=True, parameter=None):
        self.supported_modes(algorithm, mode)
        
        key = self.get_key(key, algorithm)
        if algorithm == AES128:
            return algorithms.AES(key), None
        elif algorithm == TRIDES:
            return algorithms.TripleDES(key), None
        elif algorithm == CHACHA20:
            if encrypt:
                nonce = os.urandom(16)
            else:
                if parameter == None:
                    raise Exception("No Nonce was provided for ChaCha20")
                nonce = parameter           
            return algorithms.ChaCha20(key, nonce), nonce

    def get_digest(self, hash_algorithm):
        self.supported_digest_algorithms(hash_algorithm)
        
        if hash_algorithm == SHA256:
            return hashes.SHA256()
        elif hash_algorithm == SHA512:
            return hashes.SHA512()
        elif hash_algorithm == BLAKE2:
            return hashes.BLAKE2b(64)

    def pad(self, algorithm, data):
        '''
        @param plaintext: the text to pad, type bytes
        @algorithm: the algorithm reference to used, type string
        '''
        if self._ciphers[algorithm]["block_cipher"]:
            padder = padding.PKCS7(self._ciphers[algorithm]["bs"]*8).padder()
            data = padder.update(data) + padder.finalize()
        return data
    
    def unpad(self, algorithm, data):
        '''
        @param data: the data to unpad, type bytes
        @algorithm: the algorithm reference to used, type string
        '''
        if self._ciphers[algorithm]["block_cipher"]:
            unpadder = padding.PKCS7(self._ciphers[algorithm]["bs"]*8).unpadder()
            data = unpadder.update(data) + unpadder.finalize()
        return data

    def generate_hash(self, algorithm, data):
        '''
        @param data: the data to generate digest, type bytes
        @algorithm: the algorithm reference to used, type string
        '''
        hash_algorithm = self.get_digest(algorithm)
        digest = hashes.Hash(hash_algorithm, backend=default_backend())
        digest.update(data)
        return digest.finalize()

    def generate_mac(self, key, algorithm, data):
        '''
        @param data: the data to generate mac, type bytes
        @algorithm: the algorithm reference to used, type string
        '''
        hash_algorithm = self.get_digest(algorithm)
        mac = hmac.HMAC(key, hash_algorithm, backend=default_backend())
        mac.update(data)
        return mac.finalize()
        
    def symmetric_encryption(self, algorithm_name, mode_name, key, data):
        '''
        @param data: the data to encrypt, type bytes
        @param key: the key to generate cipher, type bytes
        @param algorithm_name: the algorithm reference to used, type string
        @param mode_name: the cipher mode reference to used, type string
        '''
        mode, iv = self.get_mode(mode_name, algorithm_name)
        algorithm, nonce = self.get_algorithm(algorithm_name, mode_name, key)
        cipher = Cipher(algorithm, mode=mode, backend=default_backend())
        encryptor = cipher.encryptor()
        cryptogram = encryptor.update(self.pad(algorithm_name, data)) + encryptor.finalize()

        tag = None
        if mode_name == GCM:
            tag = encryptor.tag
        return cryptogram, iv, nonce, tag

    def symmetric_decryption(self, data, key, algorithm_name, mode_name, parameters):
        '''
        @param data: the data to decrypt, type bytes
        @param key: the key to generate cipher, type bytes
        @param algorithm_name: the algorithm reference to used, type string
        @param mode_name: the cipher mode reference to used, type string
        @param parameters: parameters to generate cipher
        '''
        iv, nonce, tag = parameters
        mode, _ = self.get_mode(mode_name, algorithm=algorithm_name, encrypt=False, parameters=(iv, tag))
        algorithm, _ = self.get_algorithm(algorithm_name, mode_name, key, encrypt=False, parameter=nonce)
        cipher = Cipher(algorithm, mode=mode, backend=default_backend())
        decryptor = cipher.decryptor()
        encoded_data = decryptor.update(data) + decryptor.finalize()
        plaintext = self.unpad(algorithm_name, encoded_data)
        return plaintext

    def DH_adaptation(self, p, g):
        '''
        @param p: param p to DHKE, type int
        @param g: param g to DHKE, type int
        '''
        parameters = (dh.DHParameterNumbers(p, g)).parameters(default_backend())

        privkey = parameters.generate_private_key()
        public_key_pem = (privkey.public_key()).public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

        return privkey, public_key_pem
    
    def DH_creation(self):
        parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

        privkey = parameters.generate_private_key()
        pubkey = privkey.public_key()

        p = parameters.parameter_numbers().p
        g = parameters.parameter_numbers().g

        pubkey_pem = pubkey.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

        return p, g, privkey, pubkey_pem

    def generate_shared_key(self, private_key, public_key_pem, algorithm):
        '''
        @param private_key: the module owner private key, type bytes
        @param public_key_pem: the other entity public key, type bytes in pem encoding
        @param algorithm_name: the algorithm reference to used, type string
        '''
    
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

        shared_key = private_key.exchange(public_key)
        hash_algorithm = self.get_digest(algorithm)

        return HKDF(algorithm=hash_algorithm,length=32,salt=None,
                info=b"handshake data",backend=default_backend()).derive(shared_key)

    def generate_rsa_signature(self, data, private_key):
        """
	    Function used to sign a message with a private key
	    :param message: The message to be signed
	    :param private_key: The private_key used to sign the message
	    :return: The result signature.
	    """
        return private_key.sign(data, asy_padding.PSS(mgf=asy_padding.MGF1(hashes.SHA256()), salt_length=asy_padding.PSS.MAX_LENGTH), hashes.SHA256())


    def validate_rsa_signature(self, signature, data, public_key):
        try:
            public_key.verify(signature,data,asy_padding.PSS(mgf=asy_padding.MGF1(hashes.SHA256()), salt_length=asy_padding.PSS.MAX_LENGTH),hashes.SHA256())
        except:
            return False
        return True

    def load_certificate(self, certificate_pem):
        try:
            return x509.load_pem_x509_certificate(certificate_pem, default_backend())
        except Exception:
            return None

    def validate_certificate_period(self, certificate):
        before = certificate.not_valid_before.timestamp()
        after = certificate.not_valid_after.timestamp()
        now = datetime.now().timestamp()
        if before < now < after:
            return True
        return False

    def validate_certificate_signature(self, certificate, issuer):
        signature = certificate.signature
        data = certificate.tbs_certificate_bytes
        hash_algorithm = certificate.signature_hash_algorithm
        public_key = issuer.public_key()
        return True
        return self.validate_signature(signature, data, public_key, hash_algorithm=hash_algorithm)

    def validate_signature(self, signature, data, public_key, hash_algorithm=hashes.SHA1()):
        try:
            public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
        except:
            print("algo não esta")
            return False
        return True


    def generate_certificate_trust_chain(self, certificate, certificates, chain=[]):
        chain.append(certificate)

        issuer = certificate.issuer.rfc4514_string()
        subject = certificate.subject.rfc4514_string()

        if issuer == subject and subject in certificates:
            return chain

        if issuer in certificates:
            return self.generate_certificate_trust_chain(certificates[issuer], certificates, chain=chain)

        return None

    def validate_trust_chain(self, chain, crl_path):
        for i in range(0, len(chain) - 1):
            if not self.validate_certificate(chain[i], crl_path, issuer=chain[i + 1]):
                return False
        return True


    def validate_certificate(self, certificate, crl_path, issuer=None):
        if not self.validate_certificate_period(certificate):
            print('problema de periodo')
            return False
        if issuer == None:
            return True

        if not self.validate_certificate_signature(certificate, issuer):
            print('problema de assinatura')
            return False

        if not self.validate_certificate_common_name(certificate, issuer):
            print('problema de name')
            return False
        return True


    def load_private_key(self, private_key_pem):
        return serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    def encode_certificate(self, cert):
        return cert.public_bytes(serialization.Encoding.PEM)

    '''
    def sign_with_cc(self, data):
        """
	Function used to load the contents of an inserted CC and sign a given message.
	:param message: THe message that is going to be signed.
	:return: The signed message and the CC Certificate in bytes.
	    """
        try:
            lib = "/usr/local/lib/libpteidpkcs11.so"
            pkcs11 = PyKCS11.PyKCS11Lib()
            pkcs11.load(lib)
            session = pkcs11.openSession(pkcs11.getSlotList()[0])

            # Get all attributes
            all_attr = list(PyKCS11.CKA.keys())
            all_attr = [e for e in all_attr if isinstance(e, int)]

            # Get the private key
            private_key = session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION KEY")
            ])[0]

            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)

            # Sign the message
            signature = bytes(session.sign(private_key, data, mechanism))

            # Get the certificate object from the session
            cert_obj = session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),(PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE"),
            ])[0]

            attr = session.getAttributeValue(cert_obj, all_attr)
            attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))

            # Get the x509 certificate using the value from the attribute in the CC
            certificate = x509.load_der_x509_certificate(bytes(attr["CKA_VALUE"]), default_backend())

            return signature, self.encode_certificate(certificate)
        except:
            print("Error - No card reader / valid CC detected")
            exit(1)
    '''

    def get_issuer_common_name(self, certificate):
        try:
            return certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except x509.ExtensionNotFound:
            return None
    
    def get_common_name(self, certificate):
        try:
            return certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except x509.ExtensionNotFound:
            return None

    def validate_certificate_common_name(self, cert, issuer):
        certificate_issuer_common_name = self.get_issuer_common_name(cert)
        issuer_common_name = self.get_common_name(issuer)
        if certificate_issuer_common_name and issuer_common_name:
            return certificate_issuer_common_name == issuer_common_name
        return False

    def generate_rsa_key(self):
        """
	    Function used to generate a Private Key
	    :return: The generated Private and Public key
	    """
        return rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        

    def generate_rsa_pem_pairs(self, key):
        private_key_pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.BestAvailableEncryption(b''))
        public_key_pem = key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return private_key_pem, public_key_pem


        

