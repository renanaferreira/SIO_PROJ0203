import os
import random
import json

import base64
import binascii
from security_module import Criptography

PRIVKEY_FILE_PATH = '/home/renan/Documents/Cadeiras/SIO/Projetos/proj0203/p2-p3/server/serverKey.pem'
SERVER_CERT_PATH = '/home/renan/Documents/Cadeiras/SIO/Projetos/proj0203/p2-p3/server.crt'
ROOT_CERT_PATH = '/home/renan/Documents/Cadeiras/SIO/Projetos/proj0203/p2-p3/root.crt'

class SecLayer():
    

    def __init__(self):
        self.crypto_module = Criptography()

    @property
    def cipher_suite(self):
        return self.crypto_module.cipher_suite

    @property
    def modes(self):
        return self.crypto_module.modes
        
    @property
    def ciphers(self):
        return self.crypto_module.ciphers

    @property
    def digest_algorithms(self):
        return self.crypto_module.digest_algorithms

    def encode(self, data, encoding='latin', b64=False):
        '''
        Function that converts a variable or list of strings to bytes by specified encoding
        @param str_list: the list of strings to be converted
        @param encoding: default='latin' the encoding type for the function
        returns: a list of bytes

        '''
        if b64:
            return base64.b64encode(data)

        if type(data) == list:
            return [item.encode(encoding) for item in data]
        return data.encode(encoding)

    def decode(self, data, encoding='latin', b64=False):
        if b64:
            return base64.b64decode(data)

        if type(data) == list:
            return [item.decode(encoding) for item in data]
        return data.decode(encoding)

    def select_algorithm(self, algorithms):
        '''
        @param algorithms: type string
        '''
        if algorithms == []:
            return None

        selected = random.randint(0, len(algorithms)-1)
        return algorithms[selected]

    def select_mode(self, modes):
        '''
        @param modes: type string
        '''
        if modes == []:
            return None

        selected = random.randint(0, len(modes)-1)
        return modes[selected]

    def select_digest(self, digests):
        '''
        @param digests: type string
        '''
        if digests == []:
            return None

        selected = random.randint(0, len(digests)-1)
        return digests[selected]

    def cipher_suite_selection(self, algorithms, modes, digests):

        algorithms = self.decode(algorithms)
        modes = self.decode(modes)
        digests = self.decode(digests)

        #Only considers supported algorithms by the server
        allowable_algorithms = [alg for alg in algorithms if alg in self.ciphers]
        algorithm = self.select_algorithm(allowable_algorithms)
        if algorithm == None:
            return None, None, None

        ciphermodes = self.cipher_suite[algorithm]['modes']
        if ciphermodes == []:
            mode = "None"
        else:
            allowable_modes = [mode for mode in modes if mode in ciphermodes]
            mode = self.select_mode(allowable_modes)
        if mode == None:
            return algorithm, None, None

        allowable_digests = [dig for dig in digests if dig in self.digest_algorithms]
        digest = self.select_digest(allowable_digests)
        if digest == None:
            return algorithm, mode, None
        
        return algorithm, mode, digest

    def DH_exchange(self, p, g):
        '''
        @param p: param p of DHKE, type bytes
        @param g: param g of DHKE, type bytes
        return private_key(type bytes) and its public key(type string encoded in ISO-8859-1) 
        '''
        p = int(self.decode(p))
        g = int(self.decode(g))
        private_key, public_key_pem =  self.crypto_module.DH_adaptation(p, g)
        return private_key, public_key_pem

    def DH_creation(self):
        p, g, private_key, public_key_pem = self.crypto_module.DH_creation()
        p = self.encode(str(p))
        g = self.encode(str(g))
        return p, g, private_key, public_key_pem

    def shared_key(self, private_key, public_key_pem, digest_algorithm):
        '''
        @param privkey: the private key of the entity, type bytes
        @param pk_pem: the public key of the other entity, type bytes
        @param digest_algorithm: The digest algorithm reference to be used, type string
        '''
        return self.crypto_module.generate_shared_key(private_key, public_key_pem, digest_algorithm)

    def encrypt(self, cipher, mode, digest, plaintext, private_key, public_key):
        key = self.shared_key(private_key, public_key, digest)
        data = self.encode(plaintext)
        cryptogram, iv, nonce, tag = self.crypto_module.symmetric_encryption(cipher, mode, key, data)

        cryptogram = self.encode(cryptogram, b64=True)
        data_for_mac = cryptogram
        cryptogram = self.decode(cryptogram, encoding='utf-8')
        if iv != None:
            iv = self.encode(iv, b64=True)
            data_for_mac += iv
            iv = self.decode(iv, encoding='utf-8')
        if nonce != None:
            nonce = self.encode(nonce, b64=True)
            data_for_mac += nonce
            nonce = self.decode(nonce, encoding='utf-8')
        if tag != None:
            tag = self.encode(tag, b64=True)
            data_for_mac += tag
            tag = self.decode(tag, encoding='utf-8')
        
        mac = self.crypto_module.generate_mac(key, digest, data_for_mac)
        mac = self.decode(self.encode(mac, b64=True), encoding='utf-8') 

        return cryptogram, mac, iv, nonce, tag

    def decrypt(self, data, mac, algorithm, mode, digest, parameters, private_key, public_key_pem):
        iv, nonce, tag = parameters
        key = self.shared_key(private_key, public_key_pem, digest)
        mac = self.decode(self.encode(mac, 'utf-8'), b64=True)

        data = self.encode(data, encoding='utf-8')
        data_for_mac = data
        data = self.decode(data, b64=True)
        if iv != None:
            iv = self.encode(iv, encoding='utf-8')
            data_for_mac += iv
            iv = self.decode(iv, b64=True)
        if nonce != None:
            nonce = self.encode(nonce, encoding='utf-8')
            data_for_mac += nonce
            nonce = self.decode(nonce, b64=True)
        if tag != None:
            tag = self.encode(tag, encoding='utf-8')
            data_for_mac += tag
            tag = self.decode(tag, b64=True)

        if mac != self.crypto_module.generate_mac(key, digest, data_for_mac):
            return None

        return self.decode(self.crypto_module.symmetric_decryption(data, key, algorithm, mode, (iv, nonce, tag)))

    def authenticate(self, challenge):
        with open(PRIVKEY_FILE_PATH, 'rb') as reader:
            private_key = self.crypto_module.load_private_key(reader.read())
            challenge_response = self.crypto_module.generate_rsa_signature(challenge, private_key)
            certificate_path_chain = self.certificate_trust_chain_path()
            return challenge_response, certificate_path_chain
        

    def certificate_trust_chain_path(self):
        return [SERVER_CERT_PATH, ROOT_CERT_PATH]

    def generate_certificate_set(self, file_paths):
        dicio = dict()
        for path in file_paths:
            with open(path, 'rb') as reader:
                certificate = self.crypto_module.load_certificate(reader.read())
                dicio[certificate.subject.rfc4514_string()] = certificate
        return dicio

    def validate_server_authentication(self, challenge, challenge_response, certificate_paths):
        dicio = self.generate_certificate_set(certificate_paths)
        with open(certificate_paths[0], 'rb') as reader:
            entity_certificate = self.crypto_module.load_certificate(reader.read())
        chain = self.crypto_module.generate_certificate_trust_chain(entity_certificate, dicio)
        print(chain)
        if not self.crypto_module.validate_trust_chain(chain, None):
            print('erro na chain')
            return False
        if not self.crypto_module.validate_signature(challenge_response, challenge, entity_certificate.public_key()):
            print('diferente')
            return False
        return True
        
