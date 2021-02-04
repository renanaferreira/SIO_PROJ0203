import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import base64

import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from security_module import Criptography

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_PORT = 8081
SERVER_URL = 'http://127.0.0.1:'+str(SERVER_PORT)
TIMEOUT = 1000

security = Criptography()

intermediate_path = 'certificates/client_intermediates'

intermediate_certs_files = [file for file in os.listdir(intermediate_path) 
                            if os.path.isfile(os.path.join(intermediate_path,file))]
intermediate_certs = dict()
for file in intermediate_certs_files:
    cert_file = open(intermediate_path + "/" + file, "rb")
    cert = security.load_certificate(cert_file.read())
    intermediate_certs[cert.subject.rfc4514_string()] = cert

root_path = 'certificates/client_roots'

root_certs_files = [file for file in os.listdir(root_path) 
                            if os.path.isfile(os.path.join(root_path,file))]
root_certs = dict()
for file in root_certs_files:
    cert_file = open(root_path + "/" + file, "rb")
    cert = security.load_certificate(cert_file.read())
    root_certs[cert.subject.rfc4514_string()] = cert

crl_path = 'CRLs/client'
crl_files = [file for file in os.listdir(crl_path) 
                            if os.path.isfile(os.path.join(crl_path,file))]
crls = []
for file in crl_files:
    crl_file = open(crl_path + "/" + file, 'rb')
    crls.append(security.load_crl(crl_file.read()))


print('certs intermediate:')
print(intermediate_certs)
print('certs root:')
print(root_certs)





def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")

    algorithms = [security.encode(cipher) for cipher in security.ciphers]
    modes = [security.encode(mode) for mode in security.modes]
    digests = [security.encode(digest) for digest in security.digests]
    parameters = {
        "algorithms": algorithms,
        "modes": modes,
        "digests": digests
    }
    
    req = requests.get(f'{SERVER_URL}/api/protocols', params=parameters)
    if req.status_code == 400:
        raise Exception('Unsupported encryption modules')
    else:
        print("Cipher Suite selection")

    parameters = req.json()
    print(f"Cipher Suite & tokenId: {parameters}")

    tokenId = parameters["tokenId"]
    cipher  = parameters["cipher"]
    mode    = parameters["mode"]
    digest  = parameters["digest"]

    
    p, g, private_key, public_key_pem = security.DH_creation()
    parameters = {'tokenId': tokenId,
                  'p': security.encode(str(p)), 
                  'g': security.encode(str(g)), 
                  'pk_pem': public_key_pem}

    req = requests.get(f'{SERVER_URL}/api/key', params=parameters)

    server_pk_pem = security.encode(req.json()['pk_pem'])
    shared_key = security.generate_shared_key(private_key, server_pk_pem, digest)

    challenge_nonce = os.urandom(16)
    message = security.compose_message(cipher, mode, digest, shared_key, challenge_nonce)

    parameters = {'tokenId': tokenId}
    req = requests.post(f'{SERVER_URL}/api/auth?step=1', params=parameters, data=message)
    body = json.loads(security.decode(security.decompose_message(cipher, mode, digest, shared_key, req.content)))
    challenge_response = security.encode(body["response"])
    server_certificate = security.load_certificate(security.encode(body['certificate']))
    challlenge = security.encode(body['challenge'])

    print('deu certo')
    print(security.validate_certificate_signature(server_certificate, list(root_certs.values())[0]))

    validated = security.authenticate_entity(server_certificate, challenge_nonce, challenge_response, intermediate_certs, root_certs, crls)

    print(f'valido? {validated}')
    exit(0)
    
    req = requests.get(f'{SERVER_URL}/api/list', params=parameters)
    if req.status_code == 200:
        print("Got Server List")

    plaintext = security.decompose_message(cipher, mode, digest, shared_key, req.content)
    if plaintext == None:
        print("Errro!!!!!!!!")
    media_list = json.loads(plaintext)


    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
    print("----")

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection < len(media_list):
            break

    # Example: Download first file
    media_item = media_list[selection]
    print(f"Playing {media_item['name']}")

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()
       
        # TODO: Process chunk

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break

if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)