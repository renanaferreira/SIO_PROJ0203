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
from requests.api import request

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

def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")

    body = security.encode(json.dumps({
        "algorithms": security.ciphers,
        "modes": security.modes,
        "digests": security.digests
    }))
    
    req = requests.post(f'{SERVER_URL}/api/protocols', data=body)


    if req.status_code == 500:
        print('error')
        exit(0)
        
    print("Cipher Suite selection")

    body = json.loads(security.decode(req.content))
    print(f"Cipher Suite & tokenId: {body}")

    tokenId = body["tokenId"]
    cipher  = body["cipher"]
    mode    = body["mode"]
    digest  = body["digest"]

    
    p, g, private_key, public_key_pem = security.DH_creation()
    body = security.encode(json.dumps({'tokenId': tokenId, 'p': p, 
                  'g': g, 'pk_pem': security.decode(public_key_pem)}))

    req = requests.post(f'{SERVER_URL}/api/key', data=body)
    if req.status_code == 500:
        print('error')
        exit(0)

    body = json.loads(security.decode(req.content))

    shared_key = security.generate_shared_key(private_key, security.encode(body['pk_pem']), digest)

    challenge_nonce = os.urandom(16)
    message = security.compose_message(cipher, mode, digest, shared_key, challenge_nonce)

    body = security.encode(json.dumps({'tokenId': tokenId, 'data': security.decode(message)}))
    req = requests.post(f'{SERVER_URL}/api/auth?step=1', data=body)
    if req.status_code == 500:
        print('error')
        exit(0)


    body = json.loads(security.decode(security.decompose_message(cipher, mode, digest, shared_key, req.content)))
    challenge_response = security.encode(body["response"])
    server_certificate = security.load_certificate(security.encode(body['certificate']))
    challlenge = security.encode(body['challenge'])

    validated = security.authenticate_entity(server_certificate, challenge_nonce, challenge_response, intermediate_certs, root_certs, crls)
    if not validated:
        print('Server não foi autenticado')
        exit(0)

    print('teste')
    nonce_teste = os.urandom(16)
    user_certificate = security.get_certificate_cc()
    response_teste = security.generate_signature_cc(challlenge)
    print(f'valido? {security.validate_signature(response_teste, nonce_teste, user_certificate.public_key())}')
    
    user_certificate = security.get_certificate_cc()
    certificate_pem = security.pack_certificate_pem(user_certificate)
    challenge_response = security.generate_signature_cc(challlenge)
    userid = security.decode(security.get_userid_cc())
    body = security.encode(json.dumps({'certificate': certificate_pem, 'response': challenge_response, 'id': userid}))
    message = security.compose_message(cipher, mode, digest, shared_key, body)

    body = security.encode(json.dumps({'tokenId': tokenId, 'data': security.decode(message)}))
    req = requests.post(f'{SERVER_URL}/api/auth?step=2', params=body,data=message)
    if req.status_code == 500:
        print('error')
        exit(0)

    message = security.decompose_message(cipher, mode, digest, shared_key, request.content)
    print('aquuuuuuuu')
    print(message)


    
    req = requests.get(f'{SERVER_URL}/api/list', params=body)
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