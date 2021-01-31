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


from security_layer import SecLayer

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_PORT = 8081
SERVER_URL = 'http://127.0.0.1:'+str(SERVER_PORT)
TIMEOUT = 1000

def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    security = SecLayer()

    # Get a list of media files
    print("Contacting Server")

    print("server auth ------")
    nonce = os.urandom(16)
    print(type(nonce))
    parameters = {'challenge': nonce}
    req = requests.get(f'{SERVER_URL}/api/auth', params=parameters)
    body = req.json()
    file_path = body['chain']
    response = body['response']
    if security.validate_server_authentication(nonce, response, file_path):
        print("deu certo porra")
    else:
        print("erro")
        exit(0)
    
    # TODO: Secure the session
    parameters = {"cipher_algorithms": security.ciphers, 
                        "cipher_modes": security.modes, 
                        "digest_algorithms": security.digest_algorithms
                    }
    req = requests.get(f'{SERVER_URL}/api/protocols', params=parameters)
    if req.status_code == 400:
        raise Exception('Unsupported encryption modules')
    else:
        print("Cipher Suite selection")

    parameters = req.json()
    print(f"Cipher Suite & tokenId: {parameters}")

    tokenId = parameters["tokenId"]
    cipher = parameters["cipher"]
    mode = parameters["mode"]
    digest = parameters["digest"]

    
    p, g, private_key, public_key_pem = security.DH_creation()
    parameters = {'tokenId': tokenId,
                  'p': p, 
                  'g': g, 
                  'pk_pem': public_key_pem}

    req = requests.get(f'{SERVER_URL}/api/key', params=parameters)

    server_pk_pem = security.encode(req.json()['pk_pem'])

    parameters = {'tokenId': tokenId}
    req = requests.get(f'{SERVER_URL}/api/list', params=parameters)
    if req.status_code == 200:
        print("Got Server List")

    body = req.json()
    cryptogram = body['message']
    mac = body['mac']
    iv = body['iv']
    nonce = body['nonce']
    tag = body['tag']


    
    
    plaintext = security.decrypt(cryptogram, mac, cipher, mode, digest, (iv, nonce, tag), private_key, server_pk_pem)
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