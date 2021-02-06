import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

BLOCK_LEN = 16

ORIGINAL_PATH = 'server/catalog'
DEST_PATH = 'server/enc_catalog'

files = [file for file in os.listdir(ORIGINAL_PATH) if os.path.isfile(os.path.join(ORIGINAL_PATH,file))]
reader = open('server/key.bin','rb')
key = reader.read()

def encryption(file):
    infile = open(os.path.join(ORIGINAL_PATH,file), 'rb')
    outfile = open(os.path.join(DEST_PATH,file), 'wb')
    nonce = os.urandom(BLOCK_LEN)

    outfile.write(nonce)
    print(f'nonce: {nonce}')
    cipher  = Cipher(algorithms.ChaCha20(key, nonce),mode=None, backend=default_backend())
    active = True
    while active:
        encryptor = cipher.encryptor()
        data = infile.read(BLOCK_LEN)
        if len(data) < BLOCK_LEN:
            active = False
        data = encryptor.update(data) + encryptor.finalize()
        outfile.write(data)

for file in files:
    encryption(file)
