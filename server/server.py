#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
from secrets import token_urlsafe

import logging
import binascii
import json
import os
import math

from security_layer import SecLayer

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)


STATE_CONNECT = 0
STATE_CS = 1
STATE_DFK = 2
STATE_CONF = 3

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4
SERVER_PORT = 8081

class MediaServer(resource.Resource):
    isLeaf = True

    def __init__(self):
        super().__init__()
        self.security_module = SecLayer()
        self.clients = dict()


    def do_get_shared_key(self, request):
        logger.debug("DF KEY Protocol")

        tokenId = self.security_module.decode(request.args.get(b'tokenId')[0])
        logger.debug(f"Key: session: tokenId: {tokenId}")

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")

        if not tokenId in self.clients:
            request.setResponseCode(405)
            return json.dumps({'issue': 'You must first initiate session on /api/protocols'}).encode('latin')

        p = request.args.get(b'p')[0]
        g = request.args.get(b'g')[0]
        client_pk_pem = request.args.get(b'pk_pem')[0]
        private_key, my_pk_pem = self.security_module.DH_exchange(p, g)


        self.clients[tokenId]["DF_key_exchange"] = {'my_privkey': private_key, 'client_pk_pem': client_pk_pem}
        self.clients[tokenId]['state'] = STATE_DFK
        logger.debug(f"Client state: {self.clients[tokenId]['state']}")

        return json.dumps({'pk_pem': self.security_module.decode(my_pk_pem)}).encode('latin')

    def do_client_auth(self, request):
        client_certificate = request.args.get(b'certificate')

        pass

    def do_server_auth(self, request):
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        challenge_nonce = request.args.get(b'challenge')[0]
        challenge_response, paths = self.security_module.authenticate(challenge_nonce)
        return json.dumps({'response':self.security_module.decode(challenge_response), 'chain': paths}).encode('latin')

    def do_get_protocols(self, request):
        logger.debug("Protocols: Cipher Suite procedure")

        #criação de um tokenId para guardar informações do cliente
        tokenId = token_urlsafe(10)
        while tokenId in self.clients:
            tokenId = token_urlsafe(10)
        self.clients[tokenId] = dict()
        self.clients[tokenId]['state'] = STATE_CONNECT
        logger.debug(f"Client state: {self.clients[tokenId]['state']}")

        logger.debug(f"Protocols: TokenId: {tokenId}")
        
        ciphers = request.args.get(b'cipher_algorithms')
        modes = request.args.get(b'cipher_modes')
        digests = request.args.get(b'digest_algorithms')

        logger.debug(f"Cipher Algorithms: {ciphers}")
        logger.debug(f"Cipher Modes: {modes}")
        logger.debug(f"Digest Algorithms: {digests}")

        cipher, mode, digest_alg = self.security_module.cipher_suite_selection(ciphers, modes, digests)
        
        logger.debug(f"Cipher Suite Selection: {cipher}, {mode}, {digest_alg}")
        self.clients[tokenId]["cipher_suite"] = {"ca": cipher, "cm": mode, "da": digest_alg}
        
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        if cipher == None or mode == None or digest_alg == None:
            request.setResponseCode(400)
            return json.dumps({'error': 'Not supported encryption functions'}).encode('latin')
        parameters = {
            'tokenId': tokenId,
            'cipher': cipher,
            'mode': mode,
            'digest': digest_alg
        }
        logger.debug(f"type: {parameters}")
        self.clients[tokenId]['state'] = STATE_CS
        logger.debug(f"Client state: {self.clients[tokenId]['state']}")

        return json.dumps(parameters, indent=4).encode('latin')


        
        

    # Send the list of media files to clients
    def do_list(self, request):

        logger.debug("Media List")

        tokenId = request.args.get(b'tokenId')[0].decode('latin')
        logger.debug(f"List: session: tokenId: {tokenId}")

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")

        if not tokenId in self.clients:
            request.setResponseCode(405)
            return json.dumps({'issue': 'You must first initiate session on /api/protocols'}).encode('latin')

        if self.clients[tokenId]['state'] != STATE_DFK:
            request.setResponseCode(405)
            return json.dumps({'issue': 'You must first establish DF Key exchange on /api/key'}).encode('latin')

        privkey = self.clients[tokenId]['DF_key_exchange']['my_privkey']
        pk_pem = self.clients[tokenId]['DF_key_exchange']['client_pk_pem']

        cipher_alg = self.clients[tokenId]['cipher_suite']['ca']
        cipher_mode = self.clients[tokenId]['cipher_suite']['cm']
        digest_alg = self.clients[tokenId]['cipher_suite']['da']        

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'




        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
                })

        plaintext = json.dumps(media_list, indent=4)
        cryptogram, mac, iv, nonce, tag = self.security_module.encrypt(cipher_alg, cipher_mode, digest_alg, plaintext, privkey, pk_pem)
        body = {'message': cryptogram, 'mac': mac, 'iv': iv, 'nonce': nonce, 'tag': tag}

        self.clients[tokenId]['state'] = STATE_CONF
        logger.debug(f"Client state: {self.clients[tokenId]['state']}")

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(body).encode('latin')


    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            
            #elif request.uri == '':
            #...
            #elif request.uri == 'api/auth':

            
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.path == b'/api/key':
                return self.do_get_shared_key(request)
            elif request.path == b'/api/auth':
                return self.do_server_auth(request)
            elif request.path == b'/api/list':
                return self.do_list(request)
            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''


print("Server started")
print("URL is: http://IP:"+str(SERVER_PORT))

s = server.Site(MediaServer())
reactor.listenTCP(SERVER_PORT, s)
reactor.run()