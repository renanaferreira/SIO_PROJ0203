#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
from secrets import token_urlsafe

import logging
import binascii
import json
import os
import math
import random
from datetime import datetime
from datetime import timedelta as delta

from security_module import Criptography

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)


STATE_CONNECT = 0
STATE_CS = 1
STATE_DHK = 2
STATE_SERVER_AUTH = 3


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

    def __init__(self, private_key, server_cert, intermediate_certs, root_certs, crls):
        '''
        rpkp: rsa private key path (inside host machine)
        crpkp: certificate rsa public key path (inside host machine)
        trcp: trusted root certificates path list (inside host machine)
        crlrp: crl root path list (inside host machine)
        '''
        super().__init__()
        self.security = Criptography()
        self.clients = dict()
        self.users = dict()

        self.private_rsa_key = self.security.load_private_key(private_key)
        self.server_certificate = self.security.load_certificate(server_cert)

        self.intermediate_certificates = dict()
        for cert in intermediate_certs:
            certificate = self.security.load_certificate(cert)
            self.intermediate_certificates[certificate.subject.rfc4514_string()] = certificate

        self.root_certificates = dict()
        for cert in root_certs:
            certificate = self.security.load_certificate(cert)
            self.root_certificates[certificate.subject.rfc4514_string()] = certificate

        self.crl_list = []
        for crl in crls:
            self.crl_list.append(self.security.load_crl(crl))

    @property
    def allowed_algorithms(self):
        return self.security.ciphers

    @property
    def allowed_modes(self):
        return self.security.modes

    @property
    def allowed_digests(self):
        return self.security.digests

            
    def cipher_suite_selection(self, algorithm_list, mode_list, digest_list):

        allowable_algorithms = [alg for alg in algorithm_list if alg in self.allowed_algorithms]
        algorithm = self.select_algorithm(allowable_algorithms)
        if algorithm == None:
            return None, None, None

        ciphermodes = self.security.get_allowed_modes(algorithm)
        if ciphermodes == []:
            mode = "None"
        else:
            allowable_modes = [mode for mode in mode_list if mode in ciphermodes and mode in self.allowed_modes]
            mode = self.select_mode(allowable_modes)
        if mode == None:
            return None, None, None

        allowable_digests = [dig for dig in digest_list if dig in self.allowed_digests]
        digest = self.select_digest(allowable_digests)
        if digest == None:
            return None, None, None
        
        return algorithm, mode, digest

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


    def do_get_shared_key(self, request):
        logger.debug("DH KEY Exchange")

        body = json.loads(self.security.decode(request.content.read()))
        tokenId = body['tokenId']
        logger.debug(f"Key: session: tokenId: {tokenId}")

        if not tokenId in self.clients:
            request.setResponseCode(500)
            return json.dumps({'issue': 'You must first initiate session on /api/protocols'}).encode('latin')

        client = self.clients[tokenId]

        p = int(body['p'])
        g = int(body['g'])
        private_key, my_pk_pem = self.security.DH_adaptation(p, g)
        key = self.security.generate_shared_key(private_key, self.security.encode(body['pk_pem']), self.clients[tokenId]['cs'][2])

        self.clients[tokenId]["dh"] = key
        self.clients[tokenId]['state'] = STATE_DHK
        logger.debug(f"Client state: {self.clients[tokenId]['state']}")

        return json.dumps({'pk_pem': self.security.decode(my_pk_pem)}).encode('latin')

    


    def do_auth(self, request):
        body = json.loads(self.security.decode(request.content.read()))
        tokenId = body['tokenId']

        logger.debug(f"Key: session: tokenId: {tokenId}")

        if not tokenId in self.clients:
            request.setResponseCode(500)
            return self.security(json.dumps({'issue': 'You must first initiate session on /api/protocols'}))

        client = self.clients[tokenId]
        key = client['dh']

        cipher = client['cs'][0]
        mode = client['cs'][1]
        digest = client['cs'][2]

        if client['state'] < STATE_DHK:
            request.setResponseCode(500)
            return self.security(json.dumps({'issue': 'You must first authenticate DH Shared key in /api/key'}))

        step = self.security.decode(request.args.get(b'step')[0])
        if step == '1':
            message = self.security.encode(body['data'])
            challenge_nonce = self.security.decompose_message(cipher, mode, digest, key, message)
            challenge_response = self.security.generate_rsa_signature(challenge_nonce, self.private_rsa_key)
            nonce = os.urandom(16)
            self.clients[tokenId]['nonce'] = nonce
            data = json.dumps({'response':self.security.decode(challenge_response), 
                               'certificate': self.security.decode(self.security.pack_certificate_pem(self.server_certificate)), 
                               'challenge': self.security.decode(nonce)}).encode('latin')
            return self.security.compose_message(cipher, mode, digest, key, data)
        elif step == '2':
            message = self.security.encode(body['data'])
            body = json.loads(self.security.decode(self.security.decompose_message(cipher, mode, digest, key, message)))
            response = self.security.encode(body['response'])
            userid = body['id']
            logger.debug(f'userid: {userid}')
            certificate = self.security.load_certificate(self.security.encode(body['certificate']))
            validated = self.security.authenticate_entity(certificate,  self.clients[tokenId]['nonce'], response, self.intermediate_certificates, self.root_certificates, self.crl_list)
            if validated:
                if not userid in self.users:
                    self.users[userid] = dict()
                    self.users[userid]['certificate'] = certificate
                    self.users[userid]['licenses'] = dict()
                    for media_id in CATALOG:
                        self.users[userid]['licenses']['views'] = 100
                        self.users[userid]['licenses']['from'] = datetime.now()
                        self.users[userid]['licenses']['until'] = datetime.now() + delta(days=2)
                else:
                    if certificate != self.users[userid]['certificate']:
                        self.users[userid]['certificate'] = certificate
                body = self.security.encode(json.dumps({'status': 'OK'}))
                logger.debug(f'you are authenticated: {body}')
                message = self.security.compose_message(cipher, mode, digest, key, body)
                return message
            else:
                body = self.security.encode(json.dumps({'status':'unvalid'}))
                return self.security.compose_message(cipher, mode, digest, key, body)
        else:
            request.setResponseCode(405)
            body = self.security.encode(json.dumps({'error': 'unespecified parameter step'}))
            return self.security.compose_message(cipher, mode, digest, key, body)



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

        body = json.loads(self.security.decode(request.content.read()))
        
        algorithms = body['algorithms']
        modes      = body['modes']    
        digests    = body['digests']

        logger.debug(f"Cipher Algorithms: {algorithms}")
        logger.debug(f"Cipher Modes: {modes}")
        logger.debug(f"Digest Algorithms: {digests}")

        cipher, mode, digest = self.cipher_suite_selection(algorithms, modes, digests)
        
        logger.debug(f"Cipher Suite Selection: {cipher}, {mode}, {digest}")

        self.clients[tokenId]["cs"] = [cipher, mode, digest]
        
        
        if cipher == None or mode == None or digest == None:
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            request.setResponseCode(500)
            return self.security.decode(json.dumps({'error': 'Not supported encryption functions'}))

        parameters = {
            'tokenId': tokenId,
            'cipher': cipher,
            'mode': mode,
            'digest': digest
        }

        logger.debug(f"type: {parameters}")

        self.clients[tokenId]['state'] = STATE_CS

        logger.debug(f"Client state: {self.clients[tokenId]['state']}")

        return self.security.encode(json.dumps(parameters))

    # Send the list of media files to clients
    def do_list(self, request):

        logger.debug("Media List")

        tokenId = request.args.get(b'tokenId')[0].decode('latin')
        logger.debug(f"List: session: tokenId: {tokenId}")

        

        if not tokenId in self.clients:
            request.setResponseCode(405)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'issue': 'You must first initiate session on /api/protocols'}).encode('latin')

        if self.clients[tokenId]['state'] != STATE_DHK:
            request.setResponseCode(405)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'issue': 'You must first establish DF Key exchange on /api/key'}).encode('latin')

        privkey = self.clients[tokenId]['DH']['my_privkey']
        pk_pem = self.clients[tokenId]['DF_key_exchange']['client_pk_pem']

        cipher = self.clients[tokenId]['cs'][0]
        mode   = self.clients[tokenId]['cs'][1]
        digest = self.clients[tokenId]['cs'][2]        

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

        data = json.dumps(media_list, indent=4).encode('latin')
        message = self.security_module.encrypt(cipher_alg, cipher_mode, digest_alg, data, privkey, pk_pem)

        self.clients[tokenId]['state'] = STATE_SERVER_AUTH
        logger.debug(f"Client state: {self.clients[tokenId]['state']}")

        # Return list to client
        return message


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

    
    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.path == b'/api/key':
                return self.do_get_shared_key(request)
            elif request.path == b'/api/auth':
                return self.do_auth(request)
            elif request.path == b'/api/list':
                return self.do_list(request)
            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods:  /api/protocols /api/key /api/auth /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''


print("Server started")
print("URL is: http://IP:"+str(SERVER_PORT))

srpk = 'server/ServerKey.pem'
sc = 'server/server.crt'

reader = open(srpk, 'rb')
private_key_bytes = reader.read()
reader = open(sc, 'rb')
cert_bytes = reader.read()

intermediate_path = 'certificates/server_intermediates'

intermediate_certs_files = [file for file in os.listdir(intermediate_path) 
                            if os.path.isfile(os.path.join(intermediate_path,file))]
itmdt_certs_bytes = []
for file in intermediate_certs_files:
    cert_file = open(intermediate_path + "/" + file, "rb")
    itmdt_certs_bytes.append(cert_file.read())

root_path = 'certificates/server_roots'

root_certs_files = [file for file in os.listdir(root_path) 
                            if os.path.isfile(os.path.join(root_path,file))]
root_certs_bytes = []
for file in root_certs_files:
    cert_file = open(root_path + "/" + file, "rb")
    root_certs_bytes.append(cert_file.read())

crl_path = 'CRLs/server'

crl_files = [file for file in os.listdir(crl_path) 
                            if os.path.isfile(os.path.join(crl_path,file))]

crl_path_bytes = []
for file in crl_files:
    cert_file = open(crl_path + "/" + file, "rb")
    crl_path_bytes.append(cert_file.read())




s = server.Site(MediaServer(private_key_bytes, cert_bytes, itmdt_certs_bytes, root_certs_bytes, crl_path_bytes))
reactor.listenTCP(SERVER_PORT, s)
reactor.run()