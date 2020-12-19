from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import os
import base64
import csv
import json
import re


class Security:
    def __init__(self, my_private_pem, my_public_pem, other_public_pem=None, username=None):
        self.my_private_pem = my_private_pem
        self.my_public_pem = my_public_pem
        self.username = username
        if other_public_pem:
            self.other_public_pem = other_public_pem
            self.other_public_key = serialization.load_pem_public_key(other_public_pem,
                backend = default_backend())
        else:
            self.other_public_pem = None
            self.other_public_key = None

        self.my_private_key = serialization.load_pem_private_key(my_private_pem,
            backend = default_backend(), password = None)

        self.my_public_key = serialization.load_pem_public_key(my_public_pem,
            backend = default_backend())

        with open("issuer_key.pem", "rb") as private_key_file_object:
            self.issuer_private_key = serialization.load_pem_private_key(private_key_file_object.read(),
                backend = default_backend(), password = None)

        with open("issuer_key_pub.pem", "rb") as public_key_file_object:
            self.issuer_public_key = serialization.load_pem_public_key(public_key_file_object.read(),
                backend=default_backend())


    def encrypt_message(self, message):
        certificate = self.create_fake_certificate(self.my_public_pem)
        secret = self.updateEncryptor(message)
        return secret + certificate

    def decrypt_message(self, bytesmessage):
        searcher = re.search(b'(?P<secret>(.|\n)*)(?P<raw_bytes>{(.|\n)*?"subject":(.|\n)*?})(?P<signature>(.|\n)*)', bytesmessage)
        secret = searcher.group('secret')
        raw_bytes = searcher.group('raw_bytes')
        signature = searcher.group('signature')
        certificate_bytes = raw_bytes + signature
        try:
            self.other_public_key = self.validate_certificate(raw_bytes, signature)
        except:
            return None
        return self.updateDecryptor(secret, self.other_public_key)


    def create_fake_certificate(self, pem_public_key):
        ISSUER_NAME = "fake_cert_authority1"
        subject = self.username
        certificate_data = {}
        certificate_data["subject"] = subject
        certificate_data["issuer"] = ISSUER_NAME
        certificate_data["public_key"] = pem_public_key.decode('utf-8')
        raw_bytes = json.dumps(certificate_data).encode('utf-8')
        signature = self.issuer_private_key.sign(raw_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return raw_bytes + signature

    def validate_certificate(self, raw_cert_bytes, signature):
        self.issuer_public_key.verify(signature,raw_cert_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        cert_data = json.loads(raw_cert_bytes.decode('utf-8'))
        print(cert_data['subject'])
        cert_data["public_key"] = cert_data["public_key"].encode('utf-8')
        other_public_key = serialization.load_pem_public_key(cert_data["public_key"],
            backend=default_backend())
        return other_public_key

    def updateEncryptor(self, plaintext):
        # generate all the keys
        aes = os.urandom(32)
        iv = os.urandom(16)
        counter = base64.b64encode(os.urandom(16))
        mac = base64.b64encode(os.urandom(16))
        aes_context = Cipher(algorithms.AES(aes), modes.CTR(iv), backend=default_backend())
        encryptor = aes_context.encryptor()

        # encrypt message
        plainbytes = plaintext.encode()
        secret = counter + plainbytes
        encrypted_text = base64.b64encode(encryptor.update(secret))
        encryptor.finalize()

        # keys asymetrical encryption
        aes_encoded = base64.b64encode(aes)
        iv_encoded = base64.b64encode(iv)
        data = aes_encoded + iv_encoded + counter + mac
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(data)
        data_digest = h.finalize()
        signature = self.my_private_key.sign(data_digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        ciphertext = self.other_public_key.encrypt(data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))

        # we have to send back:
        # encrypted msg, encrypted keys and signature, HMAC of the whole transmission
        cipherdata = ciphertext + signature + encrypted_text
        hmac_ = self.calc_hmac(cipherdata, mac)
        return hmac_.encode() + cipherdata 

    def updateDecryptor(self, secret, other_public_key):
        # extract components
        hmac_ = secret[:64].decode()
        cipherdata = secret[64:]
        ciphertext = secret[64:320] 
        signature = secret[320:576] 
        encrypted_text = secret[576:]

        # decrypt keys 
        data = self.my_private_key.decrypt(ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))
        aes_encoded = data[:44]
        iv_encoded = data[44:68]
        counter = data[68:92]
        mac = data[92:]
        aes = base64.b64decode(aes_encoded)
        iv = base64.b64decode(iv_encoded)
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(data)
        data_digest = h.finalize()

        # check signatures
        verified = True
        try:
            other_public_key.verify(signature, data_digest, 
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except:
            print("signature")
            verified = False

        # check hmac
        hmac_calc = self.calc_hmac(cipherdata, mac)
        if hmac_calc != hmac_:
            print("hmac")
            verified = False

        # decrypt text
        aes_context = Cipher(algorithms.AES(aes), modes.CTR(iv), backend=default_backend())
        decryptor = aes_context.decryptor()
        cipherbytes = base64.b64decode(encrypted_text)
        secret = decryptor.update(cipherbytes)
        secret_str = secret.decode()
        plaintext = secret_str[len(counter.decode()):]
        plainbytes = plaintext.encode()
        decryptor.finalize()

        # response
        if verified: return plainbytes
        else: return None


    def calc_hmac(self, plainbytes, mac):
        h = hmac.HMAC(mac, hashes.SHA256(), backend=default_backend())
        h.update(plainbytes)
        hmac_ = h.finalize().hex()
        return hmac_

#sec = Security()
#secret = sec.updateEncryptor("3asdasdx")
#print("recovered", sec.updateDecryptor(secret))

with open("my_key.pem", "rb") as private_key_file_object:
    my_private_pem = private_key_file_object.read()
    my_private_key = serialization.load_pem_private_key(my_private_pem,
            backend = default_backend(), password = None)

with open("my_key_pub.pem", "rb") as public_key_file_object:
    my_public_pem = public_key_file_object.read()
    my_public_key = serialization.load_pem_public_key(my_public_pem, backend=default_backend())

with open("server_key.pem", "rb") as private_key_file_object:
    server_private_pem = private_key_file_object.read()
    server_private_key = serialization.load_pem_private_key(server_private_pem,
            backend = default_backend(), password = None)

with open("server_key_pub.pem", "rb") as public_key_file_object:
    server_public_pem = public_key_file_object.read()
    server_public_key = serialization.load_pem_public_key(server_public_pem,
            backend=default_backend())


#client = Security(my_private_pem, my_public_pem, server_public_pem)
#secret = client.encrypt_message("helloworld")

#server = Security(server_private_pem, server_public_pem)
#message = server.decrypt_message(secret)
#print(message)

#certificate_bytes = client.create_fake_certificate(my_public_pem, 'sd', issuer_private_key)
#print(secret + certificate_bytes)
#try:
#b = client.validate_certificate(certificate_bytes, issuer_public_key)
#except:
#    b = None

#print(b)

#server = Security(server_private_key, server_public_key, my_public_key)
#plaintext = server.updateDecryptor(secret)
#print(plaintext)




