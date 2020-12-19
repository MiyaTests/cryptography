from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os
import base64
import csv

class Security:
    def __init__(self):
        try: 
            with open('keys.csv') as csvfile:
                table = csv.reader(csvfile, delimiter=';')
                for keys in table:  
                    self.aes = base64.b64decode(keys[0].encode()) 
                    self.iv = base64.b64decode(keys[1].encode()) 
                    self.counter = keys[2].encode() 
                    self.mac = keys[3].encode()
            if not (self.aes and self.iv and self.counter and self.mac):
                raise Exception('empty keys')
        except:
            self.aes = os.urandom(32)
            self.iv = os.urandom(16)
            self.counter = base64.b64encode(os.urandom(16))
            self.mac = b"CorrectHorseBatteryStaple"
            with open('keys.csv', 'w') as csvfile:
                table = csv.writer(csvfile, delimiter=';')
                values = [base64.b64encode(self.aes).decode(), base64.b64encode(self.iv).decode(), self.counter.decode(), self.mac.decode()]
                table.writerow(values)

        aes_context = Cipher(algorithms.AES(self.aes), modes.CTR(self.iv), backend=default_backend())
        self.encryptor = aes_context.encryptor()
        self.decryptor = aes_context.decryptor()

    def updateEncryptor(self, plaintext):
        plainbytes = plaintext.encode()
        secret = self.counter + plainbytes
        encrypted_text = base64.b64encode(self.encryptor.update(secret))
        self.encryptor.finalize()
        hmac_ = self.calc_hmac(plainbytes)
        return hmac_.encode() + encrypted_text

    def updateDecryptor(self, secret):
        ciphertext = secret[64:] 
        hmac_ = secret[:64].decode()
        cipherbytes = base64.b64decode(ciphertext)
        secret = self.decryptor.update(cipherbytes)
        secret_str = secret.decode()
        plaintext = secret_str[len(self.counter.decode()):]
        plainbytes = plaintext.encode()
        self.decryptor.finalize()
        hmac_calc = self.calc_hmac(plainbytes)
        if hmac_calc == hmac_:
            return plaintext
        else:
            return None

    def calc_hmac(self, plainbytes):
        h = hmac.HMAC(self.mac, hashes.SHA256(), backend=default_backend())
        h.update(plainbytes)
        hmac_ = h.finalize().hex()
        return hmac_

#sec = Security()
#secret = sec.updateEncryptor("3asdasdx")
#print("recovered", sec.updateDecryptor(secret))
