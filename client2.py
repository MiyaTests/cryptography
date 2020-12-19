import socket 
from subprocess import Popen, PIPE
from encrypt2 import Security
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

HOST = 'localhost'
PORT = 50007

with open("my_key.pem", "rb") as private_key_file_object:
    my_private_key = serialization.load_pem_private_key(private_key_file_object.read(),
            backend = default_backend(), password = None)

with open("my_key_pub.pem", "rb") as public_key_file_object:
    my_public_key = serialization.load_pem_public_key(public_key_file_object.read(),
            backend=default_backend())

with open("server_key_pub.pem", "rb") as public_key_file_object:
    server_public_key = serialization.load_pem_public_key(public_key_file_object.read(),
            backend=default_backend())

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    message = "hello world my dear"
    sec = Security(my_private_key, my_public_key, server_public_key)
    secret = sec.updateEncryptor(message)
    s.sendall(secret)
