import socket 
from subprocess import Popen, PIPE
from encrypt3 import Security
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

HOST = 'localhost'
PORT = 50007


with open("my_key.pem", "rb") as private_key_file_object:
    my_private_pem = private_key_file_object.read()

with open("my_key_pub.pem", "rb") as public_key_file_object:
    my_public_pem = public_key_file_object.read()

with open("server_key_pub.pem", "rb") as public_key_file_object:
    server_public_pem = public_key_file_object.read()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    message = "hello world my dear"
    sec = Security(my_private_pem, my_public_pem, server_public_pem, 'lucas')
    secret = sec.encrypt_message(message)

    s.sendall(secret)
