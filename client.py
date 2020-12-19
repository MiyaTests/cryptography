import socket 
from subprocess import Popen, PIPE
from encrypt import Security

HOST = 'localhost'
PORT = 50007
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    message = "hello world my dear"
    sec = Security()
    secret = sec.updateEncryptor(message)
    s.sendall(secret)
