import selectors
import socket
from encrypt2 import Security
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

HOST = '0.0.0.0'
PORT = 50007


with open("my_key_pub.pem", "rb") as public_key_file_object:
    my_public_key = serialization.load_pem_public_key(public_key_file_object.read(),
            backend=default_backend())

with open("server_key.pem", "rb") as private_key_file_object:
    server_private_key = serialization.load_pem_private_key(private_key_file_object.read(),
            backend = default_backend(), password = None)

with open("server_key_pub.pem", "rb") as public_key_file_object:
    server_public_key = serialization.load_pem_public_key(public_key_file_object.read(),
            backend=default_backend())

def accept(sock, mask):
    conn, addr = sock.accept()
    print("conected by ", addr)
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, read)

def read(conn, mask):
    data = conn.recv(1000)
    if data:
        sec = Security(server_private_key, server_public_key, my_public_key)
        print("recovered", sec.updateDecryptor(data))
        print(data)
    else:
        sel.unregister(conn)
        conn.close()

sock = socket.socket()
sock.bind((HOST, PORT))
sock.listen(100)
sock.setblocking(False)

sel = selectors.DefaultSelector()
sel.register(sock, selectors.EVENT_READ, accept)

while True:
    events = sel.select()
    for key, mask in events:
        callback = key.data
        callback(key.fileobj, mask)
