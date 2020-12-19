import selectors
import socket
from encrypt3 import Security
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

HOST = '0.0.0.0'
PORT = 50007


with open("server_key.pem", "rb") as private_key_file_object:
    server_private_pem = private_key_file_object.read()

with open("server_key_pub.pem", "rb") as public_key_file_object:
    server_public_pem = public_key_file_object.read()


def accept(sock, mask):
    conn, addr = sock.accept()
    print("conected by ", addr)
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, read)

def read(conn, mask):
    data = conn.recv(10000)
    if data:
        sec = Security(server_private_pem, server_public_pem)
        message = sec.decrypt_message(data)
        print("recovered", message)
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
