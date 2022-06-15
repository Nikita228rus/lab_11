import json
import socket
from rsa import *
from sha import *
from threading import Thread
from aes import *
from datetime import datetime


name = 'Bob'
client_socket = socket.socket()
client_socket.connect(("127.0.0.1", 5000))

package = eval(client_socket.recv(1024))
ID = package['ID']
enc = package['enc']
h = package['hash']

k = json.load(open('file_PKCS8.json', 'r'))
key = [k['SubjectPublicKeyInfo']['publicExponent'], k['SubjectPublicKeyInfo']['N']]
dec = decryption(enc, key)
z = dec[:len(dec) - len(ID)]
h_check = sha_256(z)
if h == h_check:
    client_socket.send(z.encode())

def sender():
    while True:
        message = input('Your message: ')
        client_socket.send(message.encode("utf-8"))


def receiver():
    while True:
        package = (client_socket.recv(1024))
        print(package)


'''tread1 = Thread(target=sender)
tread2 = Thread(target=receiver)
tread1.start()
tread2.start()
'''