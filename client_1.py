import json
import random
import socket
from threading import Thread
from datetime import datetime
from aes import *
from sha import *
from rsa import *

name = 'Alica'
client_socket = socket.socket()
client_socket.connect(("127.0.0.1", 5000))

z = str(random.randint(5, 1000))
h = sha_256(z)
generation_key(512)
enc = new_rsa_encryption(z + name, 512)


_file_ = str({'hash': h,
          'ID': name,
          'enc': enc
          }).encode()

client_socket.send(_file_)
package = client_socket.recv(1024)
if z == package.decode():
    print('Bob идентифицирован!')



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
tread2.start()'''
