import random
import socket
from threading import Thread  # Подключили класс потока
from datetime import *





new_socket = socket.socket()  # Создаём объект сокета
new_socket.bind(('127.0.0.1', 5000))  # Привязываем наш объект к ip и порту
new_socket.listen(2)  # Указываем нашему сокету, что он будет слушать 2 других

print("Server is up now!")

conn1, add1 = new_socket.accept()
# сохраняем объект сокета нашего клиента и его адрес
print("First client is connected!")

conn2, add2 = new_socket.accept()
# аналогично со вторым клиентом
print("Second client is connected!")


def acceptor1():

    while True:

        a = conn1.recv(1024)

        conn2.send(a)


def acceptor2():

    while True:
        b = conn2.recv(1024)

        conn1.send(b)


tread1 = Thread(target=acceptor1)
tread2 = Thread(target=acceptor2)

tread1.start()
tread2.start()



