#!/usr/bin python3
""" A simple chat TCP server """
import socket
import select
import json
from base64 import b64encode
from base64 import b64decode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

PORT = 11223
serect_key_1 = b'\xdc\x8e@\xa2\x90\x9cF\xf6!\x18\xccK\xc2WWo'
serect_key_2 = b'x}\x18\x86\xee+\xf2\x15\xadiBQ>\x80q\x93'

#=====================================================
# not being used when really test the time delay
#
# def generate_secret_key():
#     serect_key = get_random_bytes(16)
#     return serect_key
#=====================================================

def symm_encryption(text, serect_key):
    data = text.encode('ASCII')
    cipher = AES.new(serect_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher = json.dumps({"iv":iv, "ciphertext":ct})
    return cipher


def symm_decryption(ciphertext,serect_key):
    b64 = json.loads(ciphertext)
    iv = b64decode(b64["iv"])
    ct = b64decode(b64["ciphertext"])
    cipher = AES.new(serect_key, AES.MODE_CBC, iv)
    text = unpad(cipher.decrypt(ct), AES.block_size)
    data = text.decode('ASCII')
    return data

# send msg to all clients include sender
def broadcast_data(message):
    for sock in CONNECTION_LIST:
        if sock != SERVER_SOCKET: #yeah, i want you
            try:
                sock.send(message)
            except Exception as msg: # Connecting failed
                print(type(msg).__name__)
                sock.close()
                try:
                    CONNECTION_LIST.remove(sock)
                except ValueError as msg:
                    print("{}:{}".format(type(msg).__name__, msg))


#basic value and environment setup for receiving and sending
CONNECTION_LIST = []
SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SERVER_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
SERVER_SOCKET.bind(("", PORT))

#UI setup
#============================================
print("Listening...")
SERVER_SOCKET.listen(2)

CONNECTION_LIST.append(SERVER_SOCKET)
print("Server started!")
#============================================


while True:
    READ_SOCKETS, WRITE_SOCKETS, ERROR_SOCKETS = select.select(CONNECTION_LIST, [], [])# setup list

    #establish new connection
    for SOCK in READ_SOCKETS:

        #receive msg from client
        #try attempt
        #getpeername
        #process data --> 1. direct send
        #             --> 2. decrypt, encrypt
        #===========================================
        if SOCK != SERVER_SOCKET:
            try:
                DATA = SOCK.recv(4096).decode()
                if DATA:
                    ADDR = SOCK.getpeername()
                    notification = "\rA message from[{}:{}]:".format(ADDR[0], ADDR[1])
                    message = DATA
                    i =1
                    if i == 1:# mode 2
                        new_value = symm_decryption(message, serect_key_1)
                        message = symm_encryption(new_value,serect_key_2)
                    broadcast_data((notification+message).encode())
        #============================================


            except Exception as msg: # disconnet as the sinal for error
                print(type(msg).__name__, msg)
                disconnet = "\rClient ({0}, {1}) disconnected.".format(ADDR[0], ADDR[1])
                print(disconnet)
                broadcast_data(disconnet)
                SOCK.close()

                try:
                    print("hello, this is second try")
                    CONNECTION_LIST.remove(SOCK)
                except ValueError as msg:
                    print("{}:{}.".format(type(msg).__name__, msg))

            continue

        else: # connection connected
            SOCKFD, ADDR = SERVER_SOCKET.accept()
            CONNECTION_LIST.append(SOCKFD)
            print("\rClient ({0}, {1}) connected".format(ADDR[0], ADDR[1]))

SERVER_SOCKET.close()
