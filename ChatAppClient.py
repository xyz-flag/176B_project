#!/usr/bin python3
""" TCP Client """

import socket
import select
import sys
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
import datetime


def generate_secret_key():
    serect_key = get_random_bytes(16)
    return serect_key


def symm_encryption(text, serect_key):
    #print(datetime.datetime.now().time())
    data = text.encode('ASCII')
    cipher = AES.new(serect_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher = json.dumps({"iv":iv, "ciphertext":ct})
    return cipher


def symm_decryption(ciphertext,serect_key):
    #print(datetime.datetime.now().time())
    try:
        b64 = json.loads(ciphertext)
        iv = b64decode(b64["iv"])
        ct = b64decode(b64["ciphertext"])
        cipher = AES.new(serect_key, AES.MODE_CBC, iv)
        text = unpad(cipher.decrypt(ct), AES.block_size)
        data = text.decode('ASCII')
    except ValueError:
        print("ValueError")
    else:
        return data


def main():
    if len(sys.argv) < 3:
        print("Usage : python {0} hostname port".format(sys.argv[0]))
        sys.exit()

    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
    # serect_key = generate_secret_key()
    serect_key_1 = b'\xdc\x8e@\xa2\x90\x9cF\xf6!\x18\xccK\xc2WWo'
    serect_key_2 = b'x}\x18\x86\xee+\xf2\x15\xadiBQ>\x80q\x93'


    MASTER_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    MASTER_SOCK.settimeout(200)

    # connect to remote host
    try:
        MASTER_SOCK.connect((HOST, PORT))
    except Exception as msg:
        print(type(msg).__name__)
        print("Unable to connect")
        sys.exit()

    print("Connected to remote host. Start sending messages")
    while True:
        SOCKET_LIST = [sys.stdin, MASTER_SOCK]
        # Get the list sockets which are readable
        READ_SOCKETS, WRITE_SOCKETS, ERROR_SOCKETS = select.select(SOCKET_LIST, [], [])

        for every_sock in READ_SOCKETS: #incoming message from remote server
            if every_sock == MASTER_SOCK: #message is for this client
                data = every_sock.recv(4096).decode()

                if not data:  #exit
                    print("\nDisconnected from chat server")
                    sys.exit()

                else:
                    if "offline" in data:
                        print(data)
                    else:
                        print(data)
                        print(type(data))
                        #encryption_header = data.index('{')
                        print (datetime.datetime.now().time())
                        #print( (data[0:encryption_header]))
                        #print string about A message from[127.0.0.1:63849]:

                        #print(symm_decryption(data[encryption_header:], serect_key_2), end = "")

                        #如果print这个result，就会出现我截屏里面的第一种的问题
                        #result = symm_decryption(data[data.index('{'):], serect_key_2)

                        #只print这个可以
                        print("hhhhh")


            else: #user entered a message
                msg = sys.stdin.readline()
                print(datetime.datetime.now().time())
                print("\x1b[1A" + "\x1b[2K", end="") # replace the input value


                cipher = symm_encryption(msg,serect_key_1)
                MASTER_SOCK.sendall(cipher.encode())

main()
