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
    #command line arguments checking
    if len(sys.argv) < 3:
        print("Usage : python {0} hostname port".format(sys.argv[0]))
        sys.exit()

    #basic set up for connection and value ruquired
    #========================
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])

    serect_key_1 = b'\xdc\x8e@\xa2\x90\x9cF\xf6!\x18\xccK\xc2WWo'
    serect_key_2 = b'x}\x18\x86\xee+\xf2\x15\xadiBQ>\x80q\x93'

    MASTER_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    MASTER_SOCK.settimeout(200)
    #========================


    # go conection with connected signal
    #========================
    try:
        MASTER_SOCK.connect((HOST, PORT))
    except Exception as msg:
        print(type(msg).__name__)
        print("Unable to connect")
        sys.exit()
    print("Connected to remote host. Start sending messages")
    #========================


    # baby go!
    #========================
    while True:
        SOCKET_LIST = [sys.stdin, MASTER_SOCK]
        READ_SOCKETS, WRITE_SOCKETS, ERROR_SOCKETS = select.select(SOCKET_LIST, [], []) #set up list

        for sock in READ_SOCKETS: #received msg from server
            if sock == MASTER_SOCK:
                data = sock.recv(4096).decode()

                if not data:  # |- _ -!| we don't talk anymore like we used to be
                    print("\nDisconnected from chat server")
                    sys.exit() # goodbye my almost lover

                else:
                    if "offline" in data:
                        print(data)

                    #===================================
                    # decrypt received sock to plaintext
                    else:
                        #print(data)
                        #print(type(data))
                        encryption_header = data.index('{') # { is the divider for header and value
                        print (datetime.datetime.now().time()) #show time for comparison
                        print( (data[0:encryption_header])) #print string about A message from[127.0.0.1:63849]:

                        j = 2   #personal trick to make switch two modes for tcp easiser, value decided by programmer
                        if j == 1:
                            print(symm_decryption(data[data.index('{'):], serect_key_1)) # i^3^i
                        elif j == 2:
                            print(symm_decryption(data[data.index('{'):], serect_key_2)) # i^3^i
                    #====================================


            # input plaintext
            #client send and encrypt messages
            #show time, send tag and msg
            #sendall
            #========================
            else:
                msg = sys.stdin.readline()
                print("\x1b[1A" + "\x1b[2K") # erase the orignal input to for better looking
                print(datetime.datetime.now().time(), "send: ")
                print(msg)
                cipher = symm_encryption(msg,serect_key_1) # serect_key_1 never need to change
                MASTER_SOCK.sendall(cipher.encode())
            #========================


main()
