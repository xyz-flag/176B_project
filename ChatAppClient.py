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


def generate_secret_key():
    serect_key = get_random_bytes(16)
    return serect_key


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


def main():
    if len(sys.argv) < 3:
        print("Usage : python {0} hostname port".format(sys.argv[0]))
        sys.exit()

    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
    # serect_key = generate_secret_key()
    serect_key = b'\xdc\x8e@\xa2\x90\x9cF\xf6!\x18\xccK\xc2WWo'
    ivalue = b'\xdc\x8e@\xa2\x90\x9cF\xf6!\x18\xccK\xc2WWo'

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
                
                else: # print data
                    # iv_value = data[0]
                    # ct_value = data[1]
                    # print(type(iv_value), type(ct_value))
                    # cipher = json.dumps({'iv': iv_value, 'ciphertext': ct_value})
                    #print(symm_decryption(data[encryption_header:], serect_key), end = "")
                    if "offline" in data:
                        print(data)
                    else:
                        
                        encryption_header = data.index("{")
                        print(data[0:encryption_header])
                        print(symm_decryption(data[encryption_header:], serect_key), end = "")
            
            else: #user entered a message
                msg = sys.stdin.readline()
                print("\x1b[1A" + "\x1b[2K", end="") # erase last line
                cipher = symm_encryption(msg,serect_key)
                MASTER_SOCK.sendall(cipher.encode())

main()
