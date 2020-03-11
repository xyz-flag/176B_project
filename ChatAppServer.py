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

def broadcast_data(message):
    """ Sends a message to all sockets in the connection list. """
    # Send message to everyone, except the server.
    for sock in CONNECTION_LIST:
        if sock != SERVER_SOCKET:
            try:
                sock.send(message) # send all data at once
            except Exception as msg: # Connection was closed. Errors
                print(type(msg).__name__)
                sock.close()
                try:
                    CONNECTION_LIST.remove(sock)
                except ValueError as msg:
                    print("{}:{}".format(type(msg).__name__, msg))


CONNECTION_LIST = []
RECV_BUFFER = 4096 # Advisable to keep it as an exponent of 2
serect_key = generate_secret_key()

SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SERVER_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
SERVER_SOCKET.bind(("", PORT)) # empty addr string means INADDR_ANY

print("Listening...")
SERVER_SOCKET.listen(2) 

CONNECTION_LIST.append(SERVER_SOCKET)
print("Server started!")

while True:
    # Get the list sockets which are ready to be read through select
    READ_SOCKETS, WRITE_SOCKETS, ERROR_SOCKETS = select.select(CONNECTION_LIST, [], [])
    for SOCK in READ_SOCKETS: # New connection

        # Handle the case in which there is a new connection recieved through server_socket
        if SOCK == SERVER_SOCKET:
            SOCKFD, ADDR = SERVER_SOCKET.accept()
            CONNECTION_LIST.append(SOCKFD) # add socket descriptor
            # Adding \r to prevent message overlapping when another user
            # types it's message.
            print("\rClient ({0}, {1}) connected".format(ADDR[0], ADDR[1]))
            
        else: # Some incoming message from a client
            
            try: # Data recieved from client, process it
                DATA = SOCK.recv(RECV_BUFFER).decode()
                if DATA:
                    ADDR = SOCK.getpeername() # get remote address of the socket
                    # message = "\r[{}:{}]:".format(ADDR[0], ADDR[1], DATA.decode())
                    # cipher = symm_encryption(message,serect_key)
                    # broadcast_data(cipher.encode())
                    notification = "\rA message from[{}:{}]:".format(ADDR[0], ADDR[1])
                    # cipher = symm_encryption(notification,serect_key)
                    broadcast_data(notification.encode())
                    message = DATA
                    broadcast_data(message.encode())
            
            except Exception as msg: # Errors happened, client disconnected
                print(type(msg).__name__, msg)
                print("\rClient ({0}, {1}) disconnected.".format(ADDR[0], ADDR[1]))
                broadcast_message = "\rClient ({0}, {1}) is offline".format(ADDR[0], ADDR[1]).encode()
                broadcast_data(broadcast_message)
                SOCK.close()
                try:
                    CONNECTION_LIST.remove(SOCK)
                except ValueError as msg:
                    print("{}:{}.".format(type(msg).__name__, msg))
            continue

SERVER_SOCKET.close()

