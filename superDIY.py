import json
import secrets
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from random import choice

#MODE_CBC
#iv (bytes)
##the Initialization Vector.
##A piece of data unpredictable to adversaries.
##It is as long as the block size.

def generate_secret_key(length):
    b_length = 0.125 * length
    serect_key = get_random_bytes(int(b_length))
    return serect_key



def symm_encryption(text, serect_key):
    cipher = AES.new(serect_key, AES.MODE_CBC)
    data = text.encode('ASCII')
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher = json.dumps({'iv':iv, 'ciphertext':ct})
    #print(cipher)
    #print(type(cipher))
    return cipher


def symm_decryption(ciphertext,serect_key):
    try:
        print(serect_key)
        print(type(serect_key))
        print(ciphertext)
        print(type(ciphertext))
        b64 = json.loads(ciphertext)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(serect_key, AES.MODE_CBC, iv)
        text = unpad(cipher.decrypt(ct), AES.block_size)
        data = text.decode('ASCII')
        print("The message was: ", data)
    except ValueError:
        print("Incorrect decryption")
    except KeyError:
        print("Incorrect decryption key")
    else:
        return data



if __name__ == '__main__':
    print('TESTING ENCRYPTION')
    length = [128,192,256]
    l = choice(length)
    msg = input('Message...: ')
    #serect_key = generate_secret_key(l)
    serect_key = b'x}\x18\x86\xee+\xf2\x15\xadiBQ>\x80q\x93'

    # ivalue = b'\xdc\x8e@\xa2\x90\x9cF\xf6!\x18\xccK\xc2WWo'
    # print (type(ivalue))

    #print(serect_key)
    cipher = symm_encryption(msg,serect_key)
    print(cipher)
    print(type(cipher))
    print('\nTESTING DECRYPTION')
    #cipher = "vHaM0q1KHbgZ0CwRRYEtZw=="
    #serect_key = b'\xf4\xbc\x8b\x85\xd3o\xfeGv\x92\x94\x1e\xbb\x9c\xf3F'
    symm_decryption(cipher,serect_key)
    #print(secrets.randbits(128))
