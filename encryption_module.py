from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

from secrets import token_bytes


def encrypt(msg, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode("ascii"))
    return nonce , ciphertext , tag

def decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    plaintext2 =cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode("ascii")
    except:
        return False

def decrypt_ciphertext(ciphertext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    try:
        plaintext = cipher.decrypt(ciphertext)
        print(plaintext)
        # Unpad the plaintext if necessary
        plaintext = unpad(plaintext, AES.block_size)
        return plaintext.decode("utf-8")
    except Exception as e:
        print("Decryption error:", e)
        return None
    
def generate_AES_key():
    return token_bytes(16)

