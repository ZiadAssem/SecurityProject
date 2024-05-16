from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import rsa
import Cryptodome
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_final
from cryptography.hazmat.backends import default_backend
import base64




class RSAEncryption:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def generate_keys(self,username):
        (public_key, private_key) = rsa.newkeys(1024)
        with open('Keys/'+ username + '.pem', 'wb') as private_key_file:
            private_key_file.write(private_key.save_pkcs1('PEM'))
        
        self.public_key = public_key
        self.private_key = private_key
        return (public_key,private_key)

    def get_private_key(self,username):
        with open('Keys/'+ username + '.pem', 'rb') as private_key_file:
            private_key = rsa.PrivateKey.load_pkcs1(private_key_file.read())
            print("***Private Key***")
            print(private_key)
        return private_key
        

    def load_keys(self):
        try:
            with open('keys/public_key.pem', 'rb') as public_key_file:
                self.public_key = rsa.PublicKey.load_pkcs1(public_key_file.read())

            with open('keys/private_key.pem', 'rb') as private_key_file:
                self.private_key = rsa.PrivateKey.load_pkcs1(private_key_file.read())
        except FileNotFoundError:
            self.generate_keys()

    def encrypt(self, message):
        return rsa.encrypt(message.encode('ascii'), self.public_key)
    
    def encrypt_AES_key(self, AES_key,pub_key):
        print("********inside encrypt AES*********")
        print(pub_key)
        return rsa.encrypt(AES_key, pub_key)

    
    def decrypt(self, ciphertext, private_key):
        return rsa.decrypt(ciphertext, private_key)

    def rewind_public_key(self, key):
        key_str = key.replace("-----BEGIN RSA PUBLIC KEY-----\n", "").replace("-----END RSA PUBLIC KEY-----\n", "")

        # Decode the base64 encoded key string
        decoded_key_str = base64.b64decode(key_str)

        # Load the RSA key object
        rsa_key = RSA.import_key(decoded_key_str)

        return rsa_key
        
    def load_public_key_from_ascii(self, ascii_public_key):
        public_key = RSA.import_key(ascii_public_key)
        return public_key
            
    def sign_sha256(self, message):
        return rsa.sign(message.encode('ascii'), self.private_key, 'SHA-256')

    def verify_sha256(self, message, signature):
        try:
            return rsa.verify(message.encode('ascii'), signature, self.public_key) == 'SHA-256'
        except:
            return False


if __name__ == "__main__":
    rsa_encryption = RSAEncryption()

    message = input("Enter a message: ")
    ciphertext = rsa_encryption.encrypt(message)
    print(f"ciphertext: {ciphertext}")

    signature = rsa_encryption.sign_sha256(message)
    print(f"signature: {signature}")

    plaintext = rsa_encryption.decrypt(ciphertext)
    if plaintext:
        print(f"plaintext: {plaintext}")
    else:
        print("Decryption failed.")

    if rsa_encryption.verify_sha256(message, signature):
        print("Signature verified.")
    else:
        print("Signature verification failed.")
