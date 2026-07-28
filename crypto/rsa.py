import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


class RSACipher:
    KEY_SIZE = 2048

    @staticmethod
    def generate_key_pair():
        """Generate RSA key pair (2048 bits)
        :return: tuple (private_key_pem, public_key_pem
        """
        key = RSA.generate(RSACipher.KEY_SIZE)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key.decode('utf-8'), public_key.decode('utf-8')

    @staticmethod
    def encrypt(plaintext, public_key_pem):
        """
        Encrypt plaintext using RSA public key
        :param plaintext: String to encrypt
        :param public_key_pem: PEM encoded public key string
        :return: Base64 encoded ciphertext
        """
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
        return base64.b64encode(ciphertext).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext_b64, private_key_pem):
        """
        Decrypt ciphertext using RSA private key
        :param ciphertext_b64: Base64 encoded ciphertext
        :param private_key_pem: PEM encoded private key string
        :return: Decrypted plaintext string
        """
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        ciphertext = base64.b64decode(ciphertext_b64)
        return cipher.decrypt(ciphertext).decode('utf-8')
