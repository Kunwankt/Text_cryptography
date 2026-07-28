import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class AES256Cipher:
    BLOCK_SIZE = 16  # AES block size in bytes
    KEY_SIZE = 32  # 256 bits

    @staticmethod
    def generate_key():
        """Generate random AES-256 key"""
        return get_random_bytes(AES256Cipher.KEY_SIZE)

    @staticmethod
    def encrypt(plaintext, key):
        """
        Encrypt plaintext using AES-256 CBC
        :param plaintext: String to encrypt
        :param key: Bytes key (32 bytes)
        :return: Base64 encoded string (IV + ciphertext)
        """
        iv = get_random_bytes(AES256Cipher.BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext.encode('utf-8'), AES256Cipher.BLOCK_SIZE)
        ciphertext = cipher.encrypt(padded_data)
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext_b64, key):
        """
        Decrypt ciphertext using AES-256 CBC
        :param ciphertext_b64: Base64 encoded string (IV + ciphertext)
        :param key: Bytes key (32 bytes)
        :return: Decrypted plaintext string
        """
        data = base64.b64decode(ciphertext_b64)
        iv = data[:AES256Cipher.BLOCK_SIZE]
        ciphertext = data[AES256Cipher.BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return unpad(decrypted_data, AES256Cipher.BLOCK_SIZE).decode('utf-8')
