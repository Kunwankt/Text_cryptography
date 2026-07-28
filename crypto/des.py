import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class DESCipher:
    BLOCK_SIZE = 8  # DES block size in bytes
    KEY_SIZE = 8  # 64 bits (56 effective)

    @staticmethod
    def generate_key():
        """Generate random DES key"""
        return get_random_bytes(DESCipher.KEY_SIZE)

    @staticmethod
    def encrypt(plaintext, key):
        """
        Encrypt plaintext using DES CBC
        :param plaintext: String to encrypt
        :param key: Bytes key (8 bytes)
        :return: Base64 encoded string (IV + ciphertext)
        """
        iv = get_random_bytes(DESCipher.BLOCK_SIZE)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_data = pad(plaintext.encode('utf-8'), DESCipher.BLOCK_SIZE)
        ciphertext = cipher.encrypt(padded_data)
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext_b64, key):
        """
        Decrypt ciphertext using DES CBC
        :param ciphertext_b64: Base64 encoded string (IV + ciphertext)
        :param key: Bytes key (8 bytes)
        :return: Decrypted plaintext string
        """
        data = base64.b64decode(ciphertext_b64)
        iv = data[:DESCipher.BLOCK_SIZE]
        ciphertext = data[DESCipher.BLOCK_SIZE:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return unpad(decrypted_data, DESCipher.BLOCK_SIZE).decode('utf-8')
