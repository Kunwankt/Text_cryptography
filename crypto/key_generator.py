import base64
import random
import string
from Crypto.Random import get_random_bytes


class KeyGenerator:
    @staticmethod
    def generate_aes_key():
        """Generate random AES-256 key
        :return: Base64 encoded key string
        """
        key = get_random_bytes(32)
        return base64.b64encode(key).decode('utf-8')

    @staticmethod
    def generate_des_key():
        """Generate random DES key
        :return: Base64 encoded key string
        """
        key = get_random_bytes(8)
        return base64.b64encode(key).decode('utf-8')

    @staticmethod
    def generate_password(length=16):
        """Generate secure random password
        :param length: Password length (default 16)
        :return: Random password string
        """
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    @staticmethod
    def check_password_strength(password):
        """
        Check password strength
        :param password: Password to check
        :return: dict with score (0-100) and level
        """
        score = 0
        length = len(password)

        if length >= 8:
            score += 20
        if length >= 12:
            score += 10
        if length >= 16:
            score += 10

        if any(c.islower() for c in password):
            score += 10
        if any(c.isupper() for c in password):
            score += 10
        if any(c.isdigit() for c in password):
            score += 15
        if any(c in string.punctuation for c in password):
            score += 15

        if length >= 12 and any(c.islower() for c in password) and any(
                c.isupper() for c in password) and any(c.isdigit() for c in password) and any(
            c in string.punctuation for c in password):
            score += 10

        level = "Very Weak"
        if score >= 30:
            level = "Weak"
        if score >= 50:
            level = "Medium"
        if score >= 70:
            level = "Strong"
        if score >= 90:
            level = "Very Strong"

        return {"score": score, "level": level}
