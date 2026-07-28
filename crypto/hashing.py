import hashlib


class HashGenerator:
    @staticmethod
    def sha256(data):
        """Generate SHA-256 hash
        :param data: String to hash
        :return: Hexadecimal hash string
        """
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def sha512(data):
        """Generate SHA-512 hash
        :param data: String to hash
        :return: Hexadecimal hash string
        """
        return hashlib.sha512(data.encode('utf-8')).hexdigest()

    @staticmethod
    def md5(data):
        """Generate MD5 hash (for educational purposes only)
        :param data: String to hash
        :return: Hexadecimal hash string
        """
        return hashlib.md5(data.encode('utf-8')).hexdigest()
