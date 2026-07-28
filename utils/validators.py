import base64


def validate_aes_key(key_b64):
    """Validate AES-256 key
    :param key_b64: Base64 encoded key
    :return: bool, error message (if any)
    """
    try:
        key = base64.b64decode(key_b64)
        if len(key) != 32:
            return False, "AES key must be 32 bytes (256 bits) long"
        return True, None
    except Exception as e:
        return False, "Invalid AES key format"


def validate_des_key(key_b64):
    """Validate DES key
    :param key_b64: Base64 encoded key
    :return: bool, error message (if any)
    """
    try:
        key = base64.b64decode(key_b64)
        if len(key) != 8:
            return False, "DES key must be 8 bytes (64 bits) long"
        return True, None
    except Exception as e:
        return False, "Invalid DES key format"


def validate_not_empty(data, field_name):
    """Validate that data is not empty
    :param data: Data to check
    :param field_name: Name of field for error message
    :return: bool, error message (if any)
    """
    if not data or data.strip() == "":
        return False, f"{field_name} cannot be empty"
    return True, None
