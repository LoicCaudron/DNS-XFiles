import hashlib
import base64

def md5(f):
    hash_md5 = hashlib.md5()
    for chunk in iter(lambda: f.read(4096), b""):
        hash_md5.update(chunk)
    return hash_md5.hexdigest()

def encode_base32(data):
    if isinstance(data, str):
        # If the data is a character string, encode it in base32
        encoded_data = base64.b32encode(data.encode('utf-8')).decode('utf-8')
        return encoded_data
    elif isinstance(data, bytes):
        # If the data is in bytes (for example, from a file), encode it in base32
        encoded_data = base64.b32encode(data).decode('utf-8')
        return encoded_data
    else:
        raise ValueError("Data type not supported. Please provide string or binary data.")

def decode_base32(encoded_data):
    try:
        if isinstance(encoded_data, str):
            encoded_data = encoded_data.encode('utf-8')
        
        decoded_data = base64.b32decode(encoded_data)
        return decoded_data
    except base64.binascii.Error as e:
        raise ValueError("Invalid base32 encoded data: {}".format(str(e)))