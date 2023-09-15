from base64 import b64encode

from Crypto.Cipher.AES import new, MODE_CBC, block_size
from Crypto.Util.Padding import unpad

from hashlib import sha256

def decrypt_file(file, key):
    with open(file, 'rb') as f:
        iv = f.read(16)
        data = f.read()

    cipher = new(key, MODE_CBC, iv)
    decrypt_data = unpad(cipher.decrypt(data), block_size)

    return decrypt_data

def str_encode_b64(data_bytes : bytes) -> str:
    b64_str = b64encode(data_bytes).decode('utf-8')
    return b64_str

def gen_check_sum(data : bytes) -> bytes:
    checksum = sha256(sha256(data).digest()).hexdigest()

    data_checksum_json = {'checksum' : checksum, 'data' : data}

    return data_checksum_json