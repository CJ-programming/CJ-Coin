from Crypto.Cipher.AES import new, MODE_CBC, block_size
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

from getpass import getpass

from global_vars import version

from hashlib import sha256

from json import dump
from json import load

from os.path import getsize
from os.path import exists

from socket import gethostname
from socket import gethostbyname

from struct import pack
from struct import unpack

from sys import stdout

from time import sleep

def read_json_file(file):
    with open(file, 'r') as f:
        json_data = load(f)
        return json_data

def create_file(file_name):
    try:
        with open(file_name, 'x'): 
            pass
    except FileExistsError:
        pass

def write_json_file(data_dict, file):
    with open(file, 'w') as f:
        dump(data_dict, f)

def get_private_ipv4_address():
    hostname = gethostname()
    private_ip_address = gethostbyname(hostname)

    return private_ip_address

def get_net_addr():
    json_file_data = read_json_file('config.json')

    ipv4_address = get_private_ipv4_address()
    services = json_file_data['services']
    port = json_file_data['port']

    net_addr = {'version' : version, 'ipv4_address' : ipv4_address, 'services' : services, 'port' : port}

    return net_addr

def prefix_length(data : bytes) -> bytes:
    len_data = len(data).to_bytes(1, 'little') + data
    return len_data

def get_prefix_data(data : bytes) -> list:
    values = []
    offset = 0

    while offset < len(data):
        length = data[offset]
        offset += 1
        value = data[offset:offset+length]
        offset += length
        values.append(value)

    return values

def verify_password(password):
    with open('key.bin', 'rb') as f:
        file_data = f.read()
        key_hash, salt, salt_pbkdf2 = get_prefix_data(file_data)

    salt_password = password + salt

    for pepper in range(2**32):
        pepper_bytes = pepper.to_bytes(2, byteorder='big')
        full_password = salt_password + pepper_bytes

        key = PBKDF2(full_password, salt_pbkdf2)

        hash_guess = sha256(sha256(key).digest()).digest()

        if hash_guess == key_hash:
            return key
 
def decrypt_file(file, key):
    with open(file, 'rb') as f:
        iv = f.read(16)
        data = f.read()

    cipher = new(key, MODE_CBC, iv)
    decrypt_data = unpad(cipher.decrypt(data), block_size)

    return decrypt_data

def create_password():
    if exists('key.bin') and getsize('key.bin') > 0:
        return

    with open('key.bin', 'wb') as f:
        password = getpass('Create password: ').encode('utf-8')

        salt = get_random_bytes(32)
        salt_pbkdf2 = get_random_bytes(32)

        pepper = get_random_bytes(2)

        salt_pepper_password = password + salt + pepper

        key = PBKDF2(salt_pepper_password, salt_pbkdf2)

        password_hash = sha256(sha256(key).digest()).digest()

        f.write(prefix_length(password_hash))
        f.write(prefix_length(salt))
        f.write(prefix_length(salt_pbkdf2))

        return password
    
def exclude_keys(d : dict, keys : set) -> dict:
    return {x: d[x] for x in d if x not in keys}