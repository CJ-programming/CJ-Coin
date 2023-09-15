from Crypto.Cipher.AES import new, MODE_CBC, block_size
from Crypto.Util.Padding import pad

from database import init_peers

from ecdsa import BadSignatureError
from ecdsa.numbertheory import square_root_mod_prime
from ecdsa.ellipticcurve import Point
from ecdsa import SECP256k1
from ecdsa import SigningKey
from ecdsa import VerifyingKey
from ecdsa.util import number_to_string
from ecdsa.util import string_to_number

from os.path import exists
from os.path import getsize

from utils import create_file
from utils import write_json_file

def compress_verifying_key(verifying_key : VerifyingKey) -> bytes:
    x = verifying_key.pubkey.point.x()
    y = verifying_key.pubkey.point.y()

    e_x = number_to_string(x, SECP256k1.order) # encoded x
    return (b'\x03' + e_x) if y % 2 else (b'\x02' + e_x)

def uncompress_verifying_key(string: bytes, curve=SECP256k1) -> Point:
    is_even = string[:1] == b'\x02'
    x = string_to_number(string[1:])
    order = curve.order

    p = curve.curve.p()
    alpha = (pow(x, 3, p) + (curve.curve.a() * x) + curve.curve.b()) % p
    
    beta = square_root_mod_prime(alpha, p)

    if is_even == bool(beta & 1):
        y = p - beta

    else:
        y = beta

    point = Point(curve.curve, x, y, order)

    verifying_key = VerifyingKey.from_public_point(point, SECP256k1)

    return verifying_key

def create_private_key(key):
    if exists('private_key.bin') and getsize('private_key.bin') > 0:
        return

    with open('private_key.bin', 'wb') as f:
        private_key = SigningKey.generate(SECP256k1).to_string()

        cipher = new(key, MODE_CBC)

        ciphered_data = cipher.encrypt(pad(private_key, block_size))

        f.write(cipher.iv)
        f.write(ciphered_data)

def verify_sig(msg : bytes, sig : bytes, pub_key : VerifyingKey):
    try:
        pub_key.verify(sig, msg)    
        return True
    except BadSignatureError:
        pass

def init_all(node_id_b64_str):
    init_peers()

    create_file('config.json')
    create_file('node_id.json')

    config_json_data = {"services" :
        {"node_network" : True, 
        "node_getutxo" : True, 
        "node_bloom" : True, 
        "node_compact_filters" : True, 
        "node_network_limited" : False},

    "port" : 8133
    }

    node_id_json_data = {"node_id" : node_id_b64_str}

    if not getsize('config.json'):
        write_json_file(config_json_data, 'config.json')

    if not getsize('node_id.json'):
        write_json_file(node_id_json_data, 'node_id.json')