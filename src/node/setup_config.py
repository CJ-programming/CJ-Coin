import sys; sys.dont_write_bytecode = True

from base64 import b64encode

from crypto_utils import compress_verifying_key

from database import get_cursor
from database import write_db
from database import write_db_json

from ecdsa import SECP256k1
from ecdsa import SigningKey

from global_vars import seed_node_ipv4_address
from global_vars import seed_node_port
from global_vars import version

from json import dumps

from platform import uname

from requests import get
from requests import post
from requests import put

from secrets import randbelow

from time import time_ns

from utils import decrypt_file
from utils import get_net_addr
from utils import get_private_ipv4_address
from utils import read_json_file

def discover_nodes():
    nodes_json = get(f'http://{seed_node_ipv4_address}:{seed_node_port}/discover/nodes').json() # add potential dns seed for this
    return nodes_json
     
def send_version_message(net_addr, private_key, public_key_b64_str, request_type, port): # command is post, put, or delete
    # net_addr is version, services, ip_address, port and node_id

    json_file_data = read_json_file('config.json')

    services = json_file_data['services']

    private_ipv4_address = get_private_ipv4_address()

    timestamp = time_ns()

    addr_recv_json = {key : net_addr[key] for key in ('version', 'services', 'ipv4_address', 'port', 'node_id')}
    addr_from_json = {'services' : services, 'ipv4_address' : private_ipv4_address, 'port' : port}

    nonce = randbelow(2**32 - 1)

    system_info = uname()
    user_agent = f"{system_info.system}/{system_info.release} ({system_info.machine}; {system_info.node})"

    # start_height = get_col_last_value('blockchain.db', 'header', blockchain_cursor)
     
    start_height = 55

    relay = 1 # if zero, remote node will only send transctions relevant to the bloom filter sent by the connecitng node. (SPV)

    version_message_json = {'public_key' : public_key_b64_str, 'version' : version, 'services' : services, 'timestamp' : timestamp, 'addr_recv' : addr_recv_json,\
    'addr_from' : addr_from_json, 'nonce' : nonce, 'user_agent' : user_agent, 'start_height' : start_height, 'relay' : relay}

    message_bytes = dumps(version_message_json).encode('utf-8')
    signature = private_key.sign(message_bytes)
    signature_b64_str = b64encode(signature).decode('utf-8')

    version_message_json.update({'signature' : signature_b64_str})

    request = f"http://{net_addr['ipv4_address']}:{net_addr['port']}/discover/version"

    if request_type == 'post':
        response = post(request, json=version_message_json).json()
    
    elif request_type == 'put':
        response = put(request, json=version_message_json).json()

    return response

def boot_strap(key, port):
    private_key = SigningKey.from_string(decrypt_file('private_key.bin', key), SECP256k1)
    public_key = compress_verifying_key(private_key.get_verifying_key())

    public_key_b64_str = b64encode(public_key).decode('utf-8')

    nodes_json = discover_nodes()

    print('nodes_json:', nodes_json)    

    for net_addr in nodes_json:
        print()
        print('net_addr:', net_addr)
        print()

        if not net_addr == get_net_addr():
            response = send_version_message(net_addr, private_key, public_key_b64_str, 'post', port)

            print(response)

            net_addr.update({'services' : dumps(net_addr['services'])})

            if response == {'verack' : True}:
                write_db_json(get_cursor('peers.db'), 'peers_set', net_addr)

def update_network_status(key, port):
    nodes_json = discover_nodes()

    private_key = SigningKey.from_string(decrypt_file('private_key.bin', key), SECP256k1)
    public_key = compress_verifying_key(private_key.get_verifying_key())

    public_key_b64_str = b64encode(public_key).decode('utf-8')

    for net_addr in nodes_json:
        if not net_addr == get_net_addr():
            response = send_version_message(net_addr, private_key, public_key_b64_str, 'put', port)

            print(response)