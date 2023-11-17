import sys; sys.dont_write_bytecode = True

from crypto_utils import compress_verifying_key

from database import get_column_names_db
from database import get_col_last_value
from database import get_cursor
from database import init_blockchain
from database import init_peers
from database import init_utxos
from database import write_db
from database import write_db_json

from ecdsa import SECP256k1
from ecdsa import SigningKey

from global_vars import version

from json import dumps
from json import loads

from network import discover_nodes
from network import update_peers

from os.path import getsize

from platform import uname

from requests import get
from requests import post
from requests import put

from secrets import randbelow

from statistics import mode

from time import time

from utils import create_file
from utils import decrypt_file
from utils import get_net_addr
from utils import get_private_ipv4_address
from utils import read_json_file
from utils import write_json_file

def send_version_message(net_addr, private_key, public_key_b64_str, request_type, port): # command is post, put, or delete
    # net_addr is version, services, ip_address, and port

    services = read_json_file('config.json')['services']

    private_ipv4_address = get_private_ipv4_address()

    timestamp = time()

    addr_recv_json = {key : net_addr[key] for key in ('services', 'ipv4_address', 'port')}
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
    signature_hex = signature.hex()

    version_message_json.update({'signature' : signature_hex})

    request = f"http://{net_addr['ipv4_address']}:{net_addr['port']}/discover/version"

    if request_type == 'post':
        response = post(request, json=version_message_json).json()
    
    elif request_type == 'put':
        response = put(request, json=version_message_json).json()

    return response

def update_network_status(key, port):
    nodes_json = update_peers()

    private_key = SigningKey.from_string(decrypt_file('private_key.bin', key), SECP256k1)
    public_key = compress_verifying_key(private_key.get_verifying_key())

    public_key_b64_str = public_key.hex()

    for net_addr in nodes_json:
        if not net_addr == get_net_addr():
            response = send_version_message(net_addr, private_key, public_key_b64_str, 'put', port)

            print(response)

def boot_strap(key, port):
    private_key = SigningKey.from_string(decrypt_file('private_key.bin', key), SECP256k1)
    public_key = compress_verifying_key(private_key.get_verifying_key())

    public_key_hex = public_key.hex()

    nodes_json = discover_nodes()

    start_block_height = get_col_last_value(get_cursor('blockchain.db'), 'header', 'height')

    if start_block_height == None:
        start_block_height = 0

    responses = []

    for net_addr in nodes_json:
        updated_blocks_response = get(f"http://{net_addr['ipv4_address']}:{net_addr['port']}/discover/blockchain/headers/{start_block_height}/-1").json()
        updated_txs_response = get(f"http://{net_addr['ipv4_address']}:{net_addr['port']}/discover/blockchain/txs/{start_block_height}/-1").json()

        responses.append(dumps((updated_blocks_response, updated_txs_response)))

        if not net_addr == get_net_addr():
            response = send_version_message(net_addr, private_key, public_key_hex, 'post', port)

            net_addr.update({'services' : dumps(net_addr['services']), 'status' : 1})            

            if response == {'verack' : True}:
                write_db_json(get_cursor('peers.db'), 'peers_set', net_addr)

    updated_blocks, updated_txs = loads(mode(responses))

    header_cols = get_column_names_db(get_cursor('blockchain.db'), 'header')
    txs_cols = get_column_names_db(get_cursor('blockchain.db'), 'txs')

    for block, tx in zip(updated_blocks, updated_txs):
        write_db(get_cursor('blockchain.db'), 'header', header_cols, block)
        write_db(get_cursor('blockchain.db'), 'txs', txs_cols, tx)

def init_all(node_id_hex):
    init_blockchain()
    init_peers()
    init_utxos()

    create_file('config.json')
    create_file('bootstrap.json')
    create_file('node_id.json')

    config_json_data = {"services" :
        {"node_network" : True, 
        "node_getutxo" : True, 
        "node_bloom" : True, 
        "node_compact_filters" : True, 
        "node_network_limited" : False},

    "port" : 8233
    }

    bootstrap_json_data = {"bootstrap" : False}

    node_id_json_data = {"node_id" : node_id_hex}

    if not getsize('config.json'):
        write_json_file(config_json_data, 'config.json')
    
    if not getsize('bootstrap.json'):
        write_json_file(bootstrap_json_data, 'bootstrap.json')
    
    if not getsize('node_id.json'):
        write_json_file(node_id_json_data, 'node_id.json')