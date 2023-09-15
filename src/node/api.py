import sys; sys.dont_write_bytecode = True

from argparse import ArgumentParser

from base64 import b64encode
from base64 import b64decode

from crypto_utils import compress_verifying_key
from crypto_utils import create_private_key
from crypto_utils import uncompress_verifying_key
from crypto_utils import verify_sig
from crypto_utils import init_all

from database import get_col_last_value
from database import get_cursor
from database import read_db
from database import read_db_json
from database import update_db
from database import write_db

from ecdsa import SECP256k1
from ecdsa import SigningKey

from flask import Flask
from flask import jsonify
from flask import request

from getpass import getpass

from global_vars import version

from hashlib import sha256

from json import dumps
from json import loads

from os.path import exists
from os.path import getsize

from setup_config import boot_strap 
from setup_config import update_network_status

from utils import create_file
from utils import create_password
from utils import decrypt_file
from utils import exclude_keys
from utils import get_net_addr
from utils import get_private_ipv4_address
from utils import write_json_file
from utils import read_json_file
from utils import verify_password

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify('pong')

@app.route('/discover/nodes', methods=['GET'])
def discover_nodes_get():
    peer_dict_keys = ('version', 'services', 'ipv4_address', 'port', 'node_id')

    peers_db_data_json = read_db_json(get_cursor('peers.db'), 'peers_set', '*', 'services')

    print('peers_db_data_json:', peers_db_data_json)

    json_file_data = read_json_file('config.json')

    services = json_file_data["services"]
    port = json_file_data["port"]

    node_id = read_json_file('node_id.json')["node_id"]

    json_nodes = [{key : value for key, value in zip(peer_dict_keys, (version, services, get_private_ipv4_address(), port, node_id))}]
    json_nodes += peers_db_data_json

    return jsonify(json_nodes)

@app.route('/discover/version', methods=['POST', 'PUT'])
def version_verack():
    message = request.json

    verack_status = {'verack' : False}

    connecting_ipv4_address = request.remote_addr

    if message['addr_from']['ipv4_address'] != connecting_ipv4_address:
        return jsonify({'verack' : False})
    
    peers_columns = ('version', 'services', 'ipv4_address', 'port', 'node_id')

    signed_message = dumps(exclude_keys(message, {'signature'})).encode('utf-8')
    signature_bytes = b64decode(message['signature'])

    public_key_bytes = b64decode(message['public_key'])
    verifying_key = uncompress_verifying_key(public_key_bytes)

    node_id = sha256(sha256(public_key_bytes).digest()).digest()
    node_id_b64_str = b64encode(node_id).decode('utf-8')

    if verify_sig(signed_message, signature_bytes, verifying_key):
        nodes_db_reference = read_db(get_cursor('peers.db'), 'peers_set WHERE node_id = ?', '*', (node_id_b64_str,)).fetchone()

        data_to_write_db = (message['version'], dumps(message['services']), connecting_ipv4_address, message['addr_from']['port'], node_id_b64_str)

        if nodes_db_reference:
            if node_id_b64_str == nodes_db_reference[-1]:
                # nodes_db_reference[-1] is node_id column of reference

                if request.method == 'PUT':
                    update_db(get_cursor('peers.db'), 'peers_set', 'node_id', data_to_write_db + (node_id_b64_str,))
                    verack_status = {'verack' : True}
            
        elif request.method == 'POST':
            write_db(get_cursor('peers.db'), 'peers_set', peers_columns, data_to_write_db)
            verack_status = {'verack' : True}
    
    return jsonify(verack_status)
if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-b', action='store_true')
    parser.add_argument('-r', action='store_true')
    parser.add_argument('-u', action='store_true')

    args = parser.parse_args()

    file_password = create_password()
    
    while True:
        password = getpass('Enter password: ').encode('utf-8')
        key = verify_password(password)

        if key: # if key is not None / was verified
            break
            
        print('Incorrect password, please try again')

    create_private_key(key)

    private_key = SigningKey.from_string(decrypt_file('private_key.bin', key), SECP256k1)
    verifying_key = private_key.get_verifying_key()

    node_id = sha256(sha256(compress_verifying_key(verifying_key)).digest()).digest()

    node_id_b64_str = b64encode(node_id).decode('utf-8')

    init_all(node_id_b64_str)

    bootstrap_status = read_json_file('bootstrap.json')['bootstrap']

    port = read_json_file('config.json')['port']

    if args.b:
        if not bootstrap_status:
            print('Bootstrapping...')
            boot_strap(key, port)
            write_json_file({"bootstrap" : True}, 'bootstrap.json')
        else:
            print('Node already bootstrapped')

    bootstrap_status = read_json_file('bootstrap.json')["bootstrap"]

    if bootstrap_status:
        if args.r:
            private_ipv4_address = get_private_ipv4_address()
            app.run(private_ipv4_address, port)
        
        if args.u:
            print('Updating network status...')
            update_network_status(key, port)
    else:
        print("Node isn't bootstrapped, try using the -b flag")