from argparse import ArgumentParser

from crypto_utils import adjust_nbits
from crypto_utils import compress_verifying_key
from crypto_utils import create_private_key
from crypto_utils import update_block_reward
from crypto_utils import uncompress_verifying_key
from crypto_utils import verify_sig

from database import del_db
from database import get_col_last_value
from database import get_column_names_db
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

from global_vars import start_nbits
from global_vars import version

from hashlib import sha256

from json import dumps

from network import send_ping
from network import update_peers

from requests import post

from setup_config import init_all
from setup_config import update_network_status

from utils import create_password
from utils import decrypt_file
from utils import exclude_keys
from utils import get_private_ipv4_address
from utils import read_json_file
from utils import verify_password

from verification import verify_tx
from verification import verify_block

mempool = []
utxos_mempool = []

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
    
@app.route('/ping', methods=['GET'])
def ping_get():
    return jsonify('pong')

@app.route('/version', methods=['GET'])
def get_version_view():
    return jsonify(version)

@app.route('/prev_hash', methods=['GET'])
def get_prev_hash_view():
    prev_hash = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'hash')

    if not prev_hash: # checks if prev_hash is b''
        return jsonify((b'\x00'*32).hex())
 
    return jsonify(prev_hash)

@app.route('/nbits', methods=['GET'])
def get_nbits_view():
    prev_nbits = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'nbits')
    height = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'height')

    if not prev_nbits:
        prev_nbits = start_nbits

    if height and (height + 1) % 3 == 0:
        prev_third_timestamp = read_db(get_cursor('blockchain.db'), 'header DESC LIMIT 1 OFFSET 2', ('timestamp',), single_value=True).fetchone()
        prev_timestamp = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'timestamp')

        time_taken = prev_timestamp - prev_third_timestamp

        nbits = adjust_nbits(prev_nbits, time_taken)
    else:
        nbits = prev_nbits

    return jsonify(nbits)

@app.route('/mempool', methods=['GET'])
def get_mempool():
    return jsonify(mempool)

@app.route('/block_reward', methods=['GET'])
def get_block_reward():
    updated_block_reward = update_block_reward()

    return jsonify(updated_block_reward)

@app.route('/discover/nodes', methods=['GET'])
def discover_nodes_get():
    peer_dict_keys = ('version', 'services', 'ipv4_address', 'port', 'node_id', 'status')

    peers_db_data_json = read_db_json(get_cursor('peers.db'), 'peers_set', '*', 'services')

    up_peers = []

    for peer in peers_db_data_json:
        if send_ping(peer['ipv4_address'], peer['port']):
            update_db(get_cursor('peers.db'), 'peers_set', 'node_id', (peer['version'], dumps(peer['services']), peer['ipv4_address'], peer['port'], peer['node_id'], 1), peer['node_id'])
            up_peers.append(peer)
        else:
            update_db(get_cursor('peers.db'), 'peers_set', 'node_id', (peer['version'], dumps(peer['services']), peer['ipv4_address'], peer['port'], peer['node_id'], 0), peer['node_id'])

    json_file_data = read_json_file('config.json')

    services = json_file_data["services"]
    port = json_file_data["port"]

    node_id = read_json_file('node_id.json')["node_id"]

    json_nodes = [{key : value for key, value in zip(peer_dict_keys, (version, services, get_private_ipv4_address(), port, node_id, 1))}]

    json_nodes += up_peers

    return jsonify(json_nodes)

@app.route('/discover/version', methods=['POST', 'PUT'])
def version_verack():
    message = request.json

    verack_status = {'verack' : False}

    connecting_ipv4_address = request.remote_addr

    if message['addr_from']['ipv4_address'] != connecting_ipv4_address:
        return jsonify({'verack' : False})
    
    signed_message = dumps(exclude_keys(message, {'signature'})).encode('utf-8')
    signature_bytes = bytes.fromhex(message['signature'])

    public_key_bytes = bytes.fromhex(message['public_key'])
    verifying_key = uncompress_verifying_key(public_key_bytes)

    node_id = sha256(sha256(public_key_bytes).digest()).digest()
    node_id_hex = node_id.hex()

    peer_node_ids = read_db_json(get_cursor('peers.db'), 'peers_set', ('node_id',))

    if node_id_hex in peer_node_ids:
        verack_status = {'verack' : True}

    elif verify_sig(signed_message, signature_bytes, verifying_key):
        nodes_db_reference = read_db(get_cursor('peers.db'), 'peers_set WHERE node_id = ?', '*', (node_id_hex,)).fetchone()

        data_to_update_db = (message['version'], dumps(message['services']), connecting_ipv4_address, message['addr_from']['port'], node_id_hex, 1)

        if nodes_db_reference:
            if node_id_hex == nodes_db_reference[-2]:
                # nodes_db_reference[-2] is node_id column of reference

                if request.method == 'PUT':
                    update_db(get_cursor('peers.db'), 'peers_set', 'node_id', data_to_update_db, node_id_hex)
                    verack_status = {'verack' : True}
            
        elif request.method == 'POST':
            write_db(get_cursor('peers.db'), 'peers_set', get_column_names_db(get_cursor('peers.db'), 'peers_set'), data_to_update_db)
            verack_status = {'verack' : True}
    
    return jsonify(verack_status)

@app.route('/discover/blockchain/headers/<int:start_height>/<string:end_height>', methods=['GET'])
def get_blockchain_headers_view(start_height, end_height):
    end_height = int(end_height)

    if end_height == -1:
        end_height = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'height')

    blockchain_headers = read_db(get_cursor('blockchain.db'), 'header WHERE height BETWEEN ? AND ? ORDER BY height', '*', (start_height, end_height)).fetchall()

    return jsonify(blockchain_headers)

@app.route('/discover/blockchain/txs/<int:start_height>/<string:end_height>', methods=['GET'])
def get_blockchain_txs_view(start_height, end_height):
    end_height = int(end_height)

    if end_height == -1:
        end_height = get_col_last_value(get_cursor('blockchain.db'), 'txs ORDER BY block_height', 'block_height')

    blockchain_txs = read_db(get_cursor('blockchain.db'), 'txs WHERE block_height BETWEEN ? AND ? ORDER BY block_height', '*', (start_height, end_height)).fetchall()

    return jsonify(blockchain_txs)

@app.route('/blockchain', methods=['GET'])
def get_blockchain_view():
    blockchain_headers = read_db_json(get_cursor('blockchain.db'), 'header', '*')
    blockchain_txs = read_db_json(get_cursor('blockchain.db'), 'txs', '*', ('inputs', 'outputs'))

    blockchain_json = []

    for header in blockchain_headers:
        block_json = {'header' : header, 'txs' : []}

        for tx in blockchain_txs:
            if header['height'] == tx['block_height']:
                block_json['txs'].append(exclude_keys(tx, {'block_hash', 'block_height'}))

        blockchain_json.append(block_json)

    return jsonify(blockchain_json)

@app.route('/utxos/address/<string:address>', methods=['GET'])
def get_utxos_address_view(address):
    utxos = read_db_json(get_cursor('utxos.db'), f"utxos_set WHERE address='{address}'", get_column_names_db(get_cursor('utxos.db'), 'utxos_set'))

    return jsonify(utxos)

@app.route('/utxos_mempool/address/<string:address>', methods=['GET'])
def get_utxos_mempool_address_view(address):
    utxos_mempool_address = []

    for out in utxos_mempool:
        if out['address'] == address:
            utxos_mempool_address.append(out)

    return jsonify(utxos_mempool_address)

@app.route('/validate/tx', methods=['POST'])
def validate_tx():
    global mempool
    global utxos_mempool

    tx = request.json

    up_peers = update_peers()

    tx_valid = {'tx_valid' : False}

    if tx not in mempool:
        verify_response = verify_tx(tx, utxos_mempool)

        if verify_response != False:
            utxos_mempool = verify_response
            mempool.append(tx)
            
            for peer in up_peers:
                post(f"http://{peer['ipv4_address']}:{peer['port']}/validate/tx", json=tx)

            tx_valid = {'tx_valid' : True}
    else:
        tx_valid = {'tx_valid' : True}
    
    return jsonify(tx_valid)

@app.route('/validate/block', methods=['POST'])
def validate_block():
    global mempool
    global utxos_mempool

    block = request.json

    prev_hash = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'hash')

    block_valid = {'block_valid' : False}

    if block['header']['hash'] != prev_hash: # to check if node has already received block
        block_reward = update_block_reward()

        block_height = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'height')

        coinbase = block['txs'][0]
        
        if verify_block(coinbase, block, mempool, version, block_reward, block_height):
            up_peers = update_peers()

            if block_height == None:
                block_height = -1
            
            block_height += 1
            block_hash = block['header']['hash']
            block_size = len(dumps(block))

            blockchain_txs_cols = get_column_names_db(get_cursor('blockchain.db'), 'txs')
            utxos_cols = get_column_names_db(get_cursor('utxos.db'), 'utxos_set')

            block_header_data = tuple(block['header'].values()) + (block_height, block_size)
            
            write_db(get_cursor('blockchain.db'), 'header', get_column_names_db(get_cursor('blockchain.db'), 'header'), block_header_data)

            new_mempool = []

            for tx in block['txs']:
                tx_params = (list(tx.values()) + [block_hash, block_height])[1:]

                tx_params[1] = dumps(tx_params[1]) # tx_params[1] is the inputs
                tx_params[2] = dumps(tx_params[2]) # tx_params[2] is the outputs

                for inp in tx['inputs']:
                    if inp in utxos_mempool:
                        utxos_mempool.remove(inp)
                    else:
                        del_db(get_cursor('utxos.db'), 'utxos_set WHERE txid = ? AND output_index = ?', (inp['txid'], inp['output_index']))

                write_db(get_cursor('utxos.db'), 'utxos_set', utxos_cols, (tx['txid'], 0, tx['outputs'][0]['amount'], tx['outputs'][0]['address']))
                utxo_1 = {'txid' : tx['txid'], 'output_index' : 0, 'amount' : tx['outputs'][0]['amount'], 'address' : tx['outputs'][0]['address']}

                if utxo_1 in utxos_mempool:
                    utxos_mempool.remove(utxo_1)

                if len(tx['outputs']) > 1:
                    write_db(get_cursor('utxos.db'), 'utxos_set', utxos_cols, (tx['txid'], 1, tx['outputs'][1]['amount'], tx['outputs'][1]['address']))
                    utxo_2 = {'txid' : tx['txid'], 'output_index' : 1, 'amount' : tx['outputs'][1]['amount'], 'address' : tx['outputs'][1]['address']}

                    if utxo_2 in utxos_mempool:
                        utxos_mempool.remove(utxo_2)

                write_db(get_cursor('blockchain.db'), 'txs', blockchain_txs_cols, tx_params)
            
            for i in mempool:
                if i not in block['txs'][1:]:
                    new_mempool.append(i)

            mempool = new_mempool

            block_valid = {'block_valid' : True}

            for peer in up_peers:
                post(f"http://{peer['ipv4_address']}:{peer['port']}/validate/block", json=block)
    else:
        block_valid = {'block_valid' : True}
            
    return jsonify(block_valid)

@app.route('/utxos_mempool')
def get_utxos_mempool_view():
    return jsonify(utxos_mempool)

if __name__ == '__main__':
    parser = ArgumentParser()
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

    node_id_hex = node_id.hex()

    init_all(node_id_hex)

    port = read_json_file('config.json')['port']

    if args.r:
        private_ipv4_address = get_private_ipv4_address()
        app.run(private_ipv4_address, port)
    
    if args.u:
        print('Updating network status...')
        update_network_status(key, port)