from crypto_utils import compress_verifying_key
from crypto_utils import generate_outputs

from ecdsa import SigningKey

from global_vars import version
from global_vars import seed_node_ipv4_address
from global_vars import seed_node_port

from json import dumps

from requests import get
from requests import post

from utils import decrypt_file
from utils import gen_check_sum
from utils import str_encode_b64

def discover_nodes():
    nodes_json = get(f'http://{seed_node_ipv4_address}:{seed_node_port}/discover/nodes').json() # add potential dns seed for this
    return nodes_json

def broadcast_nodes_tx(tx):
    nodes = discover_nodes()

    for node_net_addr in nodes:
        response = post(f"http://{node_net_addr['ipv4_address']}:{node_net_addr['port']}/validate/tx", json=tx).json()
        print(response)

def broadcast_nodes_block(block):
    nodes = discover_nodes()

    for node_net_addr in nodes:
        response = post(f"http://{node_net_addr['ipv4_address']}:{node_net_addr['port']}/validate/block", json=block).json()
        print(response)

def send(key, amount, address, fee):    
    private_key = SigningKey.from_string(decrypt_file('private_key.bin', key))
    public_key = compress_verifying_key(private_key.get_verifying_key())

    public_key_b64_str = str_encode_b64(public_key)

    address_check_sum = gen_check_sum(public_key)

    inputs = get(f"http://{seed_node_ipv4_address}:{seed_node_port}/utxo/{address}")

    outputs = generate_outputs(address_check_sum['address'], inputs, amount, address, fee)

    tx_json = {'version' : version, 'inputs' : inputs, 'outputs' : outputs, 'public_key' : public_key_b64_str}

    signature = str_encode_b64(private_key.sign(dumps(tx_json).encode('utf-8')))

    tx_json.update({'signature' : signature})

    broadcast_nodes_tx(tx_json)

"""
send message:
{version, inputs, outputs, public_key, signature}


"""