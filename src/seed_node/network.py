from database import get_cursor
from database import read_db_json
from database import update_db

from global_vars import version

from json import dumps

from requests import get
from requests.exceptions import ConnectionError

from utils import get_private_ipv4_address
from utils import read_json_file

def send_ping(ipv4_address, port):
    try:
        response = get(f'http://{ipv4_address}:{port}/ping', timeout=10)
        response.raise_for_status()

        data = response.json()

        if data == 'pong':
            return True
        
    except ConnectionError:
        pass

    # returns None if ping was unsuccessful

def update_peers():
    up_peers = ()

    peers_db = read_db_json(get_cursor('peers.db'), 'peers_set', '*', 'services')

    for peer in peers_db:
        response = send_ping(peer['ipv4_address'], peer['port'])

        data_to_update_db = (peer['version'], dumps(peer['services']), peer['ipv4_address'], peer['port'], peer['node_id'])

        if not response:
            data_to_update_db += (0,) # adds new status
        
        else:
            data_to_update_db += (1,)
            up_peers += (peer,)

        update_db(get_cursor('peers.db'), 'peers_set', 'node_id', data_to_update_db, peer['node_id'])

    return up_peers

def get_net_addr():
    json_file_data = read_json_file('config.json')

    ipv4_address = get_private_ipv4_address()
    services = json_file_data['services']
    port = json_file_data['port']

    net_addr = {'version' : version, 'ipv4_address' : ipv4_address, 'services' : services, 'port' : port}

    return net_addr