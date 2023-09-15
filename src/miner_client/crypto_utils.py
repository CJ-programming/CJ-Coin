from ecdsa import SECP256k1
from ecdsa import VerifyingKey
from ecdsa.util import number_to_string

def compress_verifying_key(verifying_key : VerifyingKey) -> bytes:
    x = verifying_key.pubkey.point.x()
    y = verifying_key.pubkey.point.y()

    e_x = number_to_string(x, SECP256k1.order) # encoded x
    return (b'\x03' + e_x) if y % 2 else (b'\x02' + e_x)

def generate_outputs(own_address, inputs, amount, address, fee):    
    """
    input format:
    [{txid, output_index, value, address}]
    """

    utxos_balance = sum(i['value'] for i in inputs)
 
    if utxos_balance >= amount:
        outputs = []

        total_amount = amount - fee

        change = utxos_balance - total_amount

        outputs.append({'value' : total_amount, 'address' : address})
        outputs.append({'value' : change, 'address' : own_address})
    
    return outputs