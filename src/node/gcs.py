from hashlib import sha256
from math import ceil, log

def gcs_hash(w, N, P):
    h = sha256(w).digest()
    h = int.from_bytes(h, 'big')

    return h % (N*P)

def bit_length_x(value : int):
    value_bit_length = max(1, value.bit_length)

    # for some reason python thinks 0 is 0 bits long

    return value_bit_length

def unary_code(n): # variation of unary code, doesn't include zero on left
    unary_n = (1 << n) - 1
    return unary_n

def bit_writer(n1, n2):
    buffer = n1

    buffer <<= bit_length_x(n2)
    
    buffer += n2

    return buffer

def bin_x(data):
    bin_data = bin(data)[2:]
    return bin_data

def golomb_encode(n, P):
    q, r = divmod(n, P)

    if q: # if q isn't 0
        r <<= 1 # shift r to left to leave 0 bit for q

    unary_q = unary_code(q)
    
    golomb_encoded_n = bit_writer(r, unary_q) # stores most significant bit (q) at end to avoid 0 truncation
    # e.g. 0101 is truncated automatically by python to: 101

    return golomb_encoded_n

def golomb_decode(n, P):
    q = 0
    unary_q = 0

    mask = 1

    while n & mask:
        q += 1
        mask <<= 1

        unary_q <<= 1
        unary_q += 1

    unary_code_len = unary_q.bit_length()

    r = n >> (unary_code_len + 1)

    golomb_decoded_n = q * P + r

    return golomb_decoded_n

class GCS:
    def __init__(self, P : int):
        self.P = P
        self.values = [] # initialise values with append method
        self.N = 0 # length of GCS

    def append(self, w):
        self.N += 1

        w_gcs_hash = gcs_hash(w, self.N, self.P)

        if self.values: # if self.values isn't empty
            original_gcs_hashes = [golomb_decode(self.values[0], self.P)]

            for i in range(1, len(self.values)):
                original_value = original_gcs_hashes[i-1] + golomb_decode(self.values[i], self.P)
                original_gcs_hashes.append(original_value)
            
            original_gcs_hashes.append(w_gcs_hash)
            original_gcs_hashes.sort()

            self.values = [golomb_encode(original_gcs_hashes[0], self.P)]

            for i in range(1, len(original_gcs_hashes)):
                encoded_difference = golomb_encode(original_gcs_hashes[i] - original_gcs_hashes[i-1], self.P)
                self.values.append(encoded_difference)
        else:
            self.values.append(golomb_encode(w_gcs_hash, self.P))

    def query(self, w: bytes):
        if self.values: # if self.values isn't empty
            w_gcs_hash = gcs_hash(w, self.N-1, self.P)

            if w_gcs_hash == golomb_decode(self.values[0], self.P):
                return True

            previous = 0 # first value
            
            for i in self.values:
                original_value = previous + golomb_decode(i, self.P)

                if w_gcs_hash == original_value:
                    return True

                previous = original_value

        return False