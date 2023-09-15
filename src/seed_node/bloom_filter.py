from hashlib import sha256

def bin_x(data):
    bin_data = bin(data)[2:]
    return bin_data
    
class BloomFilter:
    def __init__(self):
        self.buffer = 0
        self.segment_length = 0
        # 14 bits per element
        # 10 hash functions

    def add(self, w):
        self.segment_length += 14
        current_hash = w

        for _ in range(10):
            current_hash = sha256(current_hash).digest()
            hash_int = int.from_bytes(current_hash, 'big')
            index = hash_int % 14
            self.buffer |= (1 << self.segment_length - 1 - index)  # sets bit to buffer, moves it to the left according to index and segment length

    def query(self, w):
        current_hash = w

        for _ in range(10):
            current_hash = sha256(current_hash).digest()
            hash_int = int.from_bytes(current_hash, 'big')
            index = hash_int % 14
            if not (self.buffer & (1 << self.segment_length - 1 - index)): # moves 
                return False

        return True

