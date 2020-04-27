import base64
from utils import *

class Adversary(object):

    def __init__(self):
        pass

    def crack_repeating_xor(self, contents):
        KEYSIZES = range(2, 41)
        keysize_to_dist = {}

        contents = base64.b64decode(contents)

        for keysize in KEYSIZES:
            blocks = []
            distances = []
            for i in range(int(len(contents) / keysize)):
                blocks.append(contents[i * keysize: i * keysize + keysize])
            biter = iter(blocks)
            for block in biter:
                try:
                    block2 = next(biter)
                except:
                    break
                distances.append(hamming_distance(block, block2) / keysize)
            keysize_to_dist[keysize] = sum(distances) / len(blocks)

        sorted_sizes = sorted(keysize_to_dist, key=keysize_to_dist.get)

        blocksize = sorted_sizes[0]
        blocks = chunk_contents(blocksize, contents)
        transposed = transpose_blocks(blocks)
        keys = []
        for block in transposed:
            keys.append(single_byte_xor_cracker(block)[0])
        key = bytes(keys)
        res = repeating_xor(contents, key)

        return key, res


