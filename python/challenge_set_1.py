import base64
import heapq
import math
from binascii import *
from collections import Counter
from Crypto.Cipher import AES


def xor_buffers(buff1, buff2):
    if len(buff1) != len(buff2):
        raise ValueError()
    out = [a ^ b for a, b in zip(buff1, buff2)]
    return bytes(out)

def hex_to_base64(hex_str):
    hex = a2b_hex(hex_str)
    return base64.b64encode(hex)

def single_byte_xor_cracker(cipher_text):
    heap = []
    for key in range(0, 256):
        plaintext = repeating_xor(cipher_text, [key])
        heapq.heappush(heap, (char_frequency_analysis(plaintext), plaintext, key))
    cracked_message = heapq.heappop(heap)
    return cracked_message[2], cracked_message[1]

def char_frequency_analysis(input_bytes):
    """
    Roughly .33 percent of letters in typical text are vowels.

    https://en.wikipedia.org/wiki/Frequency_analysis
    """

    normal_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    try:
        input_str = str(bytes.decode(input_bytes))
    except:
        return math.inf
    input_str = [s.lower() for s in input_str]
    c = Counter(input_str)
    """
    Sum the difference in frequency between the normal frequencies and the 
    frequencies in the text. Treat non normal characters as really large difference.
    
    Penalizes non ascii chars
    
    This list comprehension should be rewritten.
    """
    ascii_range = range(ord(' '), ord('~'))
    rank = sum([(abs(c[x] / len(input_bytes)) - normal_frequencies.get(x, .088 if x in ascii_range else -10.0)) for x in c])
    return rank


def repeating_xor(plaintext, key):
    repeated_key = key * int(math.ceil((len(plaintext) / len(key))))
    return xor_buffers(plaintext, repeated_key[0 : len(plaintext)])


def hamming_distance(s1, s2):
    xor = xor_buffers(s1, s2)
    dist = 0
    for byte in xor:
        bits = bin(byte)[2:]
        c = Counter(bits)
        dist += c['1']
    return dist


def repeating_xor_cracker():
    KEYSIZES = range(2, 41)
    keysize_to_dist = {}

    with open('6.txt') as f:
        contents = base64.b64decode(f.read())

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


def chunk_contents(blocksize, contents):
    return [contents[i: i + blocksize] for i in range(0, len(contents), blocksize)]


def transpose_blocks(blocks):
    blocks[-1] = bytearray(blocks[-1])
    while len(blocks[-1]) < len(blocks[0]):
        blocks[-1].append(0)
    return list(zip(*blocks))


def detect_single_charactor_xor():
    heap = []
    with open('4.txt') as f:
        for line in f:
            key_and_text = single_byte_xor_cracker(bytes.fromhex(line))
            heapq.heappush(heap, (char_frequency_analysis(key_and_text[1]), str(key_and_text[1])))
    print(heapq.heappop(heap))

def decrypt_aes_ecb(key = 'YELLOW SUBMARINE'):
    with open('7.txt') as f:
        contents = base64.b64decode(f.read())
    cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_ECB)
    res = cipher.decrypt(contents)
    return res


if __name__ == '__main__':
    """
    https://cryptopals.com/sets/1 
    Verifying functionality according to challenge outputs
    """

    # 1
    out = hex_to_base64(b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    assert(out == b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

    # 2
    out = xor_buffers(a2b_hex(b'1c0111001f010100061a024b53535009181c'),
                      a2b_hex(b'686974207468652062756c6c277320657965'))
    assert(out == a2b_hex(b'746865206b696420646f6e277420706c6179'))

    # 3
    # Looking for an english sentence
    result = single_byte_xor_cracker(bytearray.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))
    print(result)


    # 4
    detect_single_charactor_xor()

    # # 5
    out = repeating_xor(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
                        b"ICE")
    assert(a2b_hex('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f') == out)

    #
    # 5
    out = hamming_distance(b'this is a test', b'wokka wokka!!!')
    assert(out == 37)
    print(repeating_xor_cracker())

    print(decrypt_aes_ecb())

    print("Success")