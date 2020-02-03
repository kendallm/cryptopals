import base64
import heapq
from binascii import a2b_hex
from collections import Counter


def xor_buffers(buff1, buff2):
    if len(buff1) != len(buff2):
        raise ValueError()  
    out = [a ^ b for a, b in zip(buff1, buff2)]
    return bytes(out)

def hex_to_base64(hex_str):
    hex = a2b_hex(hex_str)
    return base64.b64encode(hex).decode('utf-8')

def single_byte_xor_cracker(cipher_text):
    heap = []
    for i in range(0, 256):
        key = [i] * len(cipher_text)
        plaintext = xor_buffers(cipher_text, key)
        heapq.heappush(heap, (char_frequency_analysis(plaintext), plaintext))
    return heapq.heappop(heap)[1]

def char_frequency_analysis(text):
    """
    Roughly .33 percent of letters in typical text are vowels
    """
    c = Counter(str(text))
    vowels = c['a'] + c['e'] + c['i'] + c['o'] + c['u']
    percent_vowels = vowels/len(text)
    return abs(.33 - percent_vowels)
    
if __name__ == '__main__':
    """
    https://cryptopals.com/sets/1 
    Verifying functionality according to challenge outputs
    """
    
    # 1
    out = hex_to_base64(b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    assert(out == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
    
    # 2
    out = xor_buffers(a2b_hex('1c0111001f010100061a024b53535009181c'), 
                      a2b_hex('686974207468652062756c6c277320657965'))
    assert(out == a2b_hex('746865206b696420646f6e277420706c6179'))
    
    # 3
    # Looking for an english sentence
    result = single_byte_xor_cracker(a2b_hex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))
    print(result)

