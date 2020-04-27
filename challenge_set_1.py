from binascii import a2b_hex

from utils import *
from adversary import Adversary


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
    adversary = Adversary()
    with open('6.txt') as f:
        contents = base64.b64decode(f.read())
        print(adversary.crack_repeating_xor(contents))

    print(decrypt_aes_ecb().decode('utf-8'))

    with open("8.txt") as f:
        contents = []
        for line in f:
            contents.append(line.strip())

    print(detect_aes_ecb(contents))
    print("Success")