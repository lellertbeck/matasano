#Cryptopals Crypto Challenge
#Set 1
#Luke Ellert-Beck
#8/13/2017
#Last modified: 1/28/2018

import binascii
import base64

#Challenge 1
#Convert hex to base64
def hex_to_base64(hexstr):
    byte_seq = binascii.unhexlify(hexstr)
    print(byte_seq)
    return base64.b64encode(byte_seq)

def test_chal_1():
    return hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
