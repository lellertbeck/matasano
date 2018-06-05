#Cryptopals Crypto Challenge
#Set 1
#Luke Ellert-Beck
#8/13/2017
#Last modified: 12/16/17

import binascii
import base64
import numpy
import math
import heapq
import Crypto
from Crypto.Cipher import AES

alphabet = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','v','x','y','z']
commons = ['e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'u', ' ']
expected_freq = [.13, .09, .08, .075, .07, .0675, .0625, .06, .06, .0425, .04, .0275, .1]
ascii = [chr(i) for i in xrange(127)]
KEYSIZE = range(6,40)

#Challenge 1
#Convert hex to base64
def hex_str_to_base64(hexstr):
    byte_seq = binascii.unhexlify(hexstr)
    #print byte_seq
    return base64.b64encode(byte_seq)

def test_chal_1(inp, out):
    return (hex_str_to_base64(inp) == out)

#Challenge 2
#fixed xor
def fixed_xor(hexstr, xorstr):
    #added for Challenge 3
    while len(xorstr) < len(hexstr):
        xorstr += xorstr
    if len(xorstr) > len(hexstr):
        xorstr = xorstr[:len(hexstr)]

    b1 = hextobin(hexstr)
    b2 = hextobin(xorstr)
    b3 = ""

    for x in range(0, len(b1)):
        if b1[x] == b2[x]:
            b3 += "0"
        else:
            b3 += "1"
    return bintohex(b3)

def fixed_xor_bit(s1, s2):
    b1 = bytes.fromhex(s1)
    print(b1)
    b2 = bytes.fromhex(s2)
    print(b2)
    b3 = b1 ^ b2
    print(b3)
    return b3.hex()


def test_chal_2(inp, key, out):
    return (fixed_xor(inp, key) == out)

#Challenge 3
#Single-byte XOR cipher
class key_object:
    def __init__(self, score, text, key):
        self.score = score
        self.text = text
        self.key = key
    def __cmp__(self, other):
        return cmp(self.score, other.score)
    def __str__(self):
        return self.text + ": " + str(self.score)
    def get_text(self):
        return self.text
    def get_score(self):
        return -(self.score)
    def get_key(self):
        return self.key

def score_text(plaintext):
    frequencies = []
    errors = []

    for letter in commons:
        c = plaintext.count(letter)+plaintext.count(letter.upper())
        frequencies.append(c)
    for x in range(0, len(frequencies)):
        errors.append((frequencies[x]-expected_freq[x])**2)
    score = math.sqrt(numpy.mean(errors))
    return score

#Challenge 4
#Detect single-character XOR

"""Given a file of hex strings, find one encoded with
   a single-character xor
"""
def detect_xor(filename):
    with open(filename) as hexes:
        best_match = key(0.0,"")
        for line in hexes:
            current = rank_keys_xor(line.strip())
            if current.get_score() > best_match.get_score():
                best_match = current
    return str(best_match)

def chal_4():
    return detect_xor("4.txt")

#Challenge 5
#Implement repeating-key XOR

def xor_encrypt(plaintext, key):
    hexstr = plaintext.encode('hex')
    xorkey = key.encode('hex')
    return fixed_xor(hexstr, xorkey)

#Challenge 6
#Break repeating-key XOR

class key_size():
    def __init__(self, size, dist):
        self.size = size
        self.dist = dist
    def __cmp__(self, other):
        return cmp(self.dist, other.dist)
    def get_size(self):
        return self.size
    def set_dist(self, distance):
        self.dist = distance

def hamming_distance(s1, s2):
    bin1 = strtobin(s1)
    bin2 = strtobin(s2)
    c = 0
    for x in range(len(bin1)):
        c += (bin1[x] != bin2[x])
    return c

def chal_6():
    with open("6.txt") as infile:
        text = infile.read().decode('base64')
    print(xor_decrypt(text))

def xor_decrypt(text):
    sizes = []
    key= ""
    for x in KEYSIZE:
        s1 = text[:x]
        s2 = text[x: x*2]
        s3 = text[x*2:x*3]
        s4 = text[x*3:x*4]
        heapq.heappush(sizes, key_size(x, (hamming_distance(s1,s2)+
                                           hamming_distance(s1,s3)+
                                           hamming_distance(s1,s4)+
                                           hamming_distance(s2,s3)+
                                           hamming_distance(s2,s4)+
                                           hamming_distance(s3,s4))/(6*x)))
    best_size = heapq.heappop(sizes).get_size()
    blocks = []
    for i in range(best_size):
        b = ""
        j = i
        while(j < len(text)):
            b += text[j]
            j += best_size
        blocks.append(b)

    for block in blocks:
        key += rank_keys_xor(block.encode('hex'),'k')

    return fixed_xor(text.encode('hex'), key.encode('hex')).decode('hex')

#Challenge 7
#AES in ECB mode

def chal_7():
    with open('7.txt') as infile:
        text = infile.read().decode('base64')
    print (decrypt_aes(text, "YELLOW SUBMARINE", 1))

def decrypt_aes(ciphertext, key, mode):
    cipher = AES.AESCipher(key, mode)
    return cipher.decrypt(ciphertext)

#Challenge 8
#Detect AES in ECB mode
def chal_8():
    return detect_aes("8.txt")

def detect_aes(filename):
    with open(filename) as infile:
        best_match = key(0.0, "")
        for line in infile:
            current = rank_keys_aes(line.strip())
            if current.get_score() > best_match.get_score():
                best_match = current
    return str(best_match)


########################################
#Helper Methods
"""Breaks single-xor encryption
   No key required
"""
def rank_keys_xor(hexstr, mode='o'):
    best_scores = []
    ranks = []

    for x in ascii:
        dechex = fixed_xor(hexstr, x.encode('hex'))
        plaintext = dechex.decode('hex')
        score = score_text(plaintext)
        k = key_object(-(score), plaintext, x)
        heapq.heappush(best_scores, k)

    best_match = heapq.heappop(best_scores)
    if mode == 'o':
        return best_match
    elif mode == 't':
        return best_match.get_text()
    elif mode == 's':
        return best_match.get_score()
    elif mode == 'k':
        return best_match.get_key()

"""Helper for rank_keys_aes
   Chooses key based on ECB 16-byte blocks
   Return: 16-byte ascii string
"""
def choose_key():
    return

"""Breaks aes encryption
   No key required
"""
def rank_keys_aes(hexstr, mode='o'):
    best_scores = []
    ranks = []
    key = choose_key()

    for x in ascii:
        for n in range(8):
            key +=x
        decbin = decrypt_aes(hextobin(hexstr), strtobin(key), 1)
        plaintext = bintostr(decbin)
        score = score_text(plaintext)
        k = key_object(-(score), plaintext, x)
        heapq.heappush(best_scores, k)

    best_match = heapq.heappop(best_scores)
    if mode == 'o':
        return best_match
    elif mode == 't':
        return best_match.get_text()
    elif mode == 's':
        return best_match.get_score()
    elif mode == 'k':
        return best_match.get_key()

"""Takes a string of plaintext and outputs a binary string
"""
def strtobin(text):
    binstr = ""
    for x in text:
        byte = bin(ord(x))[2:]
        while len(byte) < 8:
            byte = '0'+byte
        binstr += byte
    return binstr

"""
"""
def bintostr(binstr):
    text = ""

    i = 0
    while i < len(binstr):
        char = chr(int(binstr[i:i+8], 2))
        text += char
        i+=8
    return text

"""Takes a string of hexadecimal and outputs a binary string
"""
def hextobin(hexstr):
    binstr = ""

    for x in range(0, len(hexstr)):
        byte = bin(int(hexstr[x], 16))[2:]
        while(len(byte) < 4):
            byte = '0' + byte
        binstr += byte
    return binstr

"""Takes a byte string and returns a hex string
"""
def bintohex(binstr):
    hexstr = ""

    i = 0
    while i < len(binstr):
        hexdig = hex(int(binstr[i:i+4], 2))
        hexstr += hexdig[2:]
        i+=4
    return hexstr
