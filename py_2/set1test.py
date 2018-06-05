#Cryptopals Crypto Challenge
#Set 1 test script
#Luke Ellert-Beck
#Created: 11/9/2017
#Last Modified: 12/16/17

#test script for set1.py
import set1

tests = []
passes = True

#Challenge 1
inp = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
out = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
tests.append(set1.test_chal_1(inp, out))

#Challenge 2
inp = "1c0111001f010100061a024b53535009181c"
key = "686974207468652062756c6c277320657965"
out = "746865206b696420646f6e277420706c6179"
tests.append(set1.test_chal_2(inp, key, out))

#Challenge 3
inp = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"


#Challenge 4


for case in tests:
    if case == False:
        passes = False
        print "Challenge " + str(tests.index(case) + 1) + " failed"

if passes:
    print "All tests passed"

