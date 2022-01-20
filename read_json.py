import json
import sys

from collections import OrderedDict
from ctypes import cdll

lib = cdll.LoadLibrary("./libbgmix.so")

def elg_encrypt(secret):
    return lib.encript_single_secret(secret)


if len(sys.argv) != 3:
    print("Number of arguments incorrect, dimension set to m=64, n=64\n")
    m = 64
    n = 64
else:
    m = int(sys.argv[1])
    n = int(sys.argv[2])

f = open("encryptions.json")
data = json.load(f)
f.close()

"""
f = open("inval.json")
inval = json.load(f)
f.close()
"""

ciphers = []

for choice in data["cipherTexts"]:
    alpha = int(choice["alpha"])
    beta = int(choice["beta"])
    ciphers.append([alpha, beta])

for i in range(len(ciphers), m*n):
    # ElGammal encryption of the string "Inval"
    inval = elg_encrypt(data["invalid"])
    ciphers.append(
        [int(inval[0]),
        int(inval[1])]
    )

key = data["publicKey"]

od = OrderedDict()
od["generator"] =  int(key["g"])
od["modulus"] = int(key["p"])
od["order"] = int(key["q"])
od["public"] = int(key["y"])
od["public_randoms"] = ""
od["proof"] = ""
od["original_ciphers"] = ciphers.__str__()
od["mixed_ciphers"] = ""


f = open("ciphers_0.json", "w")
json.dump(od, f)
f.close