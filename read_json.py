import json
import os
import sys

from collections import OrderedDict
from ctypes import (
    cdll,
    c_bool,
    c_char_p,
    c_long,
    POINTER
)

def setup_curves():
    lib.init()

def elg_encrypt(secret):
    c_secret = c_long(secret)
    fun = lib._Z21encrypt_single_secretl
    fun.restype = POINTER(c_long * 2)
    return [i for i in fun(c_secret).contents]

def mix(filename, m, n):
    b_filename = filename.encode("utf-8")
    c_filename = c_char_p(b_filename)
    c_m = c_long(m)
    c_n = c_long(n)
    fun = lib.mix
    fun.restype = c_bool
    return fun(c_filename, c_m, c_n)

def main(m, n, lib):
    f = open("encryptions.json")
    data = json.load(f)
    f.close()

    ciphers = []

    for choice in data["cipherTexts"]:
        alpha = int(choice["alpha"])
        beta = int(choice["beta"])
        ciphers.append([alpha, beta])

    setup_curves()

    for i in range(len(ciphers), m*n):
        # ElGammal encryption of the string "Inval"
        inval = elg_encrypt(data["invalid"])
        ciphers.append(
            [int(inval[0]), int(inval[1])]
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

    filename = "ciphers_0.json"

    f = open(filename, "w")
    json.dump(od, f)
    f.close

    print("Created file")
    
    if os.system(f"./bgmix {m} {n}") == 0:
        print("Mix finished")
    else:
        print("Library call failed")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Number of arguments incorrect, dimension set to m=64, n=64\n")
        m = 64
        n = 64
    else:
        m = int(sys.argv[1])
        n = int(sys.argv[2])

    if os.system("make") == 0:
        lib = cdll.LoadLibrary("./libbgmix.so")
        main(m, n, lib)
    else:
        print("Compilation failed")