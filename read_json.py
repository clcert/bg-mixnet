import json
import os
import sys

from collections import OrderedDict
from ctypes import (
    cdll,
    c_bool,
    c_char_p,
    c_long,
    c_ulong,
    POINTER
)

def elg_encrypt(secret, g, q, p):
    c_secret = c_long(secret)
    c_g = c_long(g)
    c_q = c_long(q)
    c_p = c_long(p)
    fun = lib._Z21encrypt_single_secretllll
    fun.restype = POINTER(c_ulong * 2)
    return [i for i in fun(c_secret, c_g, c_q, c_p).contents]

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

    key = data["publicKey"]
    g = int(key["g"])
    q = int(key["q"])
    p = int(key["p"])

    for i in range(len(ciphers), m*n):
        # ElGammal encryption of the string "Inval"
        inval = elg_encrypt(data["invalid"], g, q, p)
        ciphers.append(
            [int(inval[0]), int(inval[1])]
        )

    od = OrderedDict()
    od["generator"] =  g
    od["modulus"] = p
    od["order"] = q
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