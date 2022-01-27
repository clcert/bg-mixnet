from collections import OrderedDict
from ctypes import (
    cdll,
    c_bool,
    c_char_p,
    c_long,
)
import json
from os import system
from os.path import (
    realpath,
    split as p_split
)
import sys

def make() -> None:
    if system("make") == -1:
        raise Exception("Compilation failed")
    
    dir_path = p_split(realpath(__file__))[0]
    if system(f"export LD_LIBRARY_PATH=/usr/local/lib:{dir_path}") == -1:
        raise Exception("Library linking failed")

def mix(m, n, ciphers_file, publics_file, proof_file, election_file) -> None:
    #make()

    f = open(election_file)
    data = json.load(f)
    f.close()

    ciphers = []

    # Add real ElGammal pairs
    for choice in data["cipherTexts"]:
        alpha = int(choice["alpha"])
        beta = int(choice["beta"])
        ciphers.append([
            alpha, beta
        ])

    alpha_pad = int(data["ciphertextForPadding"]["alpha"])
    beta_pad = int(data["ciphertextForPadding"]["beta"])

    for _ in range(len(ciphers), m*n):
        # ElGammal encryption of the string "Inval"
        ciphers.append([
            alpha_pad, beta_pad
        ])

    key = data["publicKey"]
    g = int(key["g"])
    q = int(key["q"])
    p = int(key["p"])

    od = OrderedDict()
    od["generator"] = g
    od["modulus"] = p
    od["order"] = q
    od["public"] = int(key["y"])
    od["original_ciphers"] = ciphers.__str__()

    f = open(ciphers_file, "w")
    json.dump(od, f)
    f.close

    print("Created file")

    lib = cdll.LoadLibrary("libbgmix.so")
    
    b_ciphers = ciphers_file.encode("utf-8")
    c_ciphers = c_char_p(b_ciphers)
    b_publics = publics_file.encode("utf-8")
    c_publics = c_char_p(b_publics)
    b_proof = proof_file.encode("utf-8")
    c_proof = c_char_p(b_proof)
    c_m = c_long(m)
    c_n = c_long(n)
    b_g = str(g).encode("utf-8")
    c_g = c_char_p(b_g)
    b_q = str(q).encode("utf-8")
    c_q = c_char_p(b_q)
    b_p = str(p).encode("utf-8")
    c_p = c_char_p(b_p)
    lib.mix(c_ciphers, c_publics, c_proof, c_m, c_n, c_g, c_q, c_p)

    f = open(ciphers_file, "r")
    data = f.read().replace('}', '', 1)
    f.close()

    f = open(ciphers_file, "w")
    f.write(data)
    f.close()

    print("Mixed ciphers")

def verify(m, n, ciphers_file, publics_file, proof_file) -> bool:
    #make()

    f = open(ciphers_file)
    data = json.load(f)
    f.close
    g = data["generator"]
    q = data["order"]
    p = data["modulus"]

    lib = cdll.LoadLibrary("libbgmix.so")
    
    b_ciphers = ciphers_file.encode("utf-8")
    c_ciphers = c_char_p(b_ciphers)
    b_publics = publics_file.encode("utf-8")
    c_publics = c_char_p(b_publics)
    b_proof = proof_file.encode("utf-8")
    c_proof = c_char_p(b_proof)
    c_m = c_long(m)
    c_n = c_long(n)
    b_g = str(g).encode("utf-8")
    c_g = c_char_p(b_g)
    b_q = str(q).encode("utf-8")
    c_q = c_char_p(b_q)
    b_p = str(p).encode("utf-8")
    c_p = c_char_p(b_p)

    fun = lib.validate_mix
    fun.restype = c_bool
    return fun(c_ciphers, c_publics, c_proof, c_m, c_n, c_g, c_q, c_p)

if __name__ == "__main__":
    modes = {"mix": 8, "verify": 7}
    arg_len = len(sys.argv)
    if arg_len > 1:
        mode = sys.argv[1]
        if mode in modes:
            if arg_len != modes[mode]:
                print("Number of arguments incorrect, parameters set to default\n")
                m = 64
                n = 64
                ciphers_file = "ciphers.json"
                publics_file = "public_randoms.txt"
                proof_file = "proof.txt"
                election_file = "sample.json"
            else:
                m = int(sys.argv[2])
                n = int(sys.argv[3])
                ciphers_file = sys.argv[4]
                publics_file = sys.argv[5]
                proof_file = sys.argv[6]
                if mode == "mix":
                    election_file = sys.argv[7]
        else:
            exep = f"Mode {mode} unknown, select from [{', '.join(modes)}]"
            raise Exception(exep)
    else:
        exep = f"Specify usage mode from [{', '.join(modes)}]"
        raise Exception(exep)

    if mode == "mix":
        mix(m, n, ciphers_file, publics_file, proof_file, election_file)
    elif mode == "verify":
        verify(m, n, ciphers_file, publics_file, proof_file)