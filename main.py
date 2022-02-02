from collections import OrderedDict
from ctypes import (
    cdll,
    create_string_buffer,
    c_bool,
    c_char_p,
    c_long
)
import json
from os import system
from os.path import (
    join as p_join,
    realpath,
    split as p_split
)
import sys

def make() -> None:
    dir_path = p_split(realpath(__file__))[0]
    log_path = p_join(dir_path, "main.log")
    if system(f"make LOG_CRYPTO_OUTPUT={log_path}") == -1:
        raise Exception("Compilation failed")
    
    if system(f"export LD_LIBRARY_PATH=/usr/local/lib:{dir_path}") == -1:
        raise Exception("Library linking failed")

def create_cipher(fun, c_secret, c_g, c_q, c_p, c_y):
    _ret = create_string_buffer(10000)
    fun(c_secret, _ret, c_g, c_q, c_p, c_y)
    pad_array = _ret.value.decode("utf-8").split(",")
    return [int(i) for i in pad_array]

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

    seed_pad = "1257206741114416297422800737364823130751266673136"

    key = data["publicKey"]
    g = int(key["g"])
    q = int(key["q"])
    p = int(key["p"])
    y = int(key["y"])

    lib = cdll.LoadLibrary("./libbgmix.so")

    b_secret = seed_pad.encode("utf-8")
    c_secret = c_char_p(b_secret)
    b_g = str(g).encode("utf-8")
    c_g = c_char_p(b_g)
    b_q = str(q).encode("utf-8")
    c_q = c_char_p(b_q)
    b_p = str(p).encode("utf-8")
    c_p = c_char_p(b_p)
    b_y = str(y).encode("utf-8")
    c_y = c_char_p(b_y)

    fun = lib.encrypt_single_secret
    fun.restype = c_char_p

    cm_len = len(ciphers)
    print(f"Read {cm_len} cipher pairs")
    print(f"Padding with {m*n - cm_len} cipher pairs")
    for _ in range(len(ciphers), m*n):
        # ElGammal encryption of the string "INVALID"
        pad_array = create_cipher(fun, c_secret, c_g, c_q, c_p, c_y)
        while 0 in pad_array:
            pad_array = create_cipher(fun, c_secret, c_g, c_q, c_p, c_y)
        ciphers.append(pad_array)

    od = OrderedDict()
    od["g"] = g
    od["q"] = q
    od["p"] = p
    od["y"] = y
    od["original_ciphers"] = ciphers
    #od["mixed_ciphers"] = []

    f = open(ciphers_file, "w")
    json.dump(od, f)
    f.close

    print("Created file")

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
    g = data["g"]
    q = data["q"]
    p = data["p"]

    lib = cdll.LoadLibrary("./libbgmix.so")
    
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
                election_file = "sample_2.json"
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