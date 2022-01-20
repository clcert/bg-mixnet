import json
import sys
from collections import OrderedDict

if len(sys.argv) != 3:
    print("Number of arguments incorrect, dimension set to m=64, n=64\n")
    m = 64
    n = 64
else:
    m = int(sys.argv[1])
    n = int(sys.argv[2])

# Add ElGammal parameters to voto_example.json
f = open("vote_example_0.json")
data = json.load(f)
f.close()

ciphers = []

for answer in data["vote"]["answers"]:
    for choice in answer["choices"]:
        alpha = int(choice["alpha"])
        beta = int(choice["beta"])
        ciphers.append([alpha, beta])

for i in range(len(ciphers), m*n):
    # ElGammal encryption of the string "Inval"
    ciphers.append(
        [356248063463477687949178506161066878067403877898230514979595161320856317698066991966101034887133287221012429442612860984748669662173460690762444054228779059029150719280405464083991463316787251486505762803010966733045590465948197721141374742797446931358215285666848515680770877313537941870154070091512437550974635534003411740520988005707095524238505445323626512523091063669093,
        449294656384133910125308994188602016912211152020396882952460033462894760308427608237536544112618696077571557698683983859369096428810226150599207766472208298424289263189606944312438749144139754723950370811746246192052736436782072273946905684427512146742581772327907233177322980853705834151628490755045157722495061005881684078964186825563914031979104055043813626256460997707063]
    )

f = open("key_example.json")
data = json.load(f)
f.close()

key = data["public_key"]

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