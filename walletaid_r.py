import os.path, binascii, collections, getpass, argparse, hashlib, struct, json

# Get command-line arguments
parser = argparse.ArgumentParser("walletaid.py",
                                 usage="walletaid.py \"filepath\" pubkeyprefix privkeyprefix [-comp] [-h]")
parser.add_argument("filepath", help="Path to wallet file (use \"\")")
parser.add_argument("pubkeyprefix", help="public key prefix in hex (e.g. 00 for bitcoin)")
parser.add_argument("privkeyprefix", help="private key prefix in hex (e.g. 80 for bitcoin)")
parser.add_argument("-comp", action="store_true", help="use compressed keys")

try:
    args = parser.parse_args()
except:
    print("\n\n")
    parser.print_help()
    exit()

wallet_filename = os.path.abspath(args.filepath)
pubprefix = binascii.unhexlify(args.pubkeyprefix)
privprefix = binascii.unhexlify(args.privkeyprefix)
comp = args.comp

# Calculates public key from a private key
class Point(object):
    def __init__(self, _x, _y, _order=None): self.x, self.y, self.order = _x, _y, _order

    def calc(self, top, bottom, other_x):
        l = (top * inverse_mod(bottom)) % p
        x3 = (l * l - self.x - other_x) % p
        return Point(x3, (l * (self.x - x3) - self.y) % p)

    def double(self):
        if self == INFINITY: return INFINITY
        return self.calc(3 * self.x * self.x, 2 * self.y, self.x)

    def __add__(self, other):
        if other == INFINITY: return self
        if self == INFINITY: return other
        if self.x == other.x:
            if (self.y + other.y) % p == 0: return INFINITY
            return self.double()
        return self.calc(other.y - self.y, other.x - self.x, other.x)

    def __mul__(self, e):
        if self.order: e %= self.order
        if e == 0 or self == INFINITY: return INFINITY
        result, q = INFINITY, self
        while e:
            if e & 1: result += q
            e, q = e >> 1, q.double()
        return result

    def __str__(self):
        if self == INFINITY: return "infinity"
        return "%x %x" % (self.x, self.y)


def inverse_mod(a):
    if a < 0 or a >= p: a = a % p
    c, d, uc, vc, ud, vd = a, p, 1, 0, 0, 1
    while c:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
    if ud > 0: return ud
    return ud + p


p, INFINITY = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, Point(None, None)  # secp256k1
g = Point(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
# End of code used to calculate public key

# Base58 encoder
alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58encode(v):
    '''Encode a string using Base58'''

    nPad = len(v)
    v = v.lstrip(b'\0')
    nPad -= len(v)

    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8

    result = b""
    while acc:
        acc, idx = divmod(acc, 58)
        result = alphabet[idx:idx+1] + result

    return (alphabet[0:1] * nPad + result).decode("utf-8")


# SHA-256 hashception function
def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def pubtoaddr(data):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(data).digest())
    md160 = md.digest()
    h = Hash(pubprefix+md160)
    addr = md160 + h[0:4]
    return b58encode(pubprefix+addr)


def privtopub(privkey, compressed):
    c = int(binascii.hexlify(privkey), base=16)
    pubkey = str(g * c)
    pubkey = ("0" * (64 - pubkey.index(" "))) + pubkey
    if compressed:
        if int(pubkey[-1], base=16) % 2 == 0:
            pref = "02"
        else:
            pref = "03"
        pubkey = pubkey[0:64]
    else:
        pref = "04"
        if len(pubkey) < 129:
            zeroadd = "0" * (129-len(pubkey))
            pubkey = pubkey[:64] + zeroadd + pubkey[64:]
        pubkey = pubkey.replace(" ", "")
    return binascii.unhexlify(pref + pubkey)


def privtowif(privkey, compressed):
    privkey = privprefix + privkey
    if compressed:
        privkey = privkey + b"\x01"
    h = Hash(privkey)
    privkey = privkey + h[0:4]
    return b58encode(privkey)


# Loads wallet.dat
with open(wallet_filename, "rb") as wallet:
    wallet_data = wallet.read()

    vheader = b"\x02\x01\x01\x04\x20"
    offsets = [5, 37]

    keylist = collections.OrderedDict()
    vindex = wallet_data.find(vheader, 0)

    priv = wallet_data[vindex + offsets[0]: vindex + offsets[1]]
    while True:
        if priv not in keylist and vindex != -1:
            keylist[priv] = 1

        vindex = wallet_data.find(vheader, vindex + 6)

        if vindex >= 0:
            priv = wallet_data[vindex + offsets[0]: vindex + offsets[1]]
        else:
            break


try:
    records = []
    klist_len = len(keylist)
    iters = 0

    for priv_key, one in keylist.items():
        iters += 1
        procinfo = "Processing {}/{} keys".format(iters, klist_len)
        print(procinfo, end="\r")
            
        pub_key = privtopub(priv_key, comp)
        address = pubtoaddr(pub_key)

        wif = privtowif(priv_key, comp)

        records.append({"address": address, "wif": wif})
        if iters >= klist_len:
            print(" " * len(procinfo))
            print("{} private keys found\n\nsaved to DUMP_R.txt".format(klist_len))
finally:
    with open("DUMP_R.txt", "w") as dump:
        json.dump(records, dump, indent=2)
