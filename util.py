import hashlib
import json
import hmac

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from math import ceil

# root directory (change this for different saving folder)
root_dir = "D:/Apple-CSAM-Files/"
clients_dir = root_dir + "Clients/"
mal_img_dir = root_dir + "Malicious-Images/"
dec_img_dir = root_dir + "Decrypted-Images/"

# Initialize needed cryptographic values and functions
hash_func_list = [hashlib.sha1, hashlib.sha256, hashlib.md5, hashlib.sha3_224,
                  hashlib.sha3_256, hashlib.sha3_384, hashlib.sha3_512]
dhf_l = (2 ** 64) - 59
sh_p = 340282366920938463463374607431768211297
ecc_p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
ecc_q = 115792089210356248762697446949407573529996955224135760342422259061068512044369
ecc_gen_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
ecc_gen_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
ecc_gen = ECC.EccPoint(x=int(ecc_gen_x), y=int(ecc_gen_y), curve='p256')


def aes128_enc(key, data):
    """Encryption using AES128-GCM with 96-bit nonce"""
    header = b"header"
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    json_k = ['nonce', 'header', 'ciphertext', 'tag']
    json_v = [b64encode(x).decode('utf-8') for x in [cipher.nonce, header, ciphertext, tag]]
    cipher_json = json.dumps(dict(zip(json_k, json_v)))
    return cipher_json


def aes128_dec(key, cipher_json):
    """Decryption using AES128-GCM with 96-bit nonce"""
    try:
        b64 = json.loads(cipher_json)
        json_k = ['nonce', 'header', 'ciphertext', 'tag']
        jv = {k: b64decode(b64[k]) for k in json_k}
        cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
        cipher.update(jv['header'])
        data = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    except (ValueError, KeyError):
        return None
    return data


def calc_prf(fkey, id):
    """PRF for calculating x, z, x', r' using HMAC"""
    # x, z, x', r' el_of F^2_sh * X * R, X is domain of DHF, R is range of DHF
    h = hmac.new(fkey, bytes(id), hashlib.sha1).hexdigest()
    sh_x = int.from_bytes(h.encode(), "big") % sh_p
    h = hmac.new(fkey, h.encode(), hashlib.sha1).hexdigest()
    sh_z = int.from_bytes(h.encode(), "big") % sh_p
    h = hmac.new(fkey, h.encode(), hashlib.sha1).hexdigest()
    x = int.from_bytes(h.encode(), "big") % dhf_l
    r = None
    return sh_x, sh_z, x, r


def init_sh_poly(adkey, t):
    """Initializes a shamir secret polynomial and stores the coefficients"""
    a = list()
    a.append(int.from_bytes(adkey, "big"))
    for i in range(1, t + 1):
        a.append(int.from_bytes(get_random_bytes(16), "big") - 1)
    return a


def calc_poly(x, pol):
    """Calculates the result of a polynomial for given x and coefficients"""
    res = 0
    for i in range(0, len(pol)):
        res += pol[i] * (x ** i)
    return res % sh_p


def calc_h(u, n_dash, h1_i, h2_i):
    """Calculates two hashes using the cuckoo table hash functions"""
    key = b'password'
    h1 = hmac.new(key, u.encode(), hash_func_list[h1_i]).hexdigest()
    h2 = hmac.new(key, u.encode(), hash_func_list[h2_i]).hexdigest()
    out1 = int.from_bytes(h1.encode(), "big") % n_dash
    out2 = int.from_bytes(h2.encode(), "big") % n_dash
    return out1, out2


def calc_H(x):
    """Calculates the hash for hash function H"""
    int_x = int.from_bytes(x.encode(), "big") % ecc_q
    h = int_x * ecc_gen
    return h


def hmac_sha256(key, data):
    """Calculates the hmac using sha256"""
    return hmac.new(key, data, hashlib.sha256).digest()


def calc_H_dash(ikm):
    """Calculates the hash for hash function H' using HKDF
        Source: https://en.wikipedia.org/wiki/HKDF"""
    salt = b""
    info = b""
    ikm_bytes = int(ikm.x).to_bytes(32, "big")
    length = 16
    hash_len = 32
    if len(salt) == 0:
        salt = bytes([0] * hash_len)
    prk = hmac_sha256(salt, ikm_bytes)
    t = b""
    okm = b""
    for i in range(ceil(length / hash_len)):
        t = hmac_sha256(prk, t + info + bytes([1 + i]))
        okm += t
    return okm[:length]


def recon_adkey(shares):
    """Reconstructs the adkey using a distinct number of shamir shares > t"""
    values = list()
    for s in shares:
        sh = json.loads(s)
        values.append((sh['x'], sh['z']))
    adkey = 0
    for v in values:
        temp = 1
        for other in values:
            if v is not other:
                temp = (temp * (0 - other[0] * pow(v[0] - other[0], -1, sh_p))) % sh_p
        temp = (temp * v[1]) % sh_p
        adkey = (adkey + temp) % sh_p
    return adkey


def save_image(tup, path):
    """Saves an image to a given path"""
    f = open(f"{path}{tup[0]}.png", 'wb')
    f.write(tup[1])
    f.close()
