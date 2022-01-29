import json
import random
import util

from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC


class Triple:
    """Representation of a triple"""
    def __init__(self, y, id, ad):
        self.y = y
        self.id = id
        self.ad = ad


class Voucher:
    """Representation of a voucher"""
    def __init__(self, id, Q1, ct1, Q2, ct2, rct):
        self.id = id
        self.Q1 = Q1
        self.ct1 = ct1
        self.Q2 = Q2
        self.ct2 = ct2
        self.rct = rct


class Client:
    """Represents a client in the tPSI-AD protocol"""
    def __init__(self, id, server):
        self.id = id
        self.server = server
        self.triples = list()
        self.adkey = int.to_bytes(random.randint(0, util.sh_p), 16, "big")  # (Enc, Dec), K'
        self.fkey = get_random_bytes(16)  # PRF, K''
        self.shamir_secret = util.init_sh_poly(self.adkey, server.t)
        self.pdata = self.server.pdata

    def add_triple(self, y, id, ad):
        """Adds a triple and sends an according voucher"""
        triple = Triple(y, id, ad)
        self.triples.append(triple)
        print(f"triple {triple.id} was added for client {self.id}")
        self.send_voucher(triple)

    def send_voucher(self, triple):
        """Sends a voucher to the server"""
        voucher = self.generate_voucher(triple)
        self.server.receive_voucher(self, voucher)

    def generate_voucher(self, triple):
        """Generates a voucher for a triple according to tPSI-AD protocol"""
        # step 1
        adct = util.aes128_enc(self.adkey, triple.ad)
        # step 2
        prf_sh_x, prf_sh_z, prf_x, prf_r = util.calc_prf(self.fkey, triple.id)
        # step 3
        sh_z = util.calc_poly(prf_sh_x, self.shamir_secret)
        # step 4
        rkey = get_random_bytes(16)
        json_k = ['x', 'z']
        json_v = [prf_sh_x, sh_z]
        sh = json.dumps(dict(zip(json_k, json_v)))
        json_k = ['adct', 'sh']
        json_v = [adct, sh]
        rct_data = json.dumps(dict(zip(json_k, json_v))).encode()
        rct = util.aes128_enc(rkey, rct_data)
        # step 5.1
        w1, w2 = util.calc_h(triple.y, self.server.n_dash, self.server.h1_index, self.server.h2_index)
        # step 5.2
        L = ECC.EccPoint(x=self.pdata[0][0], y=self.pdata[0][1], curve='p256')
        beta1 = random.randint(0, util.ecc_q)
        gamma1 = random.randint(0, util.ecc_q)
        beta2 = random.randint(0, util.ecc_q)
        gamma2 = random.randint(0, util.ecc_q)
        Q1 = beta1 * util.calc_H(triple.y) + gamma1 * util.ecc_gen
        Q2 = beta2 * util.calc_H(triple.y) + gamma2 * util.ecc_gen
        Q1_tuple = (int(Q1.x), int(Q1.y))
        Q2_tuple = (int(Q2.x), int(Q2.y))
        P_w1 = ECC.EccPoint(x=self.pdata[w1 + 1][0], y=self.pdata[w1 + 1][1], curve='p256')
        P_w2 = ECC.EccPoint(x=self.pdata[w2 + 1][0], y=self.pdata[w2 + 1][1], curve='p256')
        S1 = beta1 * P_w1 + gamma1 * L
        S2 = beta2 * P_w2 + gamma2 * L
        # step 5.3
        H_dash_S1 = util.calc_H_dash(S1)
        H_dash_S2 = util.calc_H_dash(S2)
        ct1 = util.aes128_enc(H_dash_S1, rkey)
        ct2 = util.aes128_enc(H_dash_S2, rkey)
        # step 6
        if random.randint(1, 2) == 1:
            voucher = Voucher(triple.id, Q1_tuple, ct1, Q2_tuple, ct2, rct)
        else:
            voucher = Voucher(triple.id, Q2_tuple, ct2, Q1_tuple, ct1, rct)
        return voucher
