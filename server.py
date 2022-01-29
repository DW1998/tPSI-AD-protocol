import json
import math
import os
import random
import shutil
import util
import nnhash

from Crypto.PublicKey import ECC


# server setup - step 0:
def process_X():
    x = list()
    for img in os.listdir(util.mal_img_dir):
        if img.endswith(".jpg") or img.endswith(".png") or img.endswith(".jpeg"):
            nh = nnhash.calc_nnhash(util.mal_img_dir + img)
            x.append(nh)
    # Remove any duplicates from x
    x = list(dict.fromkeys(x))
    return x


class Server:
    """Represents the server in the tPSI-AD protocol"""
    def __init__(self, name):
        self.name = name
        # keep lists for clients, IDs and vouchers
        self.client_list = list()
        self.client_id_list = list()
        self.client_voucher_list = list()
        self.cur_id = 0  # starting value for triple IDs
        self.t = 3  # threshold value
        self.X = process_X()  # server setup - step 0
        self.h1_index = 0  # index of cuckoo h_1
        self.h2_index = 1  # index of cuckoo h_2
        self.e_dash = 0.3  # factor for size of cuckoo
        self.n_dash = int((1 + self.e_dash) * len(self.X))  # size of cuckoo table
        self.select_cuckoo_hashes(0)  # select hash functions for cuckoo table
        self.cuckoo_table = self.create_cuckoo_table()  # server setup - step 1
        self.alpha = random.randint(0, util.ecc_q)  # server setup - step 2
        self.L = (int((self.alpha * util.ecc_gen).x), int((self.alpha * util.ecc_gen).y))
        self.pdata = self.calc_pdata()  # server setup - step 3 & 4

    def add_client(self, client):
        """Adds the given client to the server."""
        if client.id not in self.client_id_list:
            self.client_list.append(client)
            self.client_id_list.append(client.id)
            self.client_voucher_list.append(list())
            print(f"client {client.id} was added")
            # create new directory for images of client
            path = os.path.join(util.clients_dir, client.id)
            try:
                os.mkdir(path, 0o777)
                print(f"added dir: {path}")
            except OSError:
                pass
        else:
            print(f"ID {client.id} was already found")

    def delete_client(self, client_id):
        """Deletes client from the server for a given client id"""
        if client_id in self.client_id_list:
            index = self.client_id_list.index(client_id)
            self.client_list.pop(index)
            self.client_id_list.pop(index)
            self.client_voucher_list.pop(index)
            print(f"client {client_id} was deleted")
            path_clients_dir = os.path.join(util.clients_dir, client_id)
            path_dec_img_dir = os.path.join(util.dec_img_dir, client_id)
            try:
                shutil.rmtree(path_clients_dir)
                print(f"deleted dir: {path_clients_dir}")
            except OSError:
                pass
            try:
                shutil.rmtree(path_dec_img_dir)
                print(f"deleted dir: {path_dec_img_dir}")
            except OSError:
                pass
        else:
            print(f"ID {client_id} was not found")

    def inc_cur_id(self):
        """Increases the current triple ID counter"""
        self.cur_id += 1

    def select_cuckoo_hashes(self, cnt):
        """Selects two hash function used for the cuckoo table"""
        l = len(util.hash_func_list)
        if cnt == math.factorial(l):
            print(f"Could not find usable hash functions in {cnt} tries")
            return
        collision = False
        for i in self.X:
            h1_x, h2_x = util.calc_h(i, self.n_dash, self.h1_index, self.h2_index)
            if h1_x == h2_x:
                collision = True
                self.h1_index = random.randint(0, l - 1)
                self.h2_index = random.randint(0, l - 1)
                while self.h1_index == self.h2_index:
                    self.h2_index = random.randint(0, l - 1)
                break
        # retry as long as a collision occurs
        if collision:
            self.select_cuckoo_hashes(cnt + 1)

    # Server setup - step 1:
    def create_cuckoo_table(self):
        """Creates the cuckoo table and inserts all hashes"""
        cuckoo_table = dict.fromkeys((range(self.n_dash)))
        for i in self.X:
            self.cuckoo_insert(i, 0, 0, cuckoo_table)
        return cuckoo_table

    def cuckoo_insert(self, x, n, cnt, cuckoo_table):
        """Inserts a specific hash into the cuckoo table"""
        h1_x, h2_x = util.calc_h(x, self.n_dash, self.h1_index, self.h2_index)
        hashes = list()
        hashes.append(h1_x)
        hashes.append(h2_x)
        # if hash is already in the table, discard it
        if cuckoo_table[h1_x] == x or cuckoo_table[h2_x] == x:
            return
        # if there is a cycle, discard the current hash
        if cnt == self.n_dash:
            print(f"Cycle detected, {x} discarded")
            return
        # if slot in table is free, insert it
        if cuckoo_table[hashes[n]] is None:
            cuckoo_table[hashes[n]] = x
            return
        # otherwise move hash currently in slot to its alternating position and insert hash afterwards
        else:
            old_x = cuckoo_table[hashes[n]]
            h1_old_x, h2_old_x = util.calc_h(old_x, self.n_dash, self.h1_index, self.h2_index)
            cuckoo_table[hashes[n]] = x
            new_n = 0
            if n == 0:
                if h1_old_x == h1_x:
                    new_n = 1
            else:
                if h1_old_x == h2_x:
                    new_n = 1
            self.cuckoo_insert(old_x, new_n, cnt + 1, cuckoo_table)

    # Server setup - step 3 & 4
    def calc_pdata(self):
        """Calculates pdata according to tPSI-AD protocol"""
        pdata = list()
        pdata.append(self.L)
        for i in self.cuckoo_table:
            if self.cuckoo_table[i] is None:
                rand = random.randint(0, util.ecc_q)
                ecc_P = rand * util.ecc_gen
            else:
                ecc_P = self.alpha * util.calc_H(self.cuckoo_table[i])
            P = (int(ecc_P.x), int(ecc_P.y))
            pdata.append(P)
        return pdata

    def receive_voucher(self, client, voucher):
        """Receives a voucher from a client and adds it to list of voucher"""
        index = self.client_id_list.index(client.id)
        self.client_voucher_list[index].append(voucher)
        print(f"{self.name} received voucher with ID {voucher.id} from {client.id}")

    def process_vouchers(self):
        """Processes the set of received vouchers according to tPSI-AD protocol"""
        print("processing vouchers")
        index = -1
        IDLIST_GLOBAL = list()
        OUTSET_GLOBAL = list()
        for cl in self.client_voucher_list:
            index = index + 1
            # step 0
            SHARES = list()
            IDLIST = list()
            for v in cl:
                # step 1
                IDLIST.append(v.id)
                Q1 = ECC.EccPoint(x=v.Q1[0], y=v.Q1[1], curve='p256')
                Q2 = ECC.EccPoint(x=v.Q2[0], y=v.Q2[1], curve='p256')
                S1 = self.alpha * Q1
                S2 = self.alpha * Q2
                rkey1 = util.aes128_dec(util.calc_H_dash(S1), v.ct1)
                rkey2 = util.aes128_dec(util.calc_H_dash(S2), v.ct2)
                if rkey1 is None and rkey2 is None:
                    continue
                elif rkey1 is not None and rkey2 is not None:
                    continue
                elif rkey1 is not None:
                    rct_dec = util.aes128_dec(rkey1, v.rct)
                else:
                    rct_dec = util.aes128_dec(rkey2, v.rct)
                if rct_dec is not None:
                    rct = json.loads(rct_dec)
                    adct = rct['adct']
                    sh = rct['sh']
                    SHARES.append((v.id, adct, sh))
            # step 2
            dist_sh = list()
            for s in SHARES:
                dist_sh.append(s[2])
            dist_sh = list(dict.fromkeys(dist_sh))
            t_dash = len(dist_sh)
            if t_dash <= self.t:
                OUTSET = ([x[0] for x in SHARES])
                print("Not enough shares")
            else:
                adkey_int = util.recon_adkey(dist_sh[:self.t + 1])
                adkey = int.to_bytes(adkey_int, 16, "big")
                OUTSET = list()
                for s in SHARES:
                    ad = util.aes128_dec(adkey, s[1])
                    if ad is not None:
                        OUTSET.append((s[0], ad))
                path = f"{util.dec_img_dir}{self.client_id_list[index]}/"
                if not os.path.exists(path):
                    os.mkdir(path, 0o777)
                    print(f"Created Dir: {path}")
                for t in OUTSET:
                    util.save_image(t, path)
            IDLIST_GLOBAL.append(IDLIST)
            OUTSET_GLOBAL.append(OUTSET)
