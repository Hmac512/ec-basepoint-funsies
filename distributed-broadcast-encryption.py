# Based on https://eprint.iacr.org/2023/874.pdf
import sys
import random
import pytest

from py_ecc import (
    bls12_381,
)
from py_ecc.bls import point_compression

from py_ecc.fields import (
    bls12_381_FQ,
    bls12_381_FQ2,
    bls12_381_FQ12,

)

from py_ecc.utils import (
    prime_field_inv,
)

from hashlib import sha384

from py_ecc.typing import (
    Point2D,
)

random.seed(a='test', version=2)


def modP(val: int) -> int:
    return val % bls12_381.bls12_381_curve.curve_order


def random_scalar() -> int:
    return modP(random.randint(0, bls12_381.bls12_381_curve.curve_order))


class User:

    curve = bls12_381.bls12_381_curve
    pairing = bls12_381.bls12_381_pairing
    FQ = bls12_381_FQ
    FQ2 = bls12_381_FQ2
    FQ12 = bls12_381_FQ12

    def __init__(self, slot: int, group: 'Group'):
        self.t = random_scalar()
        self.slot = slot
        self.group = group
        self.secret_key = self.curve.multiply(self.curve.G2, modP(
            self.t * modP((group.alpha)**(group.max_size + 1 - slot))))
        self.public_key = [self.curve.multiply(self.curve.G2, self.t)]

        for i in range(group.max_size):
            slot_scalar = modP(self.t * (group.alpha**i))
            slot_key = self.curve.multiply(self.curve.G2, slot_scalar)
            self.public_key.append(slot_key)


    def encrypt(self, msg:int):
        s = random_scalar()
        item1 = self.curve.multiply(self.curve.G1, s)
        item2_prod = 0

        for user in self.group.users:
            part1 = self.curve.multiply(user.public_key[0], s)
            part2 = self.curve.multiply(self.curve.G1, modP(self.group.alpha ** user.slot))
            part = self.curve.add(part1, part2)




class Group:

    curve = bls12_381.bls12_381_curve
    pairing = bls12_381.bls12_381_pairing
    FQ = bls12_381_FQ
    FQ2 = bls12_381_FQ2
    FQ12 = bls12_381_FQ12

    def __init__(self, alpha: int, master_secret_key: int, max_size: int):
        self.max_size = max_size
        self.alpha = alpha
        self.public_params: list['Point2D[bls12_381_FQ]'] = []

        self.master_secret_key = master_secret_key
        self.master_public_key_G1 = self.curve.multiply(
            self.curve.G1, master_secret_key)
        self.master_public_key_G2 = self.curve.multiply(
            self.curve.G2, master_secret_key)

        for i in range(max_size*2):
            alpha_raised = modP(alpha ** (i+1))
            alpha_G1: 'Point2D[bls12_381_FQ]' = self.curve.multiply(
                self.curve.G1, alpha_raised)
            self.public_params.append(alpha_G1)

        self.users:list['User'] = []

        for i in range(max_size):
            user = User(i+1, self)
            self.users.append(user)



if __name__ == "__main__":
    alpha = random_scalar()
    master_secret_key = random_scalar()
    num_users = 5
    group1 = Group(alpha, master_secret_key, num_users)

    user1 = group1.users[1]
