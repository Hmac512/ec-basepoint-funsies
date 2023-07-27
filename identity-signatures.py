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


random.seed(a='tests2', version=2)

sys.setrecursionlimit(10000000)


def string_to_number(id: str) -> int:
    id_hash = sha384(id.encode("utf-8")).digest()
    return int.from_bytes(id_hash, "big") % bls12_381.bls12_381_curve.curve_order


def random_scalar():
    return random.randint(0, bls12_381.bls12_381_curve.curve_order) % bls12_381.bls12_381_curve.curve_order


def hash_message(msg: str, id: str, Ga: 'Point2D[bls12_381_FQ]') -> int:
    hsh = sha384(msg.encode("utf-8"))
    hsh.update(id.encode("utf-8"))
    hsh.update(str(Ga).encode("utf-8"))
    return int.from_bytes(
        hsh.digest(), "big") % bls12_381.bls12_381_curve.curve_order


def hash_id(Gr: 'Point2D[bls12_381_FQ]', id: str) -> int:
    hsh = sha384(str(Gr).encode("utf-8"))
    hsh.update(id.encode("utf-8"))
    return int.from_bytes(
        hsh.digest(), "big") % bls12_381.bls12_381_curve.curve_order


class IdentityKey:

    curve = bls12_381.bls12_381_curve
    pairing = bls12_381.bls12_381_pairing
    FQ = bls12_381_FQ
    FQ2 = bls12_381_FQ2
    FQ12 = bls12_381_FQ12

    def __init__(self, secret_key: int, master_public_key: 'Point2D[bls12_381_FQ]', id: str, Gr: 'Point2D[bls12_381_FQ]') -> None:
        self.secret_key = secret_key
        self.master_public_key = master_public_key
        self.id = id
        self.Gr = Gr

    def sign(self, msg: str):
        a = random_scalar()
        Ga = self.curve.multiply(self.curve.G1, a)
        hsh_scalar = hash_message(msg, self.id, Ga)

        b = a + ((self.secret_key * hsh_scalar) % self.curve.curve_order)
        return (Ga, b, self.Gr)

    def verify(self, msg: str, Ga: 'Point2D[bls12_381_FQ]', b: int, Gr: 'Point2D[bls12_381_FQ]') -> bool:
        d = hash_message(msg, self.id, Ga)
        c = hash_id(Gr, self.id)

        m1 = self.curve.multiply(self.curve.neg(self.curve.G1), b)
        m2 = self.curve.multiply(
            self.master_public_key, c*d % self.curve.curve_order)
        m3 = self.curve.multiply(Gr, d)

        added_m = self.curve.add(self.curve.add(m1, m2), m3)
        return added_m == self.curve.neg(Ga)


class IdentityManager:

    curve = bls12_381.bls12_381_curve
    pairing = bls12_381.bls12_381_pairing
    FQ = bls12_381_FQ
    FQ2 = bls12_381_FQ2
    FQ12 = bls12_381_FQ12

    def __init__(self, secret_key) -> None:
        self.secret_key = secret_key
        self.public_key_g1 = self.curve.multiply(
            self.curve.G1, self.secret_key)
        self.public_key_g2 = self.curve.multiply(
            self.curve.G2, self.secret_key)

    def generate_child_key(self, id: str) -> 'IdentityKey':
        r = random_scalar()
        Gr = self.curve.multiply(self.curve.G1, r)
        Gr_and_id = hash_id(Gr, id)
        usk = r + ((self.secret_key * Gr_and_id) % self.curve.curve_order)
        usk = usk & self.curve.curve_order
        return IdentityKey(usk, self.public_key_g1, id, Gr)


if __name__ == "__main__":
    sk = random_scalar()
    ibs = IdentityManager(sk)
    id_key = ibs.generate_child_key("child-1|validUntil=<timestamp>")
    (Ga1, b1, Gr1) = id_key.sign("test-msg")
    assert (id_key.verify("test-msg", Ga1, b1, Gr1) == True)
    assert (id_key.verify("test-msg2", Ga1, b1, Gr1) == False)
    print("All tests passed!")
