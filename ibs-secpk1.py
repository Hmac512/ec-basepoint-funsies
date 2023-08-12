import sys
import random
import pytest

import secp256k1


from py_ecc.utils import (
    prime_field_inv,
)

from hashlib import sha384

from py_ecc.typing import (
    PlainPoint2D
)


random.seed(a='tests2', version=2)

sys.setrecursionlimit(10000000)


def string_to_number(id: str) -> int:
    id_hash = sha384(id.encode("utf-8")).digest()
    return int.from_bytes(id_hash, "big") % secp256k1.N


def random_scalar():
    return random.randint(0, secp256k1.N) % secp256k1.N


def hash_message(msg: str, id: str, Ga: 'PlainPoint2D') -> int:
    hsh = sha384(msg.encode("utf-8"))
    hsh.update(id.encode("utf-8"))
    hsh.update(str(Ga).encode("utf-8"))
    return int.from_bytes(
        hsh.digest(), "big") % secp256k1.N


def hash_id(Gr: 'PlainPoint2D', id: str) -> int:
    hsh = sha384(str(Gr).encode("utf-8"))
    hsh.update(id.encode("utf-8"))
    return int.from_bytes(
        hsh.digest(), "big") % secp256k1.N


class IdentityKey:

    curve = secp256k1

    def __init__(self, secret_key: int, master_public_key: 'PlainPoint2D', id: str, Gr: 'PlainPoint2D') -> None:
        self.secret_key = secret_key
        self.master_public_key = master_public_key
        self.id = id
        self.Gr = Gr

    def sign(self, msg: str):
        a = random_scalar()
        Ga = self.curve.multiply(self.curve.G, a)
        hsh_scalar = hash_message(msg, self.id, Ga)

        b = a + ((self.secret_key * hsh_scalar) % self.curve.N)
        return (Ga, b, self.Gr)

    def verify(self, msg: str, Ga: 'PlainPoint2D', b: int, Gr: 'PlainPoint2D') -> bool:
        d = hash_message(msg, self.id, Ga)
        c = hash_id(Gr, self.id)

        m1 = self.curve.multiply(self.curve.neg(self.curve.G), b)
        m2 = self.curve.multiply(
            self.master_public_key, c*d % self.curve.N)
        m3 = self.curve.multiply(Gr, d)

        added_m = self.curve.add(self.curve.add(m1, m2), m3)
        print(added_m)
        print(self.curve.neg(Ga))
        return added_m == self.curve.neg(Ga)


class IdentityManager:

    curve = secp256k1

    def __init__(self, secret_key) -> None:
        self.secret_key = secret_key
        self.public_key_g1 = self.curve.multiply(
            self.curve.G, self.secret_key)

    def generate_child_key(self, id: str) -> 'IdentityKey':
        r = random_scalar()
        Gr = self.curve.multiply(self.curve.G, r)
        Gr_and_id = hash_id(Gr, id)
        usk = r + ((self.secret_key * Gr_and_id) % self.curve.N)
        usk = usk & self.curve.N
        return IdentityKey(usk, self.public_key_g1, id, Gr)


if __name__ == "__main__":
    sk = random_scalar()
    ibs = IdentityManager(sk)
    id_key = ibs.generate_child_key("child-1|validUntil=<timestamp>")
    (Ga1, b1, Gr1) = id_key.sign("test-msg")
    assert (id_key.verify("test-msg", Ga1, b1, Gr1) == True)
    assert (id_key.verify("test-msg2", Ga1, b1, Gr1) == False)
    print("All tests passed!")
