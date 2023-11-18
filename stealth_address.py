import sys
import random
import pytest


from py_ecc.utils import (
    prime_field_inv,
)
from eth_hash.auto import keccak
import secp256k1
from py_ecc.typing import (
    PlainPoint2D
)


random.seed(a='tests2', version=2)

sys.setrecursionlimit(10000000)


def string_to_number(id: str) -> int:
    id_hash = keccak.hasher(id.encode("utf-8"))
    return int.from_bytes(id_hash, "big") % secp256k1.N


def random_scalar():
    return random.randint(0, secp256k1.N) % secp256k1.N


class MainKey:

    curve = secp256k1

    def __init__(self) -> None:
        self.secret_key = random_scalar()
        self.public_key = secp256k1.multiply(secp256k1.G, self.secret_key)

    def generate_stealth_address(self) -> tuple["PlainPoint2D", int, "PlainPoint2D"]:
        ephemeral_key = random_scalar()
        ephemeral_public_key = secp256k1.multiply(secp256k1.G, ephemeral_key)

        shared_secret_1 = secp256k1.multiply(
            ephemeral_public_key, self.secret_key)
        shared_secret_2 = secp256k1.multiply(self.public_key, ephemeral_key)
        assert shared_secret_1 == shared_secret_2
        ssx, ssy = shared_secret_1
        str_sxy = f"{ssx}{ssy}"
        s = string_to_number(str_sxy)
        sG = secp256k1.multiply(secp256k1.G, s)

        stealth_private_key = s + self.secret_key
        stealth_public_key = secp256k1.add(sG, self.public_key)

        return (ephemeral_public_key, stealth_private_key, stealth_public_key)


if __name__ == "__main__":
    key = MainKey()
    ephemeral_public_key, stealth_private_key, stealth_public_key = key.generate_stealth_address()
    print("Ephemeral Public Key: \n\n\tX:%i\n\tY:%i\n" % ephemeral_public_key)
    print("Stealth Secret Key: \n\n\t%i\n" % stealth_private_key)
    print("Stealth address: \n\n\t%s\n" %
          secp256k1.pub_to_address(stealth_public_key))
