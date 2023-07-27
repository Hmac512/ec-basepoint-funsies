import random
import pytest

from py_ecc import (
    bls12_381,
)

from py_ecc.fields import (
    bls12_381_FQ,
    bls12_381_FQ2,
    bls12_381_FQ12,

)

from py_ecc.utils import (
    prime_field_inv,
)

from hashlib import sha256
random.seed(a='tests2', version=2)
class Accumulator:

    curve = bls12_381.bls12_381_curve
    pairing = bls12_381.bls12_381_pairing
    FQ = bls12_381_FQ
    FQ2 = bls12_381_FQ2
    FQ12 = bls12_381_FQ12



    def __init__(self, secret_key) -> None:
        self.secret_key = secret_key
        self.public_key_g1 = self.curve.multiply(self.curve.G1, self.secret_key)
        self.public_key_g2 = self.curve.multiply(self.curve.G2, self.secret_key)
        self.elements = []
        self.value = self.curve.G1


    def add_element_hash(self, element:bytes):
        self.elements.append(element)
        scalar = int.from_bytes(element, "big") + self.secret_key
        self.value = self.curve.multiply(self.value, scalar)

    def remove_element_hash(self, element:bytes):
        self.elements.remove(element)
        scalar = int.from_bytes(element, "big") + self.secret_key
        inv_scalar = prime_field_inv(scalar, self.curve.curve_order)
        self.value = self.curve.multiply(self.value, inv_scalar)

    def remove_element(self, element:str):
        element_hash = sha256(element.encode("utf-8")).digest()
        self.remove_element_hash(element_hash)

    def batch_add_elements(self, elements:list[str]):
        for element in elements:
            element_hash = sha256(element.encode("utf-8")).digest()
            self.add_element_hash(element_hash)

    # Membership Witness. Let (V, YV ) be an accumulator state and y an element
    # inACC.Thenwy,V isamembershipwitnessforywithrespecttotheaccumulator
    # value V if C = 1 V and wy,V = C. The Accumulator Manager issues the y+α
    # membership witness wy,V to a user associated to the element y, in order to permit him to prove that y is accumulated into V .3
    def generate_membership_witness(self, element:str):
        element_hash = sha256(element.encode("utf-8")).digest()
        scalar = int.from_bytes(element_hash, "big") + self.secret_key
        inv_scalar = prime_field_inv(scalar, self.curve.curve_order)
        return self.curve.multiply(self.value, inv_scalar)


    #  e(C, y*G2 + pk_g2) = e(V, G2)
    def verify_membership_witness(self, witness, element:str):
        element_hash = sha256(element.encode("utf-8")).digest()
        scalar = int.from_bytes(element_hash, "big")

        yg2 = self.curve.multiply(self.curve.G2, scalar)
        yg2_pk_g2 = self.curve.add(yg2, self.public_key_g2)
        pairing1 = self.pairing.pairing(yg2_pk_g2, witness)

        pairing2 = self.pairing.pairing(self.curve.G2, self.value)
        return pairing1 == pairing2


def test1(sk):

    elements = ['1', '2']
    accumulator1 = Accumulator(sk)
    accumulator1.batch_add_elements(elements)
    accumulator1.remove_element('2')

    accumulator2 = Accumulator(sk)
    accumulator2.batch_add_elements(['1'])
    assert(accumulator1.value==accumulator2.value)

def test2(sk):
    elements = ['1', '2', '4', '5', '6']
    accumulator1 = Accumulator(sk)
    accumulator1.batch_add_elements(elements)

    witness1 = accumulator1.generate_membership_witness('1')
    assert(accumulator1.verify_membership_witness(witness1, '1') == True)
    assert(accumulator1.verify_membership_witness(witness1, '2') == False)

    witness2 = accumulator1.generate_membership_witness('2')
    assert(accumulator1.verify_membership_witness(witness2, '2') == True)
    assert(accumulator1.verify_membership_witness(witness2, '1') == False)

    witness3 = accumulator1.generate_membership_witness('3')
    assert(accumulator1.verify_membership_witness(witness3, '1') == False)
    assert(accumulator1.verify_membership_witness(witness3, '2') == False)




if __name__ == "__main__":
    sk = random.randint(0, bls12_381.bls12_381_curve.curve_order)
    test1(sk)
    test2(sk)

