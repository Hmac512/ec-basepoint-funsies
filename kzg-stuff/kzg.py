import py_ecc.bls12_381.bls12_381_curve as curve
import py_ecc.bls12_381.bls12_381_pairing as pairing
from py_ecc.typing import (
    Point2D,
    Field

)
from polynomial import lagrange_polynomial, polynomial_division

from binascii import hexlify
from utils import format_data
import random
random.seed(a='test', version=2)

# Number of polynomial coeffs
default_length = 16
# simple way to get chunks that safely map to GF(n)
chunk_size = 31


def random_scalar(max_val=curve.curve_order) -> int:
    return random.randint(0, max_val)


def trusted_setup(length=default_length) -> tuple[list[Point2D[Field]], Point2D[Field]]:
    # This is our secret value used for the trusted setup
    # Anyone who knows S can generate false proofs
    # In practice we do MPC or some ceremony to generate this number
    # and as long as one party is honest S is unknown to all.
    S = random_scalar()
    trusted_points: list[Point2D[Field]] = []
    for i in range(length):
        s_power = (S**i) % curve.curve_order
        trusted_points.append(curve.multiply(curve.G1, s_power))
    g2_point = curve.multiply(curve.G2, S)
    # trusted_points = [G1, G1*s^2, G1*s^3 ...]
    # g2_point = s*G2, where G2 is the generator of the extension field of the base curve
    return (trusted_points, g2_point)


# Convert bytes into a polynomial
def encode_as_polynomial(data, length=default_length) -> tuple[list[tuple[int, int]], list[int]]:
    data = format_data(data, length*chunk_size)
    points: list[tuple[int, int]] = []
    for i in range(length):
        x = i
        y = int(hexlify(data[i*chunk_size:(i+1)*chunk_size]).decode(), 16)
        points.append((x, y))

    polynomial = lagrange_polynomial(points)
    return points, polynomial


# Evaluate the polynomial at the secret point S (from trusted setup)
def commit(polynomial: list[int], setup_g1: list[Point2D[Field]]) -> Point2D[Field]:
    assert len(polynomial) == len(setup_g1), "polynomial is not right size"

    # start at 0
    running_sum = curve.multiply(curve.G1, 0)

    for poly_coeff, setup_point in zip(polynomial, setup_g1):
        term_evaluation = curve.multiply(setup_point, poly_coeff)
        running_sum = curve.add(running_sum, term_evaluation)

    return running_sum


# Generate KZG proof of evalatuation of commited polynomial at provided point
def proof(polynomial: list[int], point: tuple[int, int], setup_g1: list[Point2D[Field]]) -> Point2D[Field]:
    assert len(polynomial)-1 <= len(setup_g1), "polynomial is not right size"

    # Write algebra to document why this works
    px_minus_y = polynomial.copy()
    px_minus_y[0] = ((curve.curve_order-1)*point[1] +
                     polynomial[0]) % curve.curve_order

    qx, remainder = polynomial_division(
        px_minus_y, (curve.curve_order-1)*point[0])
    assert remainder == 0, "point is not on polynomial"

    # start at 0
    running_sum = curve.multiply(curve.G1, 0)

    for poly_coeff, setup_point in zip(qx, setup_g1[:len(qx)]):
        term_evaluation = curve.multiply(setup_point, poly_coeff)
        running_sum = curve.add(running_sum, term_evaluation)

    return running_sum


# Verify our proof that our point is on the previously commited polynomial
def verify(commitment: Point2D[Field], proof: Point2D[Field], point: tuple[int, int], setup_g2: Point2D[Field]) -> bool:
    s_minus_x = curve.add(
        curve.multiply(curve.G2, curve.curve_order-point[0]),
        setup_g2)
    result = pairing.pairing(s_minus_x, proof)
    c_minus_y = curve.add(
        curve.multiply(curve.G1, curve.curve_order-point[1]),
        commitment
    )
    expected = pairing.pairing(curve.G2, c_minus_y)
    return result == expected


# Generate KZG proof of append only
# We are taking advantage of the additively homomorphic property
# of polynomial commitments
def commit_diff(polynomial1: list[int], polynomial2: list[int], setup_g1: list[Point2D[Field]]) -> Point2D[Field]:
    assert len(polynomial1)-1 <= len(setup_g1), "polynomial1 is not right size"
    assert len(polynomial2)-1 <= len(setup_g1), "polynomial2 is not right size"

    polynomial_diff = []
    for p1, p2 in zip(polynomial1, polynomial2):
        polynomial_diff.append(p2-p1)

    # make sure we have one term only
    assert (polynomial_diff[:-1] == [0]*15)

    # Our proof should be just evaluating the difference polynomial at the secret value

    sG_term = setup_g1[-1]
    coeff = polynomial_diff[-1]
    pi = curve.multiply(sG_term, coeff)
    return pi, polynomial_diff


# Verify append only
def verify_append_only(commitment1: Point2D[Field], commitment2: Point2D[Field], diff_commit: Point2D[Field], diff_pi: Point2D[Field], point: tuple[int, int], setup_g2: Point2D[Field]) -> bool:
    # add c2 and -c1
    expected = curve.add(commitment2, curve.neg(commitment1))
    # should be equal
    if expected != diff_commit:
        return False
    # Verify normal eval proof
    return verify(diff_commit, diff_pi, point, setup_g2)
