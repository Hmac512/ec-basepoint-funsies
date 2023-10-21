import py_ecc.bls12_381.bls12_381_curve as curve


# Extended Euclidean algorithm
def mod_inv(x: int, p: int) -> int:
    assert gcd(x, p) == 1, "Divisor %d not coprime to modulus %d" % (x, p)
    z, a = (x % p), 1
    while z != 1:
        q = - (p // z)
        z, a = (p + q * z), (q * a) % p
    return a


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


# There is a faster library with a long startup time (requires pre-computing lookup tables) of the same surface
#
# pip3 install galois
# from galois import GF, lagrange_poly
def lagrange_polynomial(points: list[tuple[int, int]], prime=curve.curve_order) -> list[int]:
    return interpolate_polynomial([i[0] for i in points], [k[1] for k in points], prime)


# lagrange interpolation reduced mod p (finite fields)
def interpolate_polynomial(x: list[int], y: list[int], prime: int) -> list[int]:
    M = [[_x**i*(-1)**(i*len(x)) for _x in x] for i in range(len(x))]
    N = [(M+[y]+M)[d:d+len(x)] for d in range(len(x)+1)]
    C = [determinant(k) for k in N]
    fac = mod_inv(C[0] * (-1)**(len(x)+1), prime)
    C = [i*fac % prime for i in C]
    return C[1:]


# Evaluate polynomial at x value
def evaluate_polynomial(polynomial: list[int], x_value: int, prime=curve.curve_order) -> int:
    result = polynomial[-1]
    for i in range(2, len(polynomial)+1):
        result = result*x_value
        result = result + polynomial[-i]
    return result % prime


# Divide polynomial (x - divisor)
def polynomial_division(polynomial: list[int], divisor: int, prime=curve.curve_order) -> tuple[list[int], int]:
    polynomial.reverse()
    c1 = polynomial[0]
    remainder = polynomial[1]
    final_polynomial = []
    for i in range(len(polynomial)-1):
        final_polynomial.append(c1)
        c1 = ((prime-1)*c1*divisor+remainder) % prime
        if i < len(polynomial)-2:
            remainder = polynomial[i+2]
    final_polynomial.reverse()
    return final_polynomial, remainder


# Your standard determinant
def determinant(m: list[list[int]]) -> int:
    M = [row[:] for row in m]
    N, sign, prev = len(M), 1, 1
    for i in range(N-1):
        if M[i][i] == 0:
            swapto = next((j for j in range(i+1, N) if M[j][i] != 0), None)
            if swapto is None:
                return 0
            M[i], M[swapto], sign = M[swapto], M[i], -sign
        for j in range(i+1, N):
            for k in range(i+1, N):
                assert (M[j][k] * M[i][i] - M[j][i] * M[i][k]) % prev == 0
                M[j][k] = (M[j][k] * M[i][i] - M[j][i] * M[i][k]) // prev
        prev = M[i][i]
    return sign * M[-1][-1]
