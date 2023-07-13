
import random

INF_POINT = None


class EllipticCurve:
    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b

    def addition(self, P1, P2):
        if P1 == INF_POINT:
            return P2
        if P2 == INF_POINT:
            return P1

        (x1, y1) = P1
        (x2, y2) = P2

        if self.equal_modp(x1, x2) and self.equal_modp(y1, -y2):
            return INF_POINT

        if self.equal_modp(x1, x2) and self.equal_modp(y1, y2):
            u = self.reduce_modp((3 * x1 * x1 + self.a) *
                                 self.inverse_modp(2 * y1))
        else:
            u = self.reduce_modp((y1 - y2) * self.inverse_modp(x1 - x2))

        v = self.reduce_modp(y1 - u * x1)
        x3 = self.reduce_modp(u * u - x1 - x2)
        y3 = self.reduce_modp(-u * x3 - v)
        return (x3, y3)

    def multiple(self, k, P):
        Q = INF_POINT
        i = 0
        j = 0
        while k != 0:
            if k & 1 != 0:
                i += 1
                Q = self.addition(Q, P)
            j += 1
            P = self.addition(P, P)
            k >>= 1
        return Q

    def is_point_on_curve(self, x, y):
        return self.equal_modp(y * y, x * x * x + self.a * x + self.b)

    # helper functions

    def reduce_modp(self, x):
        return x % self.p

    def equal_modp(self, x, y):
        return self.reduce_modp(x - y) == 0

    def inverse_modp(self, x):
        if self.reduce_modp(x) == 0:
            return None
        return pow(x, p - 2, p)


p = 26959946667150639794667015087019630673557916260026308143510066298881
a = -3
b = 18958286285566608000408668544493926415504680968679321075787234672564

P224 = EllipticCurve(p, a, b)

Gx = 19277929113566293071110308034699488026831934219452440156649784352033
Gy = 19926808758034470970197974370888749184205991990603949537637343198772
G = (Gx, Gy)

print("Check that generator point is on curve: %s" %
      P224.is_point_on_curve(Gx, Gy))

Q = P224.multiple(1, G)
print("Check generator point times 1 is equal to itself: %s" % (Q == G))


# Number of points in P256 sub-group
n = 26959946667150639794667015087019625940457807714424391721682722368061

Q = P224.multiple(n - 1, G)

print("Multiply the generator point by 1 minus the size of the sub-group (last point in group) result: \n\n\tX:%i\n\tY:%i\n" % Q)


print("Check to make sure the last point in the group is on the curve: %s" %
      (P224.is_point_on_curve(Q[0], Q[1])))

Q = P224.multiple(n, G)
print("Check that the group loops back around to the first element of the group (point at infinity): %s" % (Q == INF_POINT))


Z = P224.multiple(n+1, G)
print("Check that the group loops back around to the second element of the group (generator point): %s" % (Z == G))


alice_private_key = random.randint(0, 2**223)
print("\nGenerate random P224 private key for Alice:\n\n\t%s\n" %
      alice_private_key)

alice_public_key = P224.multiple(alice_private_key, G)
print("Generate the associated public key for Alice's private key: \n\n\tX:%i\n\tY:%i\n" %
      alice_public_key)

bob_private_key = random.randint(0, 2**223)
print("\nGenerate random P224 private key for Bob:\n\n\t%s\n" % bob_private_key)

bob_public_key = P224.multiple(bob_private_key, G)
print("Generate the associated public key for Bob's private key: \n\n\tX:%i\n\tY:%i\n" % bob_public_key)


alice_ecdh = P224.multiple(alice_private_key, bob_public_key)
bob_ecdh = P224.multiple(bob_private_key, alice_public_key)

print("Generated ECDH shared secret: \n\n\tX:%i\n\tY:%i\n" % alice_ecdh)

print("Check both Alice and Bob generate the same shared secret: %s" %
      (alice_ecdh == bob_ecdh))

# For funsies

combined_private_key = alice_private_key * bob_private_key

combined_key_public_key = P224.multiple(combined_private_key, G)

print("Check combining private keys is equivalent to ECDH: %s" %
      (alice_ecdh == combined_key_public_key))
