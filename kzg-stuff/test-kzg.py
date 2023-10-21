import random
import kzg
from polynomial import evaluate_polynomial
import time
if __name__ == '__main__':
    print("Testing kzg")
    start_time = time.time()
    st = start_time
    # run trusted setup and store public setup points
    setup_g1_points, setup_g2_point = kzg.trusted_setup()
    t = time.time() - start_time
    print("Generated trusted setup (took %.2fs)" % t)

    # encode data as polynomial P(x)
    data = b'\x99'*460
    points, encoded_polynomial = kzg.encode_as_polynomial(data)

    # create kzg commitment to P(x) using trusted setup points
    start_time = time.time()
    C = kzg.commit(encoded_polynomial, setup_g1_points)
    t = time.time() - start_time
    print("Generated KZG commitment (took %.2f)" % t)

    # choose some point on P(x) to prove
    reveal_index = random.randrange(len(points))

    x_to_reveal, _ = points[reveal_index]

    point = (x_to_reveal, evaluate_polynomial(encoded_polynomial, x_to_reveal))

    assert points[reveal_index][0] == point[0], "xs should be equal"
    assert points[reveal_index][1] == point[1], "ys should be equal"

    # generate kzg proof that point is on polynomial
    start_time = time.time()
    pi = kzg.proof(encoded_polynomial, point, setup_g1_points)
    t = time.time() - start_time
    print("Generated KZG proof of evaluation (took %.2fs)" % t)

    # verifier can verify proof that some (x,y) point is on P(x)
    # with only commitment C, proof pi, the point in question
    # and public trusted_setup curve points
    print("Now verifying proofs, this takes the longest because the pairing operation is very expensive")
    start_time = time.time()
    assert kzg.verify(C, pi, point, setup_g2_point), "proof not verified"
    t = time.time() - start_time
    print("Verified KZG proof of evaluation (took %.2fs)" % t)
    print("Success! everything took %.2fs" % (time.time() - st))
