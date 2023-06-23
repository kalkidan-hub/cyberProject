import os
import hashlib


class EllipticCurve:
    def __init__(self, p, a, b, G, n):
        self.p = p  # Prime modulus
        self.a = a  # Curve parameter 'a'
        self.b = b  # Curve parameter 'b'
        self.G = G  # Base point
        self.n = n  # Order of the base point


def point_addition(point1, point2, curve):
    # Implementation of point addition operation on the elliptic curve
    if point1 is None:
        return point2
    if point2 is None:
        return point1
    x1, y1 = point1
    x2, y2 = point2
    p = curve.p

    if x1 == x2 and y1 == y2:
        # Point doubling
        m = (3 * x1 ** 2 + curve.a) * pow(2 * y1, -1, p)
    else:
        # Point addition
        m = (y1 - y2) * pow(x1 - x2, -1, p)

    x3 = (m ** 2 - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return x3, y3


def scalar_multiplication(scalar, point, curve):
    # Implementation of scalar multiplication operation on the elliptic curve
    result = None
    current = point

    while scalar:
        if scalar & 1:
            result = point_addition(result, current, curve)
        current = point_addition(current, current, curve)
        scalar >>= 1

    return result


def mod_inverse(number, modulus):
    # Implementation of modular inverse calculation using extended Euclidean algorithm
    if number == 0:
        raise ValueError("Modular inverse does not exist.")
    t, new_t = 0, 1
    r, new_r = modulus, number

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise ValueError("Modular inverse does not exist.")
    if t < 0:
        t += modulus

    return t


# Example elliptic curve parameters
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = -3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

curve = EllipticCurve(p, a, b, G, n)


def hash_message(message):
    # Hash the message using a cryptographic hash function (e.g., SHA-256)
    hashed_message = hashlib.sha256(message).digest()
    return hashed_message


def sign_message(private_key, hashed_message):
    # Generate a random nonce (k) within the range [1, n-1]
    k = int.from_bytes(os.urandom(32), 'big') % (curve.n - 1) + 1

    # Calculate the curve point (r, _) = k * G
    R = scalar_multiplication(k, curve.G, curve)
    r = R[0] % curve.n

    # Calculate the modular inverse of k
    k_inv = mod_inverse(k, curve.n)

    # Calculate the signature component s = k_inv * (hashed_message + r * private_key) mod n
    s = (k_inv * (int.from_bytes(hashed_message, 'big') + (r * private_key))) % curve.n

    # Return the signature (r, s)
    return r, s


def verify_signature(public_key, hashed_message, signature):
    r, s = signature

    # Verify that r and s are within the valid range (0 < r < n and 0 < s < n)
    if r <= 0 or r >= curve.n or s <= 0 or s >= curve.n:
        return False

    # Calculate the modular inverse of s
    s_inv = mod_inverse(s, curve.n)

    # Calculate the curve point u1 = (hashed_message * s_inv) mod n
    u1 = (int.from_bytes(hashed_message, 'big') * s_inv) % curve.n

    # Calculate the curve point u2 = (r * s_inv) mod n
    u2 = (r * s_inv) % curve.n

    # Calculate the curve point R = u1 * G + u2 * public_key
    R = point_addition(scalar_multiplication(u1, curve.G, curve),
                       scalar_multiplication(u2, public_key, curve), curve)

    # Verify that R.x mod n is equal to r
    return R[0] % curve.n == r




private_key = int.from_bytes(os.urandom(32), 'big') % (curve.n - 1) + 1
public_key = scalar_multiplication(private_key, curve.G, curve)

