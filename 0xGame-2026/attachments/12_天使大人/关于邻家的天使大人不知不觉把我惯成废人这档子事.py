from hashlib import sha256

P.<x> = PolynomialRing(GF(2))
F.<a> = GF(2^8, modulus=x^8 + x^4 + x^3 + x + 1)
R.<t> = PolynomialRing(F)

r1 = a^5 + a^2 + 1
r2 = a^17 + a^3 + a + 1
r3 = a^41 + a^9 + a^4 + 1

f = (t - r1) * (t - r2) * (t - r3)
roots = {root for root, _ in f.roots()}

assert roots == {r1, r2, r3}

v = r1 * r2 + r3
field_value = sum(ZZ(c) << i for i, c in enumerate(v.polynomial().list()))

S.<y> = PolynomialRing(QQ)
K.<theta> = NumberField(y^3 - y - 1)

u = theta^8 + 3 * theta^5 - 2 * theta + 7
norm_value = ZZ(u.norm())

B = Matrix(ZZ, [
    [104729, 0, 0, 31415],
    [0, 104759, 0, 27182],
    [0, 0, 104761, 16180],
    [0, 0, 0, 1]
])

L = B.LLL()
det_value = abs(L.det())

E = EllipticCurve(GF(10007), [2, 3])
order_value = E.order()

data = f"{field_value}|{norm_value}|{det_value}|{order_value}"

print(sha256(data.encode()).hexdigest())