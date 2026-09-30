#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
题目 12 · 天使大人  (Crypto, 736 pts)  --  Sage-free 等价复现

附件（899 字节，需 SageMath）:
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

本机无 sagemath，且禁止 pip install。这里用「纯 Python + sympy」逐行等价实现：

  * GF(2^8)          -> 手写 GF(2) 多项式模 x^8+x^4+x^3+x+1 (0x11B) 运算
  * .polynomial().list() -> 元素的整数表示，bit i = a^i 的系数 (0/1)
  * NumberField norm -> Res(y^3-y-1, g(y))，并用乘法矩阵行列式二次校验
  * B.LLL() / det    -> 手写精确有理数 LLL (Fraction)；LLL 是幺模变换，|det| 不变，
                        同时用解析 det(B) 交叉校验
  * EllipticCurve.order() -> 逐点计数 y^2 = x^3 + 2x + 3 over GF(10007)

用法:
    source ~/re-tools/fw-env.sh     # 提供 sympy 1.14.0
    python3 scripts/12-solve.py                 # 打印结果
    python3 scripts/12-solve.py --json          # 机器可读
"""
import hashlib
import json
import sys
from fractions import Fraction

# --------------------------------------------------------------------------
# 1) GF(2^8)，模多项式 x^8 + x^4 + x^3 + x + 1  (AES 多项式, 0x11B)
# --------------------------------------------------------------------------
GF_MOD = 0x11B
A = 0b10  # 生成元 a = x


def gf_mul(a: int, b: int) -> int:
    """GF(2^8) 乘法（无进位乘法 + 模 0x11B 约简）"""
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= GF_MOD
    return r & 0xFF


def gf_pow(a: int, e: int) -> int:
    r = 1
    while e:
        if e & 1:
            r = gf_mul(r, a)
        a = gf_mul(a, a)
        e >>= 1
    return r


def gf_add(*xs: int) -> int:
    """GF(2^8) 加法 = 按位异或"""
    r = 0
    for x in xs:
        r ^= x
    return r


# r1 = a^5 + a^2 + 1 ; r2 = a^17 + a^3 + a + 1 ; r3 = a^41 + a^9 + a^4 + 1
r1 = gf_add(gf_pow(A, 5), gf_pow(A, 2), 1)
r2 = gf_add(gf_pow(A, 17), gf_pow(A, 3), A, 1)
r3 = gf_add(gf_pow(A, 41), gf_pow(A, 9), gf_pow(A, 4), 1)

# f = (t-r1)(t-r2)(t-r3) 只有这三个根（等价于验证 assert roots == {r1,r2,r3}）
# 用 GF(2^8) 上的多项式系数向量做一次显式验证：
#   t^3 + s1 t^2 + s2 t + s3,  根集合 = {r1,r2,r3}
s1 = gf_add(r1, r2, r3)                       # -(r1+r2+r3), char 2
s2 = gf_add(gf_mul(r1, r2), gf_mul(r2, r3), gf_mul(r1, r3))
s3 = gf_mul(gf_mul(r1, r2), r3)
for _root in (r1, r2, r3):
    val = gf_add(gf_mul(gf_mul(_root, _root), _root),
                 gf_mul(s1, gf_mul(_root, _root)),
                 gf_mul(s2, _root),
                 s3)
    assert val == 0, f"{_root:#04x} is not a root -> f mismatch"

v = gf_add(gf_mul(r1, r2), r3)

# field_value = sum(ZZ(c) << i for i, c in enumerate(v.polynomial().list()))
# v.polynomial().list() 的第 i 项 = a^i 的系数(0/1) = v 的二进制第 i 位
field_value = 0
for i in range(8):
    c = (v >> i) & 1          # ZZ(c) in {0,1}
    field_value |= c << i
assert field_value == v, "bit convention check failed"

# --------------------------------------------------------------------------
# 2) 数域 K = Q(theta), theta^3 - theta - 1 = 0 ; u = theta^8+3theta^5-2theta+7
#    norm_value = ZZ(u.norm()) = Res(y^3-y-1, y^8+3y^5-2y+7)   (monic => 直接等于范数)
# --------------------------------------------------------------------------
# ⚠️ 本题唯一的坑：K 是【特征 0】的数域，不是 GF(2)。
#    θ³ = θ+1
#    θ⁴ = θ²+θ
#    θ⁵ = θ²+θ+1
#    θ⁶ = θ²+2θ+1     <- 2θ 必须保留（踩坑版把它当特征 2 消成 θ²+1）
#    θ⁷ = 2θ²+2θ+1
#    θ⁸ = 2θ²+3θ+2
#    u = θ⁸ + 3θ⁵ - 2θ + 7 = 5θ² + 4θ + 12  -> norm = 2645   ✅
#    （错误版本 3θ²+2θ+10 -> norm = 1487，答案全错）
def reduce_theta(coeffs):
    """在 Z[theta]/(theta^3-theta-1) 中约简；系数按【升幂】排列，特征 0（保留偶系数）"""
    c = list(coeffs) + [0, 0, 0]
    for k in range(len(c) - 1, 2, -1):
        val = c[k]
        if val:
            c[k] = 0
            c[k - 2] += val   # theta^k = theta^(k-3)*(theta+1) = theta^(k-2) + theta^(k-3)
            c[k - 3] += val
    return tuple(c[:3])


_u_raw = [0] * 9              # theta^8 + 3*theta^5 - 2*theta + 7
_u_raw[0] += 7
_u_raw[1] += -2
_u_raw[5] += 3
_u_raw[8] += 1
U_COEFFS = reduce_theta(_u_raw)          # (12, 4, 5) = 12 + 4θ + 5θ²
assert U_COEFFS == (12, 4, 5), U_COEFFS  # 回归防护：防再次退化成特征 2


def _mul_basis(p, q):
    """基 {1, theta, theta^2} 上的乘法（模 theta^3-theta-1）"""
    raw = [0] * 5
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            raw[i + j] += a * b
    # 约简 theta^3 = theta + 1, theta^4 = theta^2 + theta
    for k in (4, 3):
        c = raw[k]
        if c:
            raw[k] = 0
            raw[k - 2] += c     # theta^k -> theta^(k-3) * (theta + 1)
            raw[k - 3] += c
    return raw[:3]


def number_field_norm_det(coeffs) -> int:
    """乘法矩阵的行列式 = 域范数"""
    one = (1, 0, 0)
    th = (0, 1, 0)
    th2 = (0, 0, 1)
    cols = []
    for basis in (one, th, th2):
        acc = [0, 0, 0]
        for c, b in zip(coeffs, (one, th, th2)):
            if c:
                prod = _mul_basis(b, basis)
                acc = [x + c * y for x, y in zip(acc, prod)]
        cols.append(acc)
    # cols[i] = u * basis_i 的坐标; 矩阵列向量 -> 行列式
    m = [[cols[j][i] for j in range(3)] for i in range(3)]
    return _det_int(m)


def _det_int(m):
    """精确整数行列式（Bareiss / 拉普拉斯，3x3 够用）"""
    if len(m) == 1:
        return m[0][0]
    if len(m) == 2:
        return m[0][0] * m[1][1] - m[0][1] * m[1][0]
    d = 0
    for j in range(len(m)):
        minor = [row[:j] + row[j + 1:] for row in m[1:]]
        d += ((-1) ** j) * m[0][j] * _det_int(minor)
    return d


def number_field_norm_resultant(coeffs) -> int:
    """Res(m, g) with m = y^3-y-1 (monic) => = Norm(g(theta))，用 sympy 校验"""
    from sympy import Poly, QQ, symbols
    y = symbols('y')
    g = sum(c * y ** i for i, c in enumerate(coeffs))
    m = y ** 3 - y - 1
    return int(Poly(m, y, domain=QQ).resultant(Poly(g, y, domain=QQ)))


norm_value = number_field_norm_det(U_COEFFS)
try:
    _norm_alt = number_field_norm_resultant(U_COEFFS)
    assert _norm_alt == norm_value, (norm_alt, norm_value)
except ImportError:
    _norm_alt = None

# --------------------------------------------------------------------------
# 3) B.LLL() -> det_value = abs(L.det())
#    LLL 只做幺模行变换, |det| 不变 => det_value == |det(B)|
#    这里仍然真的跑一遍精确 LLL 以完全复现脚本行为
# --------------------------------------------------------------------------
B = [
    [104729, 0, 0, 31415],
    [0, 104759, 0, 27182],
    [0, 0, 104761, 16180],
    [0, 0, 0, 1],
]


def lll_reduce(basis, delta=Fraction(3, 4)):
    """精确有理数 LLL（行列式在运行前后保持一致）"""
    Bm = [[Fraction(x) for x in row] for row in basis]

    def dot(u, v):
        return sum(a * b for a, b in zip(u, v))

    def gram_schmidt(Bm):
        n = len(Bm)
        star = []
        mu = [[Fraction(0)] * n for _ in range(n)]
        for i in range(n):
            bi = Bm[i][:]
            for j in range(i):
                mu[i][j] = dot(Bm[i], star[j]) / dot(star[j], star[j])
                bi = [x - mu[i][j] * y for x, y in zip(bi, star[j])]
            star.append(bi)
        return star, mu

    n = len(Bm)
    star, mu = gram_schmidt(Bm)
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round(mu[k][j])
                Bm[k] = [x - q * y for x, y in zip(Bm[k], Bm[j])]
                star, mu = gram_schmidt(Bm)
        if dot(star[k], star[k]) >= (delta - mu[k][k - 1] ** 2) * dot(star[k - 1], star[k - 1]):
            k += 1
        else:
            Bm[k], Bm[k - 1] = Bm[k - 1], Bm[k]
            star, mu = gram_schmidt(Bm)
            k = max(k - 1, 1)
    return [[int(x) for x in row] for row in Bm]


L = lll_reduce(B)
det_B = _det_int(B)
det_L = _det_int(L)
assert abs(det_B) == abs(det_L), (det_B, det_L)
det_value = abs(det_L)

# --------------------------------------------------------------------------
# 4) E = EllipticCurve(GF(10007), [2, 3]) ; order_value = E.order()
#    y^2 = x^3 + 2x + 3 over F_10007
# --------------------------------------------------------------------------
EC_P, EC_A, EC_B = 10007, 2, 3
order_value = 1  # 无穷远点
for x in range(EC_P):
    rhs = (x ** 3 + EC_A * x + EC_B) % EC_P
    if rhs == 0:
        order_value += 1
    elif pow(rhs, (EC_P - 1) // 2, EC_P) == 1:
        order_value += 2
# Hasse 区间校验
import math
assert EC_P + 1 - 2 * int(math.isqrt(EC_P)) <= order_value <= EC_P + 1 + 2 * int(math.isqrt(EC_P))

# --------------------------------------------------------------------------
# 5) 最终输出
# --------------------------------------------------------------------------
data = f"{field_value}|{norm_value}|{det_value}|{order_value}"
answer = hashlib.sha256(data.encode()).hexdigest()

if __name__ == "__main__":
    info = {
        "r1": r1, "r2": r2, "r3": r3, "v": v,
        "field_value": field_value,
        "u_in_K": f"{U_COEFFS[2]}*theta^2 + {U_COEFFS[1]}*theta + {U_COEFFS[0]}",
        "norm_value": norm_value,
        "norm_value_resultant_check": _norm_alt,
        "LLL(B)": L,
        "det_B": det_B, "det_L": det_L, "det_value": det_value,
        "order_value": order_value,
        "data": data,
        "answer_sha256": answer,
    }
    if "--json" in sys.argv:
        print(json.dumps(info, ensure_ascii=False, indent=2))
    else:
        print("=== 题目12 天使大人 -- sage-free 复现 ===")
        print(f"GF(2^8) 生成元 a = x, modulus = x^8+x^4+x^3+x+1 (0x11B)")
        print(f"  r1 = a^5+a^2+1        = 0x{r1:02x}")
        print(f"  r2 = a^17+a^3+a+1     = 0x{r2:02x}")
        print(f"  r3 = a^41+a^9+a^4+1   = 0x{r3:02x}")
        print(f"  v  = r1*r2+r3         = 0x{v:02x}")
        print(f"  field_value           = {field_value}")
        print(f"数域 K=Q(theta), theta^3-theta-1=0")
        print(f"  u = theta^8+3theta^5-2theta+7 = {U_COEFFS[2]}theta^2+{U_COEFFS[1]}theta+{U_COEFFS[0]}")
        print(f"  norm_value            = {norm_value}   (resultant 校验: {_norm_alt})")
        print(f"LLL 矩阵 B:")
        for row in B:
            print(f"  {row}")
        print(f"LLL 归约后 L:")
        for row in L:
            print(f"  {row}")
        print(f"  det_value             = {det_value}   (= {104729}*{104759}*{104761})")
        print(f"椭圆曲线 E: y^2=x^3+2x+3 over GF(10007)")
        print(f"  order_value           = {order_value}")
        print()
        print(f"data = {data}")
        print(f"sha256(data) = {answer}")
