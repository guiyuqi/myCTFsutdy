import numpy as np, sys
sys.path.insert(0,'shared')
from mlkem import *
rng = np.random.default_rng(1)
a = rng.integers(0,Q,256); b = rng.integers(0,Q,256)
# roundtrip
assert np.array_equal(invntt(ntt(a)) , a%Q), "ntt roundtrip fail"
# mul consistency
m1 = invntt(basemul_ntt(ntt(a), ntt(b)))
m2 = np.array(naive_negacyclic_mul(a,b))
print("mul match:", np.array_equal(m1, m2))
# samplentt determinism + range
s = sample_ntt(bytes(range(32)),0,1)
print("sample ok", s.min(), s.max())
