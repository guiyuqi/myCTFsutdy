#!/usr/bin/env python3
"""12079 Chronos-Vault - trit-channel audit (run 2).

Verified facts (fast, <300MB):
  * 42 cards = comps of size 1670..1680 (the 8977-point comp is the noise slab).
  * Lattice points have EXACTLY 3 distinct values per scale axis; the triple is
    always a permutation of them.
  * Permutation PARITY is a perfect group discriminator:
      lattice: 100% one parity class (3 permutations)
      noise  : all 6 permutations, ~1/6 each
  * The only payload-capable channel on lattice points is WHICH of the 3
    same-parity permutations -> 1.585 bit/point -> ~13.9 KB over 70560 points.
  * Noise-point scale magnitudes are continuous, broad (mean -6.8, skew -1.75),
    a DIFFERENT distribution from the 3 lattice levels -> not a trivially
    decodable second channel.
  * Lattice INDEX recovery is the blocker: mutual-4NN mesh graph has chords
    (dA+dB==D holds only 5.1%), so corner-BFS unwrap fails.
"""
import numpy as np, pickle, itertools, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'work', '12079_chronos'))
from ply_io import read_ply

PLY = os.path.join(os.path.dirname(__file__), '..', 'work', '12079_chronos', 'handout', 'point_cloud.ply')
txt, props, d = read_ply(PLY)
xyz = np.stack([d['x'], d['y'], d['z']], 1).astype(np.float64)
sc = np.stack([d['scale_0'], d['scale_1'], d['scale_2']], 1).astype(np.float64)
comps = pickle.load(open(os.path.join(os.path.dirname(__file__), '..', 'work', '12079_chronos', 'comps.pkl'), 'rb'))
cards = [np.array(c) for c in comps if 1670 <= len(c) <= 1680]
assert len(cards) == 42, len(cards)
lat = np.concatenate(cards)
print('PLY: %d pts / %d props; cards=%d, lattice=%d, noise=%d'
      % (len(d), len(props), len(cards), len(lat), len(d) - len(lat)))

r = np.argsort(np.argsort(sc, 1), 1)
sgn = np.sign((r[:, 0]-r[:, 1])*(r[:, 1]-r[:, 2])*(r[:, 0]-r[:, 2]))
lpar = np.unique(sgn[lat]); npar = np.unique(sgn[~lat])
print('permutation classes present: lattice sign=%s  noise sign=%s' % (lpar, npar))
print('lattice permutation counts:', {p: int(((r[lat] == np.array(p)).all(1)).sum())
      for p in itertools.permutations(range(3))})
print('noise   permutation counts:', {p: int(((r[~lat] == np.array(p)).all(1)).sum())
      for p in itertools.permutations(range(3))})
for k in range(3):
    u = np.unique(sc[lat, k])
    print('axis%d lattice distinct values=%d -> %s' % (k, len(u), np.round(u, 4)))
v = sc[~lat]
print('noise scale mean=%s std=%s' % (np.round(v.mean(0), 3), np.round(v.std(0), 3)))
bits = len(lat)*np.log2(3)
print('payload capacity of trit channel: %.0f trits = %.0f bits = %.0f bytes' % (len(lat), bits, bits/8))
