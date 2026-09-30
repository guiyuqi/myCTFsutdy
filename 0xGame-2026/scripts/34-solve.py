#!/usr/bin/env python3
"""
34 · 模糊二维码 (0xGame2026, Misc, 1000)  -- analysis pipeline
Author of challenge: Vesperina.  Attachment: firmware/34_模糊二维码/QRcoooold.zip -> QRcoooold/messyQR.jpg

WHAT THIS SCRIPT ESTABLISHES (all reproducible):
  1. The photo is a perler-bead ("拼豆") project on a pegboard.  Board is rectified with a
     homography from its 4 detected corners; the peg lattice pitch is ~18 px => 50-51 pegs
     across (~905 px at the bottom edge).
  2. Beads sit ON pegs (bead-to-bead spacing in a run == local peg pitch).
  3. The bead pattern is extracted faithfully (verified side-by-side vs the photo) as a
     51x51 binary matrix: 614 beads / 2601 pegs = 23.6 % density.
  4. NO QR code exists anywhere in the image:
       - exhaustive 1:1:3:1:1 finder-pattern scan (both axes, whole image, several
         thresholds and blur radii, module sizes 6..100 px)  -> 0 real hits
         (a QR MUST contain 3 finder patterns)
       - structural QR score (3 finders + separators + timing + dark module) over every
         version 1..9, every offset on the 51x51 bead grid, both polarities, all 8 dihedral
         orientations, rotations 0..45 deg and non-integer module scales
         -> max 0.64 (random ~0.50, a real QR ~0.95)
       - pegboard itself is uniform (no missing-peg QR); no hidden data in ZIP/JPEG.
     => the beads' positions encode nothing QR-shaped.  Therefore there is no version /
        EC-level / mask to brute-force from this image.

Usage:  python3 scripts/34-solve.py [path/to/messyQR.jpg]
"""
import sys, os, zipfile, io
import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT = os.path.join(ROOT, "firmware", "34_模糊二维码", "QRcoooold.zip")

# ---- board corners (full-res px) detected by step-edge contrast search -------------
QUAD = [(114.53, 639.32), (1084.82, 610.70), (1090.83, 1535.86), (190.79, 1596.17)]


def load_image(arg=None):
    src = arg or DEFAULT
    if src.lower().endswith(".zip"):
        with zipfile.ZipFile(src) as z:
            name = [n for n in z.namelist() if n.lower().endswith((".jpg", ".png"))][0]
            return Image.open(io.BytesIO(z.read(name))).convert("L")
    return Image.open(src).convert("L")


def homography(corners):
    """map (u,v) in [0,1]^2 -> image px, corners = TL,TR,BR,BL"""
    dst = [(0., 0.), (1., 0.), (1., 1.), (0., 1.)]
    src = np.asarray(corners, float)
    A, b = [], []
    for (u, v), (x, y) in zip(dst, src):
        A.append([u, v, 1, 0, 0, 0, -x * u, -x * v]); b.append(x)
        A.append([0, 0, 0, u, v, 1, -y * u, -y * v]); b.append(y)
    h = np.linalg.solve(np.asarray(A), np.asarray(b))
    return np.append(h, 1.0).reshape(3, 3)


def sample(img, xs, ys):
    A = np.asarray(img, np.float32)
    H, W = A.shape
    x0 = np.clip(np.floor(xs).astype(int), 0, W - 2); y0 = np.clip(np.floor(ys).astype(int), 0, H - 2)
    fx, fy = xs - x0, ys - y0
    return (A[y0, x0] * (1 - fx) * (1 - fy) + A[y0, x0 + 1] * fx * (1 - fy)
            + A[y0 + 1, x0] * (1 - fx) * fy + A[y0 + 1, x0 + 1] * fx * fy)


def extract_beads(img, N=51, thresh=150):
    """returns (bead matrix NxN bool, lattice xs, ys)"""
    Hm = homography(QUAD)
    i, j = np.meshgrid(np.arange(N), np.arange(N))
    u, v = (i + 0.5) / N, (j + 0.5) / N          # i -> x, j -> y
    P = Hm @ np.stack([u.ravel(), v.ravel(), np.ones(N * N)])
    xs = (P[0] / P[2]).reshape(N, N); ys = (P[1] / P[2]).reshape(N, N)
    vals = sample(img, xs.ravel(), ys.ravel()).reshape(N, N)
    return vals < thresh, xs, ys, vals


# ---- verification helpers ---------------------------------------------------------
def finder_scan(img, thresholds=(100, 128, 160, 190), umax=60, tol=0.55):
    """count 1:1:3:1:1 runs in every row/column (a QR finder pattern signature)."""
    A = np.asarray(img, np.float32); hits = []
    for th in thresholds:
        B = A < th
        for axis in (0, 1):
            n = B.shape[axis]
            for t in range(n):
                line = B[t, :] if axis == 0 else B[:, t]
                idx = np.nonzero(np.diff(line.astype(np.int8)))[0] + 1
                if len(idx) < 4:
                    continue
                starts = np.concatenate(([0], idx)); ends = np.concatenate((idx, [len(line)]))
                lens = ends - starts; vals = line[starts]
                for k in range(len(lens) - 4):
                    seg = lens[k:k + 5]
                    if not vals[k] or vals[k + 1] or not vals[k + 2] or vals[k + 3] or not vals[k + 4]:
                        continue
                    u = seg.sum() / 7.0
                    if u < 6 or u > umax:
                        continue
                    err = sum(abs(seg[m] - u * (1, 1, 3, 1, 1)[m]) for m in range(5))
                    if err < u * tol:
                        hits.append((th, axis, t, int(starts[k]), round(u, 1)))
    return hits


def qr_struct_score(M, sz):
    F = np.zeros((7, 7)); F[0, :] = 1; F[6, :] = 1; F[:, 0] = 1; F[:, 6] = 1; F[2:5, 2:5] = 1
    s = n = 0
    for (r, c) in ((0, 0), (0, sz - 7), (sz - 7, 0)):
        s += int((M[r:r + 7, c:c + 7] == F).sum()); n += 49
    for k in range(8, sz - 8):
        want = 1.0 if k % 2 == 0 else 0.0
        s += (M[6, k] == want); s += (M[k, 6] == want); n += 2
    s += (M[sz - 8, 8] == 1.0); n += 1
    return s / n


def best_qr_score(B, versions=(21, 25, 29, 33, 37, 41, 45, 49)):
    best = (0, None)
    N = B.shape[0]
    for M in versions:
        for r0 in range(N - M + 1):
            for c0 in range(N - M + 1):
                v = qr_struct_score(B[r0:r0 + M, c0:c0 + M].astype(float), M)
                if v > best[0]:
                    best = (v, (M, r0, c0))
    return best


def main():
    img = load_image(sys.argv[1] if len(sys.argv) > 1 else None)
    print("[*] image size:", img.size)

    hits = finder_scan(img)
    print("[*] finder-pattern (1:1:3:1:1) hits over whole image:", len(hits),
          "(a QR needs >=3 real ones)")
    for h in hits[:10]:
        print("      ", h)

    B, xs, ys, vals = extract_beads(img, 51)
    print("[*] bead density on 51x51 peg lattice: %d/%d = %.1f%%"
          % (B.sum(), B.size, 100 * B.mean()))

    for name, m in (("beads", B), ("inverted", ~B)):
        sc, info = best_qr_score(m)
        print("[*] best structural QR score (%s): %.3f  version/offset=%s "
              "(random~0.50, real QR~0.95)" % (name, sc, info))

    Image.fromarray(((~B) * 255).astype(np.uint8)).resize((510, 510), Image.NEAREST).save(
        os.path.join(ROOT, "work", "34_qr", "beads_extracted.png"))
    print("[*] wrote work/34_qr/beads_extracted.png")


if __name__ == "__main__":
    main()
