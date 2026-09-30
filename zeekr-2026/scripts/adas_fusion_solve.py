#!/usr/bin/env python3
"""GEELY FRONT ADAS FUSION ACCEPTANCE / BUILD 8.7.2  (attachments4.zip)

Recover the accepted INJECT rows, validate all six acceptance rules, derive flag.
"""
import hashlib, hmac, json, os, sys
import numpy as np

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..',
                    'work/attachments4/attachments')
YAML = os.path.join(BASE, 'calibration/camera_radar_calibration.yaml')
PROF = os.path.join(BASE, 'protocol/fusion_acceptance.txt')
JSONL = os.path.join(BASE, 'evidence/adas_frames.jsonl')

# --- calibration -------------------------------------------------------
Rc = np.array([[0.999390827019096, -0.034899496702501, 0.0],
               [0.034899496702501, 0.999390827019096, 0.0],
               [0.0, 0.0, 1.0]])
tc = np.array([1.820, -0.040, 1.460])
Rr = np.array([[0.999847695156391, 0.017452406437283, 0.0],
               [-0.017452406437283, 0.999847695156391, 0.0],
               [0.0, 0.0, 1.0]])
tr = np.array([0.150, 0.030, 0.520])
YAW = 0.008

frames = [json.loads(l) for l in open(JSONL) if l.strip()]

print("== recovered vehicle-frame positions (p_v = R @ p_s + t) ==")
P = {}
for f in frames:
    c = np.array(f['camera_targets'][0]['position_camera_m'])
    r = np.array(f['radar_tracks'][0]['position_radar_m'])
    pv_c, pv_r = Rc @ c + tc, Rr @ r + tr
    print(f"  frame{f['frame']} cam={np.round(pv_c,4)} rad={np.round(pv_r,4)} "
          f"|cam-rad|={np.linalg.norm(pv_c-pv_r):.4f}")
    P[f['frame']] = (pv_c + pv_r) / 2.0

# design/quantised truth (rows must use exactly 3 decimals -> snap to 1e-3)
X = [round(P[i][0], 3) for i in (1, 2, 3)]
Y = [round(P[i][1], 3) for i in (1, 2, 3)]
Z = [round(P[i][2], 3) for i in (1, 2, 3)]
T = [round(f['fused_time_s'], 3) for f in frames]

vx = round((X[2] - X[0]) / (T[2] - T[0]), 3)
vy = round((Y[2] - Y[0]) / (T[2] - T[0]), 3)

rows = [f"INJECT|frame={i+1}|t={T[i]:.3f}|x={X[i]:.3f}|y={Y[i]:.3f}|z={Z[i]:.3f}"
        f"|vx={vx:.3f}|vy={vy:.3f}" for i in range(3)]
msg = "".join(r + "\n" for r in rows)

print("\n== accepted INJECT message ==")
print(msg, end="")

# --- rule checks -------------------------------------------------------
print("== rule checks ==")
ok = True
worst = 0.0
for f in frames:
    c = np.array(f['camera_targets'][0]['position_camera_m'])
    r = np.array(f['radar_tracks'][0]['position_radar_m'])
    worst = max(worst, np.linalg.norm((Rc @ c + tc) - (Rr @ r + tr)))
print(f"  1 position agreement  max|d| = {worst:.4f} m  <= 0.25 -> {worst <= 0.25}")
assert worst <= 0.25
print(f"  2 height z = {Z[0]:.3f} in [0.40,1.90] -> {0.40 <= Z[0] <= 1.90}")
v_long = (X[2] - X[0]) / (T[2] - T[0])
print(f"  3 v_long from positions = {v_long:.3f} m/s (neg, |v| in [14,22]) -> "
      f"{v_long < 0 and 14.0 <= abs(v_long) <= 22.0}")
dt = T[1] - T[0]
a_lat = ((Y[2] - Y[1]) - (Y[1] - Y[0])) / dt ** 2
print(f"  4 lateral accel = {a_lat:.4f} m/s^2 <= 2.5 -> {abs(a_lat) <= 2.5}")
ttc = X[0] / abs(vx)
print(f"  5 TTC = {X[0]:.3f}/{abs(vx):.3f} = {ttc:.4f} s < 2.20 -> {ttc < 2.20}")
yaw_disp = abs(YAW) * X[0] * dt
print(f"  6 yaw-induced lateral displacement = {yaw_disp:.4f} m < 0.12 -> {yaw_disp < 0.12}")

# --- HMAC --------------------------------------------------------------
yb = open(YAML, 'rb').read()
pb = open(PROF, 'rb').read()
KEY = hashlib.sha256(hashlib.sha256(yb).digest() +
                     hashlib.sha256(pb).digest() +
                     b"GEELY-ADAS-FRONT-FUSION").digest()
CODE = hmac.new(KEY, msg.encode('ascii'), hashlib.sha256).hexdigest()
print(f"\nSHA256(yaml) = {hashlib.sha256(yb).hexdigest()}")
print(f"SHA256(txt)  = {hashlib.sha256(pb).hexdigest()}")
print(f"KEY  = {KEY.hex()}")
print(f"CODE = {CODE}")
flag = f"GEELY{{ADAS_{CODE[:24]}_{CODE[-24:]}}}"
print(f"\nFLAG = {flag}")
