#!/usr/bin/env python3
"""GEELY ADAS front-fusion acceptance (attachments15.zip) - independent recompute.

Chain: recover vehicle-frame track from camera+radar -> validate 6 acceptance
rules -> build the accepted INJECT message -> KEY/CODE HMAC -> flag.
"""
import hashlib, hmac, json, sys, os

BASE = sys.argv[1] if len(sys.argv) > 1 else 'work/redo15/attachments'
YAML = os.path.join(BASE, 'calibration/camera_radar_calibration.yaml')
TXT  = os.path.join(BASE, 'protocol/fusion_acceptance.txt')
JSONL= os.path.join(BASE, 'evidence/adas_frames.jsonl')

R = {'camera': [[ 0.999390827019096, -0.034899496702501, 0.0],
                [ 0.034899496702501,  0.999390827019096, 0.0],
                [ 0.0, 0.0, 1.0]],
     'radar' : [[ 0.999847695156391,  0.017452406437283, 0.0],
                [-0.017452406437283,  0.999847695156391, 0.0],
                [ 0.0, 0.0, 1.0]]}
T     = {'camera': [1.820, -0.040, 1.460], 'radar': [0.150, 0.030, 0.520]}
DELAY = {'camera': 0.045, 'radar': 0.038}

def mv(M, v):
    return [sum(M[i][j] * v[j] for j in range(3)) for i in range(3)]

frames = [json.loads(l) for l in open(JSONL) if l.strip()]

# The yaml block labelled `sensor_from_vehicle` behaves as vehicle_from_sensor:
# the doc's stated p_v = R^T (p_s - t) gives cam/radar disagreement 5.5 m and z<0,
# while p_v = R p_s + t gives agreement 2e-4 m and z = 0.750 exactly.
rows, X, Y, Z, TT = [], [], [], [], []
for f in frames:
    cam = [a + b for a, b in zip(mv(R['camera'], f['camera_targets'][0]['position_camera_m']), T['camera'])]
    rad = [a + b for a, b in zip(mv(R['radar'],  f['radar_tracks'][0]['position_radar_m']),  T['radar'])]
    gap = sum((a - b) ** 2 for a, b in zip(cam, rad)) ** 0.5
    tc  = f['ego']['camera_capture_time_s'] + DELAY['camera'] - f['fused_time_s']
    tr  = f['ego']['radar_capture_time_s']  + DELAY['radar']  - f['fused_time_s']
    assert gap <= 0.25, (f['frame'], gap)
    assert abs(tc) < 1e-9 and abs(tr) < 1e-9, (tc, tr)
    p = [round((cam[i] + rad[i]) / 2, 3) for i in range(3)]
    X.append(p[0]); Y.append(p[1]); Z.append(p[2]); TT.append(f['fused_time_s'])
    print(f"frame{f['frame']} fused_t={f['fused_time_s']:.3f} "
          f"cam=({cam[0]:.4f},{cam[1]:.4f},{cam[2]:.4f}) rad=({rad[0]:.4f},{rad[1]:.4f},{rad[2]:.4f}) "
          f"|d|={gap:.5f} delay_residual=({tc:+.1e},{tr:+.1e}) -> xyz=({p[0]:.3f},{p[1]:.3f},{p[2]:.3f})")

vx = (X[2] - X[0]) / (TT[2] - TT[0])
vy = (Y[2] - Y[0]) / (TT[2] - TT[0])
ay = ((Y[2] - Y[1]) / (TT[2] - TT[1]) - (Y[1] - Y[0]) / (TT[1] - TT[0])) / (TT[1] - TT[0])
ttc = X[0] / abs(vx)
yaw = abs(frames[0]['ego']['yaw_rate_radps'] * X[0] * (TT[1] - TT[0]))

checks = [
    ("1 cam/radar <= 0.25 m", max(abs(a - b) for a, b in zip(X, Y)) is not None),
    ("2 height in [0.40,1.90]", all(0.40 <= z <= 1.90 for z in Z)),
    ("3 vx<0 and 14<=|vx|<=22", vx < 0 and 14.0 <= abs(vx) <= 22.0),
    ("4 lateral accel <= 2.5", abs(ay) <= 2.5),
    ("5 TTC < 2.20 s", ttc < 2.20),
    ("6 yaw disp < 0.12 m", yaw < 0.12),
]
for name, ok in checks:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
assert all(ok for _, ok in checks)
print(f"vx={vx:.3f} vy={vy:.3f} ay={ay:.6f} TTC={ttc:.6f} yaw_disp={yaw:.6f}")

rows = [f"INJECT|frame={i+1}|t={TT[i]:.3f}|x={X[i]:.3f}|y={Y[i]:.3f}|z={Z[i]:.3f}|vx={vx:.3f}|vy={vy:.3f}"
        for i in range(3)]
msg = "".join(r + "\n" for r in rows)
print("\n--- accepted injection message (single LF after each row) ---")
print(msg, end="")

yb, tb = open(YAML, 'rb').read(), open(TXT, 'rb').read()
dy, dt = hashlib.sha256(yb).digest(), hashlib.sha256(tb).digest()
key  = hashlib.sha256(dy + dt + b"GEELY-ADAS-FRONT-FUSION").digest()
code = hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()
print(f"SHA256(yaml) = {dy.hex()}")
print(f"SHA256(txt)  = {dt.hex()}")
print(f"KEY  = {key.hex()}")
print(f"CODE = {code}")
print(f"FLAG = GEELY{{ADAS_{code[:24]}_{code[-24:]}}}")
