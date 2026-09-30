#!/usr/bin/env python3
"""GEELY ADAS front-fusion (attachments15.zip) - CONFIRMED solution.

Confirmed flag: GEELY{ADAS_480aface33774137b2a67cb7_a42cb64dabf2e476c38ce26e}

Key point (the real trap): rule 3 says the relative velocity is "derived from the
three frame positions" - i.e. from the *recovered* vehicle-frame positions, NOT from
the rounded 3-decimal design integers.  Recovering the transform gives floats like
39.499844 / 37.699587, whose difference yields vx = -18.003 (not -18.000); vy = 1.804.
"""
import hashlib, hmac, json, os, sys

BASE = sys.argv[1] if len(sys.argv) > 1 else 'work/redo15/attachments'
YAML = os.path.join(BASE, 'calibration/camera_radar_calibration.yaml')
TXT  = os.path.join(BASE, 'protocol/fusion_acceptance.txt')
JSONL= os.path.join(BASE, 'evidence/adas_frames.jsonl')

R = {'camera': [[0.999390827019096, -0.034899496702501, 0.0],
                [0.034899496702501,  0.999390827019096, 0.0],
                [0.0, 0.0, 1.0]],
     'radar' : [[0.999847695156391,  0.017452406437283, 0.0],
                [-0.017452406437283,  0.999847695156391, 0.0],
                [0.0, 0.0, 1.0]]}
T     = {'camera': [1.820, -0.040, 1.460], 'radar': [0.150, 0.030, 0.520]}
DELAY = {'camera': 0.045, 'radar': 0.038}

def mv(M, v): return [sum(M[i][j] * v[j] for j in range(3)) for i in range(3)]

frames = [json.loads(l) for l in open(JSONL) if l.strip()]

# transform: the yaml block labelled `sensor_from_vehicle` actually holds
# vehicle_from_sensor; the working inverse is p_vehicle = R @ p_sensor + t
# (doc's p_v = R^T (p_s - t) gives 5.5 m disagreement and z = -2.17).
P, TS = [], []
for f in frames:
    cam = [a + b for a, b in zip(mv(R['camera'], f['camera_targets'][0]['position_camera_m']), T['camera'])]
    rad = [a + b for a, b in zip(mv(R['radar'],  f['radar_tracks'][0]['position_radar_m']),  T['radar'])]
    gap = sum((a - b) ** 2 for a, b in zip(cam, rad)) ** 0.5
    dcam = f['ego']['camera_capture_time_s'] + DELAY['camera'] - f['fused_time_s']
    drad = f['ego']['radar_capture_time_s']  + DELAY['radar']  - f['fused_time_s']
    assert gap <= 0.25 and abs(dcam) < 1e-9 and abs(drad) < 1e-9
    P.append([(cam[i] + rad[i]) / 2 for i in range(3)])
    TS.append(f['fused_time_s'])
    print(f"frame{f['frame']}  p_v=({P[-1][0]:.6f}, {P[-1][1]:.6f}, {P[-1][2]:.6f})  |cam-rad|={gap:.5f}  delay_residual=({dcam:+.0e},{drad:+.0e})")

# velocities DERIVED FROM THE RECOVERED POSITIONS (rule 3), full precision
vx = (P[2][0] - P[0][0]) / (TS[2] - TS[0])
vy = (P[2][1] - P[0][1]) / (TS[2] - TS[0])
print(f"\nderived vx={vx:.6f} -> {vx:.3f}   vy={vy:.6f} -> {vy:.3f}")

rows = [f"INJECT|frame={i+1}|t={TS[i]:.3f}|x={P[i][0]:.3f}|y={P[i][1]:.3f}|z={P[i][2]:.3f}|vx={vx:.3f}|vy={vy:.3f}"
        for i in range(3)]
msg = "".join(r + "\n" for r in rows)
print("\n--- accepted injection message (single LF after each row) ---")
print(msg, end="")

yb, tb = open(YAML, 'rb').read(), open(TXT, 'rb').read()
dy, dt = hashlib.sha256(yb).digest(), hashlib.sha256(tb).digest()
key  = hashlib.sha256(dy + dt + b"GEELY-ADAS-FRONT-FUSION").digest()   # raw 32-byte digests
code = hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()
print(f"SHA256(yaml) = {dy.hex()}")
print(f"SHA256(txt)  = {dt.hex()}")
print(f"KEY  = {key.hex()}")
print(f"CODE = {code}")
print(f"FLAG = GEELY{{ADAS_{code[:24]}_{code[-24:]}}}")
