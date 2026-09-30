#!/usr/bin/env python3
"""CTF+ platform helper (0xgame2026).

Token: env CTF_TOKEN, or file ~/ctf-2026/.token (single line).

Usage:
  ctfplus.py list                    # all challenges (grouped)
  ctfplus.py detail <id>             # one challenge detail + attachments
  ctfplus.py mine                    # my team / user base info
  ctfplus.py start <id>              # start THIS challenge's container -> address
  ctfplus.py stop  <id>              # release the container slot (do this!)
  ctfplus.py submit <id> <flag>      # submit ONE flag (rate limited 10/min)
  ctfplus.py log                     # show submission history

Safety: submissions are hard-limited to 10 per rolling 60s and every attempt is
appended to evidence/submit-log.jsonl. No scanning, no brute force.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

BASE = "https://0xgame2026.play.ctfplus.cn/api"
ROOT = os.path.expanduser("~/ctf-2026")
LOG = os.path.join(ROOT, "evidence", "submit-log.jsonl")
RATE_LIMIT = 10          # submissions
RATE_WINDOW = 60         # seconds


def cookie():
    """Session cookie for the competition node (gorilla/sessions SessionStore)."""
    c = os.environ.get("CTF_COOKIE", "").strip()
    if not c and os.path.exists(os.path.join(ROOT, ".cookie")):
        c = open(os.path.join(ROOT, ".cookie")).read().strip()
    if not c:
        sys.exit("no cookie: set CTF_COOKIE or write ~/ctf-2026/.cookie")
    return c


def call(path, method="GET", payload=None, timeout=30):
    url = BASE + path
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Cookie", cookie())
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("Referer", "https://0xgame2026.play.ctfplus.cn/")
    req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) ctfplus-helper")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        return {"_http": e.code, "_raw": raw}
    try:
        j = json.loads(raw)
    except Exception:
        return {"_http": 200, "_raw": raw}
    if isinstance(j, dict) and "data" in j:
        return j
    return j


def submissions_last_minute():
    if not os.path.exists(LOG):
        return 0
    now = time.time()
    n = 0
    for line in open(LOG):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if now - rec.get("ts", 0) < RATE_WINDOW:
            n += 1
    return n


def append_log(rec):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def cmd_list():
    r = call("/challenge/getChallengeList", "POST", {"tags": []})
    data = r.get("data") if isinstance(r, dict) else r
    print(json.dumps(data, ensure_ascii=False, indent=2)[:400000])


def cmd_start(cid):
    r = call("/challenge/startChallenge", "POST", {"id": str(cid)})
    print(json.dumps(r, ensure_ascii=False, indent=2))
    return r


def cmd_stop(cid):
    r = call("/challenge/stopChallenge", "POST", {"id": str(cid)})
    print(json.dumps(r, ensure_ascii=False, indent=2))
    return r


def cmd_detail(cid):
    r = call("/challenge/getChallengeDetailInfo", "POST", {"challenge_id": int(cid)})
    print(json.dumps(r, ensure_ascii=False, indent=2)[:200000])


def cmd_mine():
    print(json.dumps(call("/user/getUserInfo"), ensure_ascii=False, indent=2)[:20000])
    print(json.dumps(call("/team/getTeamInfo"), ensure_ascii=False, indent=2)[:20000])


def cmd_submit(cid, flag):
    """Submit one flag. Hard rate cap: never more than RATE_LIMIT per RATE_WINDOW.

    When the window is full we WAIT instead of failing, so a caller never
    mistakes throttling for a rejected flag. Uses an exclusive lock file so
    concurrent callers cannot race past the cap.
    """
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    lock = LOG + ".lock"
    with open(lock, "a+") as lf:
        try:
            import fcntl
            fcntl.flock(lf, fcntl.LOCK_EX)
        except Exception:
            pass
        waited = 0
        while True:
            n = submissions_last_minute()
            if n < RATE_LIMIT:
                break
            if waited == 0:
                print("[rate-limit] %d/%d in last %ds, waiting for a free slot..."
                      % (n, RATE_LIMIT, RATE_WINDOW), file=sys.stderr)
            time.sleep(2)
            waited += 2
            if waited > 300:
                sys.exit("rate limit: still full after 300s, giving up")
        t0 = time.time()
        r = call("/challenge/submitFlag", "POST", {"challenge_id": int(cid), "flag": flag})
        rec = {
            "ts": t0,
            "time": datetime.now(timezone.utc).isoformat(),
            "challenge_id": cid,
            "flag": flag,
            "result": r,
        }
        append_log(rec)
    print(json.dumps(r, ensure_ascii=False, indent=2))


def cmd_log():
    if not os.path.exists(LOG):
        print("(empty)")
        return
    for line in open(LOG):
        print(line.rstrip())


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    c = sys.argv[1]
    if c == "list":
        cmd_list()
    elif c == "detail":
        cmd_detail(sys.argv[2])
    elif c == "start":
        cmd_start(sys.argv[2])
    elif c == "stop":
        cmd_stop(sys.argv[2])
    elif c == "mine":
        cmd_mine()
    elif c == "submit":
        cmd_submit(sys.argv[2], sys.argv[3])
    elif c == "log":
        cmd_log()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
