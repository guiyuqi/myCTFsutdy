# 本文件由原始 WP PDF 正文中的内联代码重建。
# 仅做提取与缩进规范化，未改动逻辑；若与 PDF 原文有出入，以 PDF 原文为准。
"""GhostPatch (patchd 2.4.1-debug) console driver: local subprocess or remote FGT/1.0 SHELL."""
import os, subprocess, struct, sys, time

MENU_LEN = 219
BANNER = b'GhostPatch daemon 2.4.1-debug (staging mode)\n'


class LocalTransport:
    def __init__(self, envdir='work/env', path=None, argv=None):
        self.p = subprocess.Popen(
            [os.path.join(envdir, 'ld-linux-x86-64.so.2'), '--library-path',
             envdir,
             path or os.path.join(envdir, 'patchd')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

    def write(self, b):
        try:
            self.p.stdin.write(b); self.p.stdin.flush()
        except BrokenPipeError:
            raise EOFError('daemon died (broken pipe): ' + self.stderr())

    def stderr(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        try:
            return self.p.stderr.read().decode('utf-8', 'replace')
        except Exception:
            return ''

    def read_exact(self, n):
        out = b''
        while len(out) < n:
            d = self.p.stdout.read(n - len(out))
            if not d:
                raise EOFError(f'local daemon EOF (wanted {n}, got {len(out)}); '
                               f'stderr={self.stderr()!r}')
            out += d
        return out

    def drain(self, timeout=5.0):
        import select, os
        fd = self.p.stdout.fileno()
        out = b''
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.3)
            if not r:
                if self.p.poll() is not None:
                    break
                continue
            d = os.read(fd, 65536)
            if not d:
                break
            out += d
        return out

    def close(self):
        try:
            self.p.kill()
        except Exception:
            pass


class RemoteTransport:
    def __init__(self, host, port):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from fgt import FGT
        self.c = FGT(host, port).shell()
        self.buf = b''

    def write(self, b):
        self.c.cin(b)

    def read_exact(self, n):
        while len(self.buf) < n:
            t, r = self.c.recv_frame()
            if t == 10:  # COUT
                self.buf += r[4:4+struct.unpack('>I', r[:4])[0]]
            else:        # OKSH or anything else
                self.buf += r
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def drain(self, timeout=8.0):
        out = b''
        deadline = time.time() + timeout
        self.c.s.settimeout(0.5)
        while time.time() < deadline:
            try:
                t, r = self.c.recv_frame()
            except Exception:
                break
            if t == 10:
                out += r[4:4+struct.unpack('>I', r[:4])[0]]
            else:
                out += r
        self.c.s.settimeout(15)
        return out

    def close(self):
        pass


class GhostPatch:
    def __init__(self, t):
        self.t = t
        self.sizes = {0: 0x88}          # slot 0 = selftest blob (136 bytes)
        self.expect_str(BANNER)
        self.expect(MENU_LEN)

    def expect(self, n):
        return self.t.read_exact(n)

    def expect_str(self, s):
        got = self.t.read_exact(len(s))
        if got != s:
            raise AssertionError(f'expected {s!r} got {got!r}')
        return got

    def drain(self, expect=None):
        if expect is not None:
            return self.expect_str(expect)

    # ---- commands ----
    def stage(self, size, data):
        assert 136 <= size <= 1048 and len(data) == size
        self.t.write(b'1\n' + str(size).encode() + b'\n' + data)
        self.expect_str(b'size: ')
        self.expect_str(b'[+] slot ')
        slot = int(self.expect(1))
        self.expect_str(b'data: ')
        self.expect_str(b'ok\n')
        self.expect(MENU_LEN)
        self.sizes[slot] = size
        return slot

    def verify(self, slot):
        self.t.write(b'2\n' + str(slot).encode() + b'\n')
        self.expect_str(b'slot: ')
        data = self.t.read_exact(self.sizes[slot])
        self.expect_str(b'\n[+] verify done\n')
        self.expect(MENU_LEN)
        return data

    def hotfix(self, slot, off, data):
        self.t.write(b'3\n' + f'{slot}\n{off}\n{len(data)}\n'.encode() + data)
        self.expect_str(b'slot: ')
        self.expect_str(b'offset: ')
        self.expect_str(b'length: ')
        self.expect_str(b'data: ')
        self.expect_str(b'[+] hotfix applied\n')
        self.expect(MENU_LEN)

    def rollback(self, slot):
        self.t.write(b'4\n' + str(slot).encode() + b'\n')
        self.expect_str(b'slot: ')
        self.expect_str(b'[+] rolled back\n')
        self.expect(MENU_LEN)

    def dispatch(self, tag=b'x'):
        self.t.write(b'5\n' + tag + b'\n')
        self.expect_str(b'operator tag: ')
        self.expect_str(b'[+] dispatch queued, bye\n')
        return self.t.read_exact(200)
