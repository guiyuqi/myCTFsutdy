# 本文件由原始 WP PDF 正文中的内联代码重建。
# 仅做提取与缩进规范化，未改动逻辑；若与 PDF 原文有出入，以 PDF 原文为准。
"""FGT/1.0 client: DH handshake + RC4 framed channel (see notice.txt from tcp/8888)."""
import socket, struct, hashlib, os, sys, time

# frame types
GET, META, DATA, END, ERR, LIST, SHELL, OKSH, CIN, COUT = range(1, 11)


def rc4(key):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    i = j = 0
    while True:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        yield S[(S[i] + S[j]) & 0xff]


class FGT:
    def __init__(self, host, port, verbose=True):
        self.v = verbose
        self.s = socket.create_connection((host, port), timeout=15)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b''
        line = self.readline()
        assert line.startswith(b'FGT/1.0 READY'), line
        parts = dict(kv.split(b'=') for kv in line.split()[2:])
        self.p = int(parts[b'p'], 16)
        self.g = int(parts[b'g'], 16)
        self.nbytes = (self.p.bit_length() + 7) // 8
        self.a = int.from_bytes(os.urandom(6), 'big') % (self.p - 2) + 1
        A = pow(self.g, self.a, self.p)
        self.send_raw(b'FGT/1.0 HELLO %x\n' % A)
        line = self.readline()
        assert line.startswith(b'FGT/1.0 OK'), line
        B = int(line.split()[2], 16)
        shared = pow(B, self.a, self.p)
        self.K = hashlib.sha256(shared.to_bytes(self.nbytes, 'big')).digest()[:16]
        self.enc = rc4(self.K)
        self.dec = rc4(self.K)
        if self.v:
            print(f'[+] p={self.p:x} g={self.g} A={A:x} B={B:x} shared={shared} '
                  f'K={self.K.hex()}', file=sys.stderr)

    def send_raw(self, b):
        self.s.sendall(b)

    def recv_exact(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65536)
            if not d:
                raise EOFError('connection closed')
            self.buf += d
        r, self.buf = self.buf[:n], self.buf[n:]
        return r

    def readline(self):
        while b'\n' not in self.buf:
            d = self.s.recv(65536)
            if not d:
                raise EOFError('connection closed during handshake')
            self.buf += d
        i = self.buf.index(b'\n')
        line, self.buf = self.buf[:i], self.buf[i+1:]
        return line

    def frame(self, ftype, payload=b''):
        body = bytes([ftype]) + payload
        ct = bytes(c ^ next(self.enc) for c in body)
        self.send_raw(struct.pack('>H', len(ct)) + ct)

    def recv_frame(self):
        ln = struct.unpack('>H', self.recv_exact(2))[0]
        ct = self.recv_exact(ln)
        pt = bytes(c ^ next(self.dec) for c in ct)
        return pt[0], pt[1:]

    # --- high level ---
    def get(self, name):
        self.frame(GET, struct.pack('>H', len(name)) + name)
        data = bytearray(); meta = None
        while True:
            t, r = self.recv_frame()
            if t == META:
                size, sha = struct.unpack('>Q', r[:8])[0], r[8:40]
                nl = struct.unpack('>H', r[40:42])[0]
                meta = (size, sha.hex(), r[42:42+nl])
            elif t == DATA:
                seq, dl = struct.unpack('>II', r[:8])
                data += r[8:8+dl]
            elif t == END:
                return meta, bytes(data)
            elif t == ERR:
                return None, None
            else:
                raise Exception(f'unexpected frame {t} {r[:40]!r}')

    def list_files(self):
        self.frame(LIST)
        t, r = self.recv_frame()
        assert t == LIST, (t, r)
        cnt = struct.unpack('>H', r[:2])[0]; p = 2; names = []
        for _ in range(cnt):
            nl = struct.unpack('>H', r[p:p+2])[0]; p += 2
            names.append(r[p:p+nl].decode()); p += nl
        return names

    def shell(self):
        self.frame(SHELL)
        t, r = self.recv_frame()
        assert t == OKSH, (t, r)
        return self

    def cin(self, data: bytes):
        self.frame(CIN, struct.pack('>I', len(data)) + data)

    def cout(self):
        """Receive one COUT frame, return bytes."""
        t, r = self.recv_frame()
        if t != COUT:
            return None, (t, r)
        return r[4:4+struct.unpack('>I', r[:4])[0]], t

    def recv_until_idle(self, timeout=1.5):
        """Drain COUT frames until the socket goes idle."""
        self.s.settimeout(timeout)
        out = b''
        try:
            while True:
                d, t = self.cout()
                if d is None:
                    break
                out += d
        except socket.timeout:
            pass
        finally:
            self.s.settimeout(15)
        return out


if __name__ == '__main__':
    host, port = sys.argv[1], int(sys.argv[2])
    c = FGT(host, port)
    print('LIST:', c.list_files())
