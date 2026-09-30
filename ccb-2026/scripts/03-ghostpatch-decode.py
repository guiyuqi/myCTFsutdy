# 本文件由原始 WP PDF 正文中的内联代码重建。
# 仅做提取与缩进规范化，未改动逻辑；若与 PDF 原文有出入，以 PDF 原文为准。
import struct, hashlib, os, sys

s2c = open('r_9999_s2c.bin','rb').read()
c2s = open('r_9999_c2s.bin','rb').read()

# handshake offsets: server sends "FGT/1.0 ... p g\n" then client HELLO ... then "OK ...\n"
def after_hs(buf, marker):
    i = buf.index(marker)
    return buf.index(b'\n', i) + 1

print("S2C head:", c2s[:0])
print("S2C first 120:", repr(s2c[:120]))
print("C2S first 120:", repr(c2s[:120]))

so = after_hs(s2c, b'FGT/1.0')
co = after_hs(c2s, b'HELLO')

# find 'OK' start of s2c crypto stream: it's right after the handshake line
# but OK line precedes the first encrypted frame; locate it
ok_i = s2c.index(b'OK ')
so = s2c.index(b'\n', ok_i) + 1
print("crypto start s2c:", so, "c2s:", co)


def rc4_ks(key, n):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    ks = bytearray(); i = j = 0
    for _ in range(n):
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        ks.append(S[(S[i] + S[j]) & 0xff])
    return bytes(ks)


def split_ct(buf, start):
    i = start; out = []
    while i + 2 <= len(buf):
        ln = struct.unpack('>H', buf[i:i+2])[0]; i += 2
        if i + ln > len(buf): break
        out.append((ln, bytes(buf[i:i+ln]))); i += ln
    return out


def decrypt(buf, start):
    frames = split_ct(buf, start)
    total = sum(ln for ln, _ in frames)
    ks = rc4_ks(K, total + 64)
    pos = 0; dec = []
    for ln, ct in frames:
        dec.append((ln, bytes(c ^ ks[pos+k] for k, c in enumerate(ct)))); pos += ln
    return dec


NAMES = {1:'GET',2:'META',3:'DATA',4:'END',5:'ERR',6:'LIST',7:'SHELL',8:'OKSH',9:'CIN',10:'COUT'}


def parse(dec, label, dumpdir=None):
    print(f'===== {label}: {len(dec)} frames =====')
    files = {}; cur = None; order = []
    for idx, (ln, pt) in enumerate(dec):
        t = pt[0] if pt else -1
        r = pt[1:]
        if t == 2 and len(r) >= 42:
            sz = struct.unpack('>Q', r[:8])[0]; sha = r[8:40]
            nl = struct.unpack('>H', r[40:42])[0]; nm = r[42:42+nl]
            cur = nm; files[cur] = {'size': sz, 'sha': sha.hex(), 'chunks': {}}
            order.append((nm, sz, sha.hex()))
            print(f'[{idx}] META name={nm} size={sz} sha={sha.hex()}')
        elif t == 3 and len(r) >= 8:
            seq, dl = struct.unpack('>II', r[:8]); data = r[8:8+dl]
            if cur is not None:
                files[cur]['chunks'][seq] = data
        elif t == 4:
            print(f'[{idx}] END sha={r[:32].hex() if len(r)>=32 else r.hex()}')
        elif t == 1 and len(r) >= 2:
            nl = struct.unpack('>H', r[:2])[0]; print(f'[{idx}] GET {r[2:2+nl]}')
        elif t == 5:
            print(f'[{idx}] ERR {r.hex()}')
        elif t == 6 and len(r) >= 2:
            cnt = struct.unpack('>H', r[:2])[0]; p = 2; names = []
            for _ in range(cnt):
                if p+2 > len(r): break
                nl = struct.unpack('>H', r[p:p+2])[0]; p += 2; names.append(r[p:p+nl]); p += nl
            print(f'[{idx}] LIST {names}')
        elif t == 7:
            print(f'[{idx}] SHELL {r!r}')
        elif t == 8:
            print(f'[{idx}] OKSH {r!r}')
        elif t == 9 and len(r) >= 4:
            sl = struct.unpack('>I', r[:4])[0]; print(f'[{idx}] CIN {r[4:4+sl]!r}')
        elif t == 10 and len(r) >= 4:
            sl = struct.unpack('>I', r[:4])[0]; print(f'[{idx}] COUT {r[4:4+sl]!r}')
        else:
            print(f'[{idx}] ?type={t} ln={ln} {pt[:64]!r}')
    if dumpdir:
        os.makedirs(dumpdir, exist_ok=True)
        for nm, info in files.items():
            seqs = sorted(info['chunks'])
            gap = [s for s in range(seqs[0], seqs[-1]+1) if s not in info['chunks']] if seqs else []
            body = b''.join(info['chunks'][s] for s in seqs)
            d = hashlib.sha256(body).hexdigest()
            fn = os.path.join(dumpdir, nm.decode('utf-8', 'replace'))
            open(fn, 'wb').write(body)
            print(f'-> {fn}: got {len(body)} expect {info["size"]} '
                  f'size_ok={len(body)==info["size"]} sha_ok={d==info["sha"]} gaps={gap[:20]}')
    return files


K = hashlib.sha256((129261817995543).to_bytes(6, 'big')).digest()[:16]
c2s_dec = decrypt(c2s, co)
parse(c2s_dec, 'C2S')
s2c_dec = decrypt(s2c, so)
parse(s2c_dec, 'S2C', dumpdir='files2')
