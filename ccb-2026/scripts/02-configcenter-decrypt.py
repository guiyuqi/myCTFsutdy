# 本文件由原始 WP PDF 正文中的内联代码重建。
# 仅做提取与缩进规范化，未改动逻辑；若与 PDF 原文有出入，以 PDF 原文为准。
import base64, re, glob, sys

KEY = b'bd18306e92864e39'


def S(s):
    raw = base64.b64decode(s)
    out = bytearray()
    for i, c in enumerate(raw):
        c ^= KEY[i % len(KEY)]
        c = (c - i) % 256
        out.append(c)
    return bytes(out)


def E(t):
    if isinstance(t, str):
        t = t.encode()
    raw = bytearray()
    for i, c in enumerate(t):
        c = (c + i) % 256
        c ^= KEY[i % len(KEY)]
        raw.append(c)
    return base64.b64encode(bytes(raw)).decode()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'E':
        for a in sys.argv[2:]:
            print(a, '->', E(a))
        sys.exit(0)
    strs = set()
    for f in sorted(glob.glob('src/**/*.php', recursive=True)):
        txt = open(f, 'rb').read().decode('utf-8', errors='replace')
        for m in re.findall(r"S\('([A-Za-z0-9+/=]+)'\)", txt):
            strs.add((f, m))
    for f, m in sorted(strs):
        try:
            d = S(m)
        except Exception as e:
            d = ('ERR ' + str(e)).encode()
        print("%-22s %-32s -> %r" % (f, m[:30], d))
