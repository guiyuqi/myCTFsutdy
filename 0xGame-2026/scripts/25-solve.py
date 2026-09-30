import re, zlib, sys

def load(path):
    data = open(path,'rb').read()
    objs = {}
    for m in re.finditer(rb'(?<![0-9])(\d+)\s+(\d+)\s+obj\b', data):
        num = int(m.group(1)); start = m.end()
        e = data.find(b'endobj', start)
        if e < 0: continue
        objs[num] = data[start:e]
    # object streams
    for num in list(objs):
        body = objs[num]
        if b'/ObjStm' not in body: continue
        sm = re.search(rb'stream\r?\n', body)
        if not sm: continue
        raw = body[sm.end():body.rfind(b'endstream')]
        try: dec = zlib.decompress(raw)
        except Exception: continue
        n = int(re.search(rb'/N\s+(\d+)', body).group(1))
        first = int(re.search(rb'/First\s+(\d+)', body).group(1))
        hdr = dec[:first].split()
        pairs = [(int(hdr[i]), int(hdr[i+1])) for i in range(0, 2*n, 2)]
        for i,(onum,off) in enumerate(pairs):
            end = pairs[i+1][1] if i+1 < len(pairs) else len(dec)-first
            objs[onum] = dec[first+off:first+end]
    return data, objs

def stream_of(body):
    sm = re.search(rb'stream\r?\n', body)
    if not sm: return None
    raw = body[sm.end():body.rfind(b'endstream')]
    raw = raw.rstrip(b'\r\n')
    filt = re.search(rb'/Filter\s*(/\w+|\[[^\]]*\])', body)
    f = filt.group(1) if filt else b''
    if b'FlateDecode' in f:
        try: return zlib.decompress(raw)
        except Exception:
            try: return zlib.decompressobj().decompress(raw)
            except Exception: return None
    return raw

def parse_cmap(txt):
    m = {}
    for blk in re.findall(rb'beginbfchar(.*?)endbfchar', txt, re.S):
        for src,dst in re.findall(rb'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', blk):
            m[bytes.fromhex(src.decode())] = bytes.fromhex(dst.decode()).decode('utf-16-be','replace')
    for blk in re.findall(rb'beginbfrange(.*?)endbfrange', txt, re.S):
        for lo,hi,dst in re.findall(rb'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', blk):
            lo_b, hi_b = bytes.fromhex(lo.decode()), bytes.fromhex(hi.decode())
            base = int(dst,16)
            for i in range(int.from_bytes(hi_b,'big')-int.from_bytes(lo_b,'big')+1):
                code = (int.from_bytes(lo_b,'big')+i).to_bytes(len(lo_b),'big')
                m[code] = chr(base+i)
    return m

def main(path):
    data, objs = load(path)
    # build page list order via /Type/Page
    pages = [n for n,b in objs.items() if re.search(rb'/Type\s*/Page\b', b)]
    print("pages:", len(pages), file=sys.stderr)
    # font -> cmap: collect all font objs
    fontmaps = {}
    for n,b in objs.items():
        if b'/ToUnicode' in b and b'/Type' in b and b'/Font' in b:
            tu = re.search(rb'/ToUnicode\s+(\d+)\s+\d+\s+R', b)
            if not tu: continue
            st = stream_of(objs.get(int(tu.group(1)), b''))
            if st: fontmaps[n] = parse_cmap(st)
    print("fonts w/ ToUnicode:", len(fontmaps), file=sys.stderr)
    results = []
    for n in sorted(pages):
        b = objs[n]
        res = re.search(rb'/Resources\s+(\d+)\s+\d+\s+R', b)
        resbody = objs.get(int(res.group(1)), b'') if res else b
        # map font name -> obj num
        fmap = {}
        fm = re.search(rb'/Font\s*<<(.*?)>>', resbody, re.S)
        fontdict = fm.group(1) if fm else b''
        if not fm:
            fr = re.search(rb'/Font\s+(\d+)\s+\d+\s+R', resbody)
            if fr: fontdict = objs.get(int(fr.group(1)), b'')
        for name, onum in re.findall(rb'/(\w+)\s+(\d+)\s+\d+\s+R', fontdict):
            fmap[name.decode()] = int(onum)
        # contents
        cs = []
        cm = re.search(rb'/Contents\s+(\d+)\s+\d+\s+R', b)
        if cm: cs = [int(cm.group(1))]
        else:
            cm2 = re.search(rb'/Contents\s*\[(.*?)\]', b, re.S)
            if cm2: cs = [int(x) for x in re.findall(rb'(\d+)\s+\d+\s+R', cm2.group(1))]
        content = b''
        for c in cs:
            s = stream_of(objs.get(c, b''))
            if s: content += s + b'\n'
        out = []
        cur = None
        for tok in re.finditer(rb'/(\w+)\s+[\d.]+\s+Tf|<([0-9A-Fa-f\s]*)>\s*Tj|\((?:[^()\\]|\\.)*\)\s*Tj|\[(.*?)\]\s*TJ', content, re.S):
            if tok.group(1):
                cur = fontmaps.get(fmap.get(tok.group(1).decode(), -1), None)
            elif tok.group(2) is not None:
                hx = re.sub(rb'\s', b'', tok.group(2))
                if len(hx) % 2: hx += b'0'
                bs = bytes.fromhex(hx.decode())
                out.append(decode(bs, cur))
            elif tok.group(3) is not None:
                for h in re.findall(rb'<([0-9A-Fa-f\s]*)>', tok.group(3)):
                    hx = re.sub(rb'\s', b'', h)
                    if len(hx)%2: hx += b'0'
                    out.append(decode(bytes.fromhex(hx.decode()), cur))
                for l in re.findall(rb'\(((?:[^()\\]|\\.)*)\)', tok.group(3)):
                    out.append(l.decode('latin1'))
            else:
                lit = re.match(rb'\((.*)\)\s*Tj', tok.group(0), re.S)
                if lit: out.append(lit.group(1).decode('latin1'))
        results.append((n, ''.join(out)))
    return results

def decode(bs, cmap):
    if cmap:
        # try 2-byte codes then 1-byte
        s = ''
        i = 0
        while i < len(bs):
            if i+1 < len(bs) and bs[i:i+2] in cmap:
                s += cmap[bs[i:i+2]]; i += 2
            elif bs[i:i+1] in cmap:
                s += cmap[bs[i:i+1]]; i += 1
            else:
                s += bs[i:i+1].decode('latin1'); i += 1
        return s
    return bs.decode('latin1')

if __name__ == '__main__':
    for n, t in main(sys.argv[1]):
        print(f"=== page obj {n} ===")
        print(t)
