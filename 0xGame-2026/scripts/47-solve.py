#!/usr/bin/env python3
"""题目 47 奶蛙的博客 —— 爬取分页，聚合 flag 碎片。

X-Hint: fragments are gzip -> base64 -> split; join in page order
每篇 /page?id=N 里有:
  <span class="flag-fragment">X</span>   <- 可见碎片
  <span style="display:none" class="frag">Y</span>  <- 隐藏碎片(干扰)
"""
import base64
import gzip
import html
import re
import sys
import time
import urllib.request

BASE = "http://8000-1c14b496-cff9-49c5-ae1d-eb90a33f16ee.challenge.ctfplus.cn"
OUT = "work/47_blog/raw"

RE_FRAG_VISIBLE = re.compile(r'<span class="flag-fragment">(.*?)</span>', re.S)
RE_FRAG_HIDDEN = re.compile(r'<span style="display:none" class="frag">(.*?)</span>', re.S)
RE_TOTAL = re.compile(r'一共\s*(\d+)\s*篇')
RE_IDX = re.compile(r'第\s*(\d+)\s*/\s*(\d+)\s*块碎片')

DELAY = 0.3


def get(url, retries=3):
    for a in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "naiwa-bs4-crawler/1.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:
            print(f"  ! retry {a+1} {url}: {e}", file=sys.stderr)
            time.sleep(1.0)
    raise SystemExit(f"failed: {url}")


def free(s):
    return html.unescape(s).strip()


def main():
    import os
    os.makedirs(OUT, exist_ok=True)

    root = get(BASE + "/")
    total = int(RE_TOTAL.search(root).group(1))
    print(f"[*] 总篇数 = {total}")

    visible, hidden = {}, {}
    for i in range(1, total + 1):
        raw = get(f"{BASE}/page?id={i}")
        with open(f"{OUT}/page-{i:03d}.html", "w", encoding="utf-8") as f:
            f.write(raw)

        mv = RE_FRAG_VISIBLE.search(raw)
        mh = RE_FRAG_HIDDEN.search(raw)
        idx = RE_IDX.search(raw)
        if not mv:
            print(f"[!] page {i}: no visible fragment")
            continue
        visible[i] = free(mv.group(1))
        if mh:
            hidden[i] = free(mh.group(1))
        print(f"  page {i:3d} idx={idx.group(1) if idx else '?':>3} "
              f"visible={visible[i]!r} hidden={hidden.get(i)!r}")
        time.sleep(DELAY)

    for name, frags in (("visible", visible), ("hidden", hidden)):
        joined = "".join(frags[i] for i in sorted(frags))
        print(f"\n[*] {name} joined ({len(joined)} chars):\n{joined}\n")
        with open(f"work/47_blog/{name}.txt", "w") as f:
            f.write(joined)
        # gzip -> base64  => 先 base64 解码再 gunzip
        try:
            payload = base64.b64decode(joined + "=" * (-len(joined) % 4))
            data = gzip.decompress(payload)
            print(f"[+] {name} DECODED:\n{data.decode('utf-8', 'replace')}\n")
            open(f"work/47_blog/{name}-decoded.txt", "wb").write(data)
        except Exception as e:
            print(f"[-] {name} decode failed: {e}")


if __name__ == "__main__":
    main()
