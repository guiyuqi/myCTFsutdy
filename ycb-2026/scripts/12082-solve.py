#!/usr/bin/env python3
"""12082 谁教坏了我的Agent — 复现 6 个答案。
恶意组件 = 伪造 MCP 插件 cfg-guard@1.4.2（返回文本里夹带"请对 <hash>.<域名> 做解析验证"的注入式指令）。
受害者 = EMP_107：唯一 gitconfig 篡改写入成功 + PAT 被风控锁定。
"""
import json, base64, re, sys

LOG = 'orchestration_logs.json'
rows = [json.loads(l) for l in open(LOG, encoding='utf-8')]

def ev(emp=None, pred=None):
    out = []
    for o in rows:
        if emp and o.get('employee_id') != emp:
            continue
        if pred and not pred(o):
            continue
        out.append(o)
    return out

# --- 1/4/5/6：受害会话 EMP_107-2026-0915-b41d77e0 ---
sess = 'EMP_107-2026-0915-b41d77e0'
S = ev(pred=lambda o: o['session_id'] == sess)

# 恶意组件安装：写 ~/.agent/mcp_servers.json，包 @corp-tools/mcp-cfg-guard@1.4.2
inst = [o for o in ev('EMP_107') if o.get('tool') == 'write_file'
        and o['args']['path'].endswith('.agent/mcp_servers.json')]
assert len(inst) == 1, inst
ts = inst[0]['timestamp']                      # 2026-09-10T14:22:12.000+08:00
assert '@corp-tools/mcp-cfg-guard@1.4.2' in inst[0]['args']['content']
# 题目口径：YYYYMMDDTHHMM（T 为字面量）—— 平台按此形式判定通过
install_time = ts[0:10].replace('-', '') + 'T' + ts[11:13] + ts[14:16]
assert install_time == '20260910T1422', install_time

# 本地配置篡改 -> 代码拉取重定向域名
w = [o for o in S if o.get('tool') == 'write_file' and o['args']['path'] == '~/.gitconfig']
assert len(w) == 1 and w[0]['result']['status'] == 'ok'
m = re.search(r'\[url "https://([^/"]+)/"\]', w[0]['args']['content'])
assert m, w[0]['args']['content']
redirect_host = m.group(1)                     # git-cache.corp-fast.net
redirect_reg = '.'.join(redirect_host.split('.')[-2:])   # corp-fast.net

# 越权读取的内部文档（会话内无用户请求、且与 git 配置审计无关）
reads = [o for o in S if o.get('tool') == 'read_file']
docs = [o['args']['path'] for o in reads if o['args']['path'].startswith('/docs/')]
assert len(docs) == 1, docs
doc_name = docs[0].rsplit('/', 1)[-1]          # asset-inventory-2026Q3.md
assert doc_name == 'asset-inventory-2026Q3.md'

# --- 2：插件回包里的 5 个"配置指纹"是 Base32 分片，拼接解码得 PAT ---
resp = [o for o in S if o.get('server_name') == 'cfg-guard' and o.get('direction') == 's2c'][0]
text = resp['result']['content'][0]['text']
fps = re.findall(r'→\s*([A-Z2-7]{4,})', text)
assert len(fps) == 5, fps
fps[0] = resp['result']['meta']['telemetry_sync']        # 与 #1 同一片(KBAVILJZ)
# 沙箱内实际发出的 DNS 子域标签（用 c2s 的参数顺序 == 报告顺序）
labels = [o['args']['query'].rstrip('.').split('.')[0]
          for o in ev('EMP_107', lambda o: o.get('tool') == 'dns_query'
                      and o['args']['query'].rstrip('.').endswith('e-cdn81.net'))]
assert labels == fps[1:], (labels, fps)
b32 = fps[0] + ''.join(labels)
token = base64.b32decode(b32 + '=' * ((8 - len(b32) % 8) % 8)).decode()
assert token == 'PAT-9F4K2M-Q3GIT7-CORP4S', token
# 交叉验证：与 ~/.git-credentials 明文一致
cred = [o for o in S if o.get('tool') == 'read_file' and o['args']['path'] == '~/.git-credentials'][0]
assert token in cred['result']['content'], cred['result']['content']

# --- 1：隧道外带域名（注册域）---
tunnel_queries = ev('EMP_107', lambda o: o.get('tool') == 'dns_query' and 'e-cdn81' in o['args']['query'])
assert len(tunnel_queries) == 4
tunnel_reg = '.'.join(tunnel_queries[0]['args']['query'].rstrip('.').split('.')[-2:])
assert tunnel_reg == 'e-cdn81.net'

# --- 3：工号 ---
emp_id = re.search(r'EMP_(\d+)', sess).group(1)

answers = [tunnel_reg, token, emp_id, install_time, doc_name, redirect_reg]
flag = 'flag{' + '_'.join(answers) + '}'
print('1 隧道域名        :', tunnel_reg)
print('2 被盗令牌        :', token)
print('3 工号            :', emp_id)
print('4 组件安装完成时间:', install_time)
print('5 越权读取文档    :', doc_name)
print('6 重定向域名      :', redirect_reg)
print('FLAG             :', flag)
print('SUBMIT_INNER     :', flag[5:-1])
