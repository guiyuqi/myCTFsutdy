#!/usr/bin/env bash
# 把平台 token 写进凭据文件（工作区之外，0600）——token 不回显、不进 shell 历史、不进工作区。
#
# 用法（在你自己的终端里跑，输入过程无回显）：
#   bash ~/ctf-2026/scripts/set-token.sh
#   bash ~/ctf-2026/scripts/set-token.sh https://ycb-bk.dasctf.com 1750
#
# token 从哪来：浏览器登录 ycb-bk.dasctf.com → F12 → Application/存储 → Cookies（或 localStorage 的
# jwtToken）→ 名字叫 Authorization 的那条值（通常是 eyJ 开头的 JWT，很长）。
# 粘贴时整段粘，别带引号、别带 "Bearer " 前缀（如果带了，本脚本会自动去掉）。
set -euo pipefail

CREDS="${CTF_CREDS:-$HOME/.config/ctf/creds.env}"
BASE="${1:-https://ycb-bk.dasctf.com}"
MATCH="${2:-1750}"

mkdir -p "$(dirname "$CREDS")"
[ -e "$CREDS" ] && chmod 600 "$CREDS"

if [ -t 0 ]; then
  printf '粘贴 token（无回显，粘完回车）：'
  IFS= read -r -s TOKEN
  printf '\n'
else
  IFS= read -r TOKEN
fi

# 去掉常见包装：Bearer 前缀 / 引号 / 空白 / cookie 形式 Authorization=xxx
# 1) 先去引号/空白/Authorization= 包装
TOKEN="${TOKEN%\"}"; TOKEN="${TOKEN#\"}"; TOKEN="${TOKEN%\'}"; TOKEN="${TOKEN#\'}"
TOKEN="${TOKEN#Authorization=}"
TOKEN="$(printf '%s' "$TOKEN" | tr -d '[:space:]')"
# 2) 再统一成 "Bearer <jwt>"——★ 顺序不能反：先加前缀再删空白会把空格删掉，变成 BearereyJ…（平台 40401）
while :; do
  case "$TOKEN" in
    [Bb]earer*) TOKEN="${TOKEN#[Bb]earer}" ;;
    *) break ;;
  esac
done
TOKEN="Bearer $TOKEN"

if [ ${#TOKEN} -lt 20 ]; then
  echo "[!] token 太短（${#TOKEN} 字符），大概率没粘对，已放弃写入。" >&2
  exit 1
fi

python3 - "$CREDS" "$BASE" "$MATCH" "$TOKEN" <<'PY'
import sys, re, os
creds, base, match, token = sys.argv[1:5]
lines = []
if os.path.exists(creds):
    with open(creds, encoding="utf-8") as f:
        lines = f.read().splitlines()
want = {"CTFD_BASE": base, "MATCH_ID": match, "CTFD_TOKEN": token}
seen = set()
out = []
for ln in lines:
    m = re.match(r'^\s*([A-Z0-9_]+)\s*=', ln)
    if m and m.group(1) in want:
        k = m.group(1)
        out.append(f"{k}={want[k]}")
        seen.add(k)
    else:
        out.append(ln)
for k, v in want.items():
    if k not in seen:
        out.append(f"{k}={v}")
with open(creds, "w", encoding="utf-8") as f:
    f.write("\n".join(out).rstrip("\n") + "\n")
os.chmod(creds, 0o600)
PY

chmod 600 "$CREDS"
python3 - "$CREDS" <<'PY'
import sys, re
tok = base = match = ""
for ln in open(sys.argv[1], encoding="utf-8"):
    k, _, v = ln.strip().partition("=")
    if k == "CTFD_TOKEN": tok = v
    elif k == "CTFD_BASE": base = v
    elif k == "MATCH_ID": match = v
mask = f"{tok[:6]}…{tok[-4:]}" if len(tok) > 12 else "（过短）"
print(f"[✓] 已写入 {sys.argv[1]}（0600）")
print(f"    CTFD_BASE = {base}")
print(f"    MATCH_ID  = {match}")
print(f"    CTFD_TOKEN= {mask}  （长度 {len(tok)}）")
PY
echo
echo "→ 立刻验证（平台每次响应都会刷新 token，旧值会 40401，所以要马上验）："
python3 "$(dirname "$0")/ycb.py" creds || {
  echo
  echo "[!] 鉴权没通过。最可能：token 不是页面当前在用的那个，或已经被下一次请求刷新掉了。"
  echo "    正确取法：比赛页面按 F12 → Console → 粘贴 scripts/grab-token-snippet.js 全文"
  echo "    （它会 copy() 到剪贴板），然后马上重跑本脚本。"
  exit 1
}
