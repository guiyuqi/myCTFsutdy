#!/bin/bash
# 打包比赛材料：本会话对话 + ctfagent 台账 + 各 run 事件流 + WP 草稿 + INDEX。
#
# 用法：
#   tools/package_upload.sh                 # 输出到 upload-<MMDD-HHMM>/
#   tools/package_upload.sh --with-full     # 连 .full 原始事件流一起（约 400MB）
#
# 为什么分开：面板/复盘只需要"压缩后"的事件流（几十 MB）；审核交材料常常要
# 原始完整版（含 reasoning），所以 --with-full 才带。
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT="$ROOT/upload-$(date +%m%d-%H%M)"
WITH_FULL=0
[ "${1:-}" = "--with-full" ] && WITH_FULL=1

mkdir -p "$OUT"/{conversations,runs,wp}
echo "输出目录：$OUT"

# 1) 本机 DSH 会话对话（这个隔离会话 + 子代理会话都在里面）
PY="$ROOT/.s1-venv/bin/python"
[ -x "$PY" ] || PY=$(command -v python3)
if [ -f "$ROOT/tools/export_conversation.py" ]; then
  "$PY" "$ROOT/tools/export_conversation.py" --all --out "$OUT/conversations" \
    > "$OUT/conversations/_export.log" 2>&1 \
    && echo "  ✓ 对话导出：$(ls "$OUT/conversations" | wc -l) 个文件" \
    || echo "  ! 对话导出失败，见 conversations/_export.log"
fi

# 2) 台账（题/族/尝试/判死/人解）
CTFAGENT="$ROOT/ctfagent/bin/ctfagent"
if [ -x "$CTFAGENT" ]; then
  PATH="$ROOT/ctfagent/bin:$PATH" "$CTFAGENT" export --jsonl "$OUT/ledger.jsonl" \
    > /dev/null 2>&1 && echo "  ✓ 台账：$(wc -l < "$OUT/ledger.jsonl") 行" \
    || echo "  ! 台账导出失败（后端 :8011 在跑吗？）"
fi

# 3) 各 run 的事件流：压缩版一定带；--with-full 再带原始完整版
n=0; nf=0
for f in "$ROOT"/state/muteki/*.jsonl; do
  [ -f "$f" ] || continue
  base=$(basename "$f")
  cp "$f" "$OUT/runs/$base" && n=$((n+1))
  if [ "$WITH_FULL" = "1" ] && [ -f "$f.full" ]; then
    cp "$f.full" "$OUT/runs/${base%.jsonl}.full.jsonl" && nf=$((nf+1))
  fi
done
echo "  ✓ run 事件流：$n 个（原始完整版 $nf 个）"

# 4) WP 草稿
if compgen -G "$ROOT/.tmp/wp/*.md" > /dev/null; then
  cp "$ROOT"/.tmp/wp/*.md "$OUT/wp/" 2>/dev/null
  echo "  ✓ WP 草稿：$(ls "$OUT/wp" | wc -l) 篇"
fi

# 4.5) 自动脱敏（二进制安全，含缩写形式；这一步曾经漏过，别删）
python3 - "$OUT" <<'PYEOF'
import re, sys, pathlib
root = pathlib.Path(sys.argv[1])
pat = re.compile(rb"sk-[A-Za-z0-9]{6,}(?:\.\.\.)?|AKIA[0-9A-Z]{12,}|ghp_[A-Za-z0-9]{20,}")
n = 0
for f in root.rglob("*"):
    if not f.is_file():
        continue
    try:
        raw = f.read_bytes()
    except OSError:
        continue
    new = pat.sub(b"sk-REDACTED-BY-PACKAGER", raw)
    if new != raw:
        f.write_bytes(new)
        n += 1
print(f"  · 自动脱敏：{n} 个文件")
PYEOF

# 5) 密钥自查（正常结果：只有测试里的 sk-test 之类占位）
echo "  · 密钥扫描（sk-/token/AKIA 出现次数）："
grep -rIoh -E "sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{12,}|ghp_[A-Za-z0-9]{20,}" "$OUT" 2>/dev/null \
  | sort | uniq -c | head -5 || true
echo "    （空 = 没有真实密钥；若有命中，交付前必须删掉）"

# 6) INDEX
{
  echo "# 比赛材料包 $(date '+%Y-%m-%d %H:%M')"
  echo
  echo "| 内容 | 数量 | 说明 |"
  echo "|---|---|---|"
  echo "| conversations/ | $(ls "$OUT/conversations" 2>/dev/null | wc -l) | 本机 agent 会话对话（md 人读版 + jsonl 原始） |"
  echo "| runs/ | $(ls "$OUT/runs" 2>/dev/null | wc -l) | muteki run 事件流（${WITH_FULL:+含原始完整版}） |"
  echo "| wp/ | $(ls "$OUT/wp" 2>/dev/null | wc -l) | Write-up 草稿 |"
  echo "| ledger.jsonl | $([ -f "$OUT/ledger.jsonl" ] && wc -l < "$OUT/ledger.jsonl" || echo 0) | 台账：题/族/尝试/判死/人解 |"
  echo
  echo "## 已解出题目"
  echo
  grep -h "FLAG：" "$OUT"/wp/*.md 2>/dev/null | sed 's/^\*\*FLAG：\*\* //' | sort -u
  echo
  echo "## 生成方式"
  echo
  echo '```bash'
  echo "tools/package_upload.sh --with-full   # 由 ./tools/package_upload.sh 生成"
  echo '```'
} > "$OUT/INDEX.md"
echo "  ✓ INDEX.md"
echo
echo "完成：du -sh $OUT"
du -sh "$OUT" 2>/dev/null | tail -1
