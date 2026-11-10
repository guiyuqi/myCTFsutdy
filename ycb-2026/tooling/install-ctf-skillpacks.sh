#!/usr/bin/env bash
# install-ctf-skillpacks.sh —— 把 CTF 技能包装进 DSH 用户技能根
#
# 两个来源：
#   skills/upstream/<vendor>/<skill>/   —— 外部 MIT 包（保持原样，便于随上游更新）
#   skills/local/<skill>/              —— 本工作区自有技能（我们的复盘沉淀放这里）
#
# 背景（2026-10-13 实测，2026-10-25 复核）：
#   DSH 的 agent preset 层挂着 @deepseek-ai/dsh-skill-filesystem，默认扫描根包含
#   <dshHome>/skills（= ~/.dsh/skills，可用 $DSH_HOME 覆盖）。
#   该 provider **带 watcher 热加载**：新增/删除 <root>/<name>/SKILL.md 会在下一步
#   直接刷新技能目录，**不需要重启 dsh web**。
#   ⚠️ 加载器只读 frontmatter 的 name / description / whenToUse / metadata；
#      顶层未知键（bind_tools / acceptance / failure_modes）会被**静默丢弃**（勘误 B1）。
#      本脚本因此对 frontmatter 做一次校验，名字不对就跳过并报警。
#
# 用法:
#   bash scripts/install-ctf-skillpacks.sh            # 安装/更新（幂等）
#   bash scripts/install-ctf-skillpacks.sh --list     # 只看会装什么，不动手
#   bash scripts/install-ctf-skillpacks.sh --undo     # 卸载（只删本脚本装的那些）
#   DSH_HOME=/path bash scripts/...                   # 装到别的 DSH 根
set -uo pipefail

WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UP="$WS/skills/upstream"
LOCAL="$WS/skills/local"
DEST="${DSH_HOME:-$HOME/.dsh}/skills"

# 上游包：ljagiello/ctf-skills 的 9 个题型技能 + png-lsb-skills
UPSTREAM_PACKS=(
  "ljagiello-ctf-skills/ctf-web"
  "ljagiello-ctf-skills/ctf-reverse"
  "ljagiello-ctf-skills/ctf-crypto"
  "ljagiello-ctf-skills/ctf-pwn"
  "ljagiello-ctf-skills/ctf-forensics"
  "ljagiello-ctf-skills/ctf-misc"
  "ljagiello-ctf-skills/ctf-malware"
  "ljagiello-ctf-skills/ctf-osint"
  "ljagiello-ctf-skills/ctf-ai-ml"
  "png-lsb-skills"
)
# 故意不装（避免与现有路由/交付格式打架）：
#   solve-challenge  —— 与 PRIMARY 路由 ctf-sandbox / ctf-sandbox-orchestrator 职责重叠
#   ctf-writeup      —— 与 AGENTS.md 强制的 wp.md 统一格式冲突
SKIPPED=("ljagiello-ctf-skills/solve-challenge" "ljagiello-ctf-skills/ctf-writeup")

# 组装源目录（绝对路径）：上游 + 本地
SRCS=()
for p in "${UPSTREAM_PACKS[@]}"; do SRCS+=("$UP/$p"); done
if [ -d "$LOCAL" ]; then
  for d in "$LOCAL"/*/; do
    [ -f "${d}SKILL.md" ] && SRCS+=("${d%/}")
  done
fi

name_of() { basename "$1"; }
kind_of() { case "$1" in "$LOCAL"/*) echo "local" ;; *) echo "upstream" ;; esac; }

MODE="${1:-install}"

case "$MODE" in
  --list)
    echo "技能根: $DEST"
    echo "将安装 ${#SRCS[@]} 个技能:"
    for p in "${SRCS[@]}"; do
      printf "  + %-14s [%s] %s\n" "$(name_of "$p")" "$(kind_of "$p")" "$p"
    done
    echo "故意跳过 ${#SKIPPED[@]} 个:"
    for p in "${SKIPPED[@]}"; do printf "  - %s\n" "$(name_of "$p")"; done
    exit 0 ;;
  --undo)
    n=0
    for p in "${SRCS[@]}"; do
      d="$DEST/$(name_of "$p")"
      [ -d "$d" ] && { rm -rf "$d"; echo "  已删除 $d"; n=$((n+1)); }
    done
    echo "撤销完成：删除 $n 个技能目录（vendored 副本仍在 $UP / $LOCAL）"
    exit 0 ;;
  install) ;;
  *) echo "用法: $0 [--list|--undo]"; exit 2 ;;
esac

[ -d "$UP" ] || { echo "[!] 找不到 vendored 副本: $UP"; exit 1; }
mkdir -p "$DEST"

ok=0; fail=0
for src in "${SRCS[@]}"; do
  nm="$(name_of "$src")"
  if [ ! -f "$src/SKILL.md" ]; then echo "  [!] 源缺失，跳过: $src"; fail=$((fail+1)); continue; fi
  # 校验 frontmatter 的 name 必须是 kebab-case 且与目录名一致（provider 会静默丢弃不合法项）
  fmname="$(sed -n '1,20p' "$src/SKILL.md" | grep -m1 '^name:' | sed 's/^name:[[:space:]]*//' | tr -d '\r')"
  if [ "$fmname" != "$nm" ]; then
    echo "  [!] frontmatter name($fmname) != 目录名($nm)，provider 会丢弃 → 跳过"; fail=$((fail+1)); continue
  fi
  # 校验 when（错误写法）→ 提示应改为 whenToUse
  if sed -n '1,20p' "$src/SKILL.md" | grep -qE '^when:'; then
    echo "  [!] $nm: frontmatter 用了 'when:'，应改成 'whenToUse:'（否则触发条件丢失）"
  fi
  rm -rf "$DEST/$nm"
  cp -r "$src" "$DEST/$nm" && { printf "  + %-16s [%s] %s 个文件\n" "$nm" "$(kind_of "$src")" "$(find "$DEST/$nm" -type f | wc -l)"; ok=$((ok+1)); }
done

echo
echo "安装完成: $ok 个成功 / $fail 个跳过  → $DEST"
echo "技能目录会在下一步自动热刷新（watcher），无需重启 dsh web。"
echo "撤销: bash scripts/install-ctf-skillpacks.sh --undo"
