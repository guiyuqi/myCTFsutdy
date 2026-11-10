#!/usr/bin/env bash
# triage-auto.sh —— 任何附件到手后**第一条**命令：把标准工具全跑一遍并落盘
#
# 为什么有这个脚本（2026-10-31 强网杯 ELFStudy 教训）：
#   三个逆向跑者 + 父代理共 ~110 分钟，全部在**手搓解码**（XOR/AES/RELA/字节置换），
#   但从头到尾**没有任何人跑过 binwalk / unblob / rabin2 -zz**。
#   而该题平台已有 314 队解出 ⇒ 标准工具大概率直接吐答案。
#   根因不是能力，是**派单时把任务框成了"解码这个异常块"**，于是没人做"先认这是什么文件"。
#   ⇒ 现在把它变成强制第一步：没有 triage 落盘，任何分析/报告都不算数。
#
# 用法： bash scripts/triage-auto.sh <文件> [题号]
# 产物： evidence/<题号或文件名>-triage.txt   + 屏幕上的 TRIAGE SUMMARY
set -u
F="${1:?用法: bash scripts/triage-auto.sh <文件> [题号]}"
ID="${2:-$(basename "$F" | tr -c 'A-Za-z0-9._-' '_')}"
OUT="evidence/${ID}-triage.txt"
mkdir -p evidence
run() { echo "### $*" >>"$OUT"; eval "$@" >>"$OUT" 2>&1 || echo "(失败/不存在)" >>"$OUT"; echo >>"$OUT"; }
: >"$OUT"
echo "=== triage $(date '+%F %T') ===" >>"$OUT"
echo "file: $F" >>"$OUT"
run "ls -la '$F'"
run "sha256sum '$F'"
run "file -k '$F'"

# ① 签名扫描：**这条就是 ELFStudy 缺的那一步**
command -v binwalk >/dev/null && run "timeout 120 binwalk '$F'" \
  || echo "!! binwalk 不可用" >>"$OUT"
# ② 现代容器/固件解包
#   坑（2026-10-31 实测）：unblob 的 -d 是 --depth（整数范围），输出目录是 -e / --extract-dir。
#   写成 `unblob -d <dir>` 会直接 `Error: Invalid value for '-d' / '--depth'` 而空手而归，
#   屏幕上却像"跑过了"。必须用 -e。
command -v unblob  >/dev/null && run "timeout 180 unblob -e work/unblob_${ID} '$F' 2>&1 | tail -20" \
  || echo "!! unblob 不可用" >>"$OUT"
# ③ 通用归档读取
command -v 7z      >/dev/null && run "7z l '$F' 2>&1 | tail -25"
# ④ 全字符串（含宽字符）——rabin2 能扫出被拆开的串
command -v rabin2  >/dev/null && run "rabin2 -zz '$F' 2>/dev/null | head -60"
run "strings -a -n 6 '$F' | head -40"
run "strings -a -e l -n 6 '$F' | head -20"
# ⑤ 按类型补刀
case "$(file -b "$F")" in
  *ELF*)  command -v readelf >/dev/null && run "readelf -hSW '$F' | head -40"
          command -v checksec >/dev/null && run "checksec --file='$F' 2>/dev/null" ;;
  *Zip*|*zip*) command -v zipinfo >/dev/null && run "zipinfo -v '$F' | head -40" ;;
  *image*|*PNG*|*JPEG*|*GIF*) command -v exiftool >/dev/null && run "exiftool '$F' | head -30"
          command -v pngcheck >/dev/null && run "pngcheck -vt '$F' | head -20" ;;
  *Matroska*|*MPEG*|*MP4*) command -v ffprobe >/dev/null && run "ffprobe -v error -show_format -show_streams '$F' 2>&1 | head -60" ;;
esac

echo "================= TRIAGE SUMMARY ================="
echo "证据已落盘: $OUT"
echo "--- 签名字段（binwalk）---"
grep -A40 '^### timeout 120 binwalk' "$OUT" 2>/dev/null | grep -Ei 'zip|gzip|png|jpeg|xz|7z|cpio|zlib|squash|cramfs|lzma|raw' | head -10
echo "--- 归档内容（7z / zipinfo）---"
grep -Ei '^\s+(Path|Size|Attr|Name|  [0-9-]+ )' "$OUT" | head -10
echo "--- 可疑字符串（rabin2 -zz / strings）---"
grep -Eio '(flag|ctf|qwb|secret|key|pass)[a-z0-9_{}-]{0,40}' "$OUT" | sort -u | head -10
echo "================================================="
echo "★ 先看上面三段再动手。若签名/归档/字符串任一命中，**先解这个**，别急着分析异常块。"
