#!/usr/bin/env bash
# selfcheck.sh —— CTF 解题环境自检（本工作区的官方入口）
#
# 用法:
#   bash scripts/selfcheck.sh                 # 快速自检（几秒，命令/导入存在性）
#   bash scripts/selfcheck.sh --full          # 附加端到端冒烟（Ghidra 反编译 / squashfs 解包 / 浏览器）
#   bash scripts/selfcheck.sh --capabilities  # 能力断言：真跑一次，判"装了 != 能用"
#
# 设计原则：**用激活后的解释器验**，避免"以为没有某包"这类误判
#   （python 逆向库在 ~/re-tools/pylibs，必须 source fw-env.sh 后才会出现在 sys.path）
#
# 出处：~/ctf/templates/ENV-SELFCHECK.template.md + 2026-10-13 赛前实测。
set -uo pipefail

# 三种模式：默认快速 / --full 端到端冒烟 / --capabilities 能力断言
MODE=quick
case "${1:-}" in
  --full)         MODE=full ;;
  --capabilities) MODE=caps ;;
  "")             ;;
  *) echo "用法: $0 [--full|--capabilities]"; exit 2 ;;
esac
FULL=0; [ "$MODE" = "full" ] && FULL=1
CAPS=0; [ "$MODE" = "caps" ] && CAPS=1

WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# ⚠️ 临时目录名**不能以 '.' 开头**：Ghidra 的 analyzeHeadless 会拒绝任何带
# 点号开头路径元素的工程目录（"Path element starting with '.' is not permitted"），
# 于是 fw-decompile 在这种 cwd 下必然失败。实测踩过，故这里用 selfcheck-tmp。
TMPD="$WS/work/selfcheck-tmp"

pass=0
fail=0
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mMISS\033[0m  %s\n' "$1"; fail=$((fail+1)); }
chk()  { if command -v "$1" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
sect() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }

printf '\033[1m=== CTF 环境自检  %s  (mode=%s) ===\033[0m\n' "$(date '+%F %T')" "$MODE"
echo "工作区: $WS"

# ---------------------------------------------------------------- 0. 激活工具链
sect "0. 工具链激活"
if ! source "$HOME/re-tools/fw-env.sh" >/dev/null 2>&1; then
  bad "无法 source ~/re-tools/fw-env.sh"; echo; echo "自检中止"; exit 2
fi
case ":${PYTHONPATH:-}:" in
  *"/re-tools/pylibs"*) ok "PYTHONPATH 已注入 re-tools/pylibs" ;;
  *) bad "PYTHONPATH 未注入（python 逆向库会全部 import 失败）" ;;
esac
PY="$(command -v python3)"
ok "python3 = $PY ($("$PY" -V 2>&1))"
[ -n "${GHIDRA_INSTALL_DIR:-}" ] && [ -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ] \
  && ok "Ghidra = $GHIDRA_INSTALL_DIR" || bad "Ghidra analyzeHeadless 不可执行"

# ------------------------------------------------- 1. 反编译脚本（fw-decompile 依赖）
sect "1. fw-decompile 反编译脚本（缺了会让所有原生二进制题直接失败）"
if [ -f "$WS/scripts/DecompileScript.java" ]; then
  ok "$WS/scripts/DecompileScript.java"
else
  bad "$WS/scripts/DecompileScript.java —— 修复: cp ~/ctf/scripts/DecompileScript.java $WS/scripts/"
fi

# ----------------------------------------------------------- 2. 环境层自带命令
sect "2. 环境层自带命令（~/re-tools/bin）"
for c in fw-decompile unsquashfs sasquatch jefferson mksquashfs \
         ubireader_extract_images ubireader_extract_files \
         qemu-mipsel-static qemu-arm-static qemu-aarch64-static qemu-riscv64-static \
         rea jq chromium-path web-probe pwpython; do chk "$c"; done

# ------------------------------------------------- 2.5 移动 / 语言运行时（2026-10-13 扩充）
sect "2.5 移动题 / 语言运行时（Android · Go · Rust · .NET）"
for c in jadx apktool adb go rustc cargo dotnet; do chk "$c"; done
# 功能级：不只看在不在（Java/.NET 程序"存在但起不来"很常见）
_ver() { # _ver <命令> <参数> <展示名>
  if command -v "$1" >/dev/null 2>&1 && out=$("$1" "$2" 2>&1 | head -1) && [ -n "$out" ]; then ok "$3 → $out"; else bad "$3（命令存在但跑不起来）"; fi
}
_ver jadx --version "jadx --version"
_ver apktool --version "apktool --version"
_ver adb version "adb version"
_ver go version "go version"
_ver rustc --version "rustc --version"
_ver dotnet --version "dotnet --version"
# frida：核心是 Python 模块（CLI 由 frida-tools 提供，属可选）
if "$PY" -c "import frida" 2>/dev/null; then
  ok "python 模块 frida $("$PY" -c 'import frida;print(frida.__version__)' 2>/dev/null)"
else
  bad "python 模块 frida（Android/iOS 动态 Hook 的核心）"
fi
for c in frida frida-ps objection; do
  if command -v "$c" >/dev/null 2>&1; then ok "$c（frida-tools/objection CLI）"; else echo "  INFO  $c 未装（可选：frida-tools / objection 的 CLI 包装）"; fi
done

# ------------------------------------------------------------------ 2.6 字典
sect "2.6 字典（~/re-tools/wordlists/seclists）"
WL="${WORDLISTS:-$HOME/re-tools/wordlists}/seclists"
for f in Discovery/Web-Content/common.txt \
         Discovery/Web-Content/raft-medium-directories.txt \
         Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
         Discovery/DNS/subdomains-top1million-5000.txt \
         Passwords/Common-Credentials/Pwdb_top-100000.txt \
         Passwords/Leaked-Databases/rockyou.txt.tar.gz \
         Usernames/top-usernames-shortlist.txt; do
  if [ -s "$WL/$f" ]; then ok "$f（$(wc -l < "$WL/$f") 行）"; else bad "$WL/$f"; fi
done

# --------------------------------------------------- 2.7 沙箱能力（信息，不计失败）
sect "2.7 沙箱能力（仅信息，不计入失败数）"
if "$PY" -c "import socket;socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)" 2>/dev/null; then
  echo "  INFO  RAW socket 可用（可直接 nmap -sS / scapy 发包 / ARP）"
else
  echo "  INFO  RAW socket 被沙箱拒绝（bwrap --cap-drop）——需要发包/扫描时走 Docker："
  echo "        docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --network host <镜像> <cmd>"
  echo "        （↑ 已实测：这样 nmap -sS 可对宿主端口正常扫描）"
fi
if docker info >/dev/null 2>&1; then ok "docker daemon（RAW socket 备用通道可用）"; else bad "docker daemon 不可达（RAW socket 备用通道失效）"; fi

# ------------------------------- 2.8 赛前高危缺口（仅信息，不计入失败数）
# 来源：2026-10-18 ctf.show 环境体检（~/ctf/SESSION-HANDOVER-2026-10-18-ctfshow-envcheck.md）。
# 这些缺口不会让日常自检变红，但会在**特定题型**上直接把能力归零——所以显式列出来，
# 把"发现缺工具"从赛中挪到赛前。
sect "2.8 赛前高危缺口（仅信息，不计失败）"
gaps=0
_gap_cmd() { # _gap_cmd <名字> <命令> [提示]
  printf "  %-22s " "$1"
  if command -v "$2" >/dev/null 2>&1; then echo "有"; else echo "缺${3:+（$3）}"; gaps=$((gaps+1)); fi
}
printf "  %-22s " "i386（32 位）"
if [ -e /lib/ld-linux.so.2 ] || [ -e /lib32/ld-linux.so.2 ]; then echo "有（原生 loader）"
elif command -v i386-run >/dev/null 2>&1; then echo "有（i386-run → qemu -L 预置 GLIBC）"
else echo "缺（32 位 ELF 跑不了）→ libc6:i386，或 i386 rootfs + qemu-i386-static -L"; gaps=$((gaps+1)); fi
for t in bkcrack fcrackzip john zip2john; do _gap_cmd "$t" "$t" "zip/口令题核心"; done
printf "  %-22s " "john 格式数"
if command -v john >/dev/null 2>&1; then
  n=$(john --list=formats 2>/dev/null | tr ',' '\n' | wc -l)
  if [ "${n:-0}" -gt 100 ]; then echo "有（jumbo $n 个格式）"; else echo "少（$n 个，可能拿到的是 classic john）"; fi
else echo "缺"; gaps=$((gaps+1)); fi
printf "  %-22s " "hashcat"
if command -v hashcat >/dev/null 2>&1; then
  dev=$(hashcat -I 2>/dev/null | grep -c 'Device ID' || true)
  if [ "${dev:-0}" -gt 0 ]; then echo "有（$dev 个 OpenCL 设备）"
  else echo "有二进制但 **0 个 OpenCL 设备**（需 GPU 或 pocl）→ CPU 破解用 john"; fi
else echo "缺"; gaps=$((gaps+1)); fi
printf "  %-22s " "pyzipper"
if "$PY" -c "import pyzipper" 2>/dev/null; then echo "有（AES-ZIP 读写）"; else echo "缺"; gaps=$((gaps+1)); fi
_gap_cmd ssh ssh
for t in sshpass expect; do _gap_cmd "$t" "$t" "ssh 类 PWN 无法脚本化"; done
printf "  %-22s " "libcdb（在线）"
if timeout 25 libcdb lookup puts 809c0 >/dev/null 2>&1; then echo "可用（libc.rip）"
else echo "不可用（断网时需本地 DB）"; gaps=$((gaps+1)); fi
printf "  %-22s " "libc 离线 DB"
if [ -d "$HOME/re-tools/libc-database" ]; then echo "有"; else echo "无（可选：libcdb fetch \$HOME/re-tools/libc-database）"; fi
printf "  %-22s " "wine"
if command -v wine >/dev/null 2>&1; then
  echo "有二进制但**跑不起来**（wineserver 需 mkdir /run/user/\$UID/wine，沙箱只读）→ PE 动态验证走 Unicorn/angr"
else echo "无"; fi
echo "  ↳ 本段 $gaps 项缺失；补齐属「人类装包」，记进 needs-approval.md，不要自行安装。"

# --------------------------------------------------------------- 3. 系统工具
sect "3. 系统工具"
for c in ffmpeg zbarimg tshark tcpdump upx pdftotext exiftool sqlite3 nasm \
         r2 radare2 binwalk foremost pngcheck steghide nc gcc gdb; do chk "$c"; done

# --------------------------------------------------------------- 4. Python 库
sect "4. Python 库（必须用激活后的解释器验）"
"$PY" - <<'PY'
import importlib
mods = ["requests","PIL","numpy","scipy","sympy","z3","angr","capstone","keystone",
        "unicorn","lief","pwn","cryptography","Crypto","cv2","pyzbar","reedsolo",
        "pypdf","zstandard","elftools","r2pipe"]
bad = []
for m in mods:
    try: importlib.import_module(m)
    except Exception: bad.append(m)
print("  MISS: " + (", ".join(bad) if bad else "none —— 全部可用"))
# 可选包单列（缺失不应判 fail，只是题型覆盖变窄）
opt = []
for m in ["scapy","ropper","frida"]:
    try: importlib.import_module(m)
    except Exception: opt.append(m)
print("  可选包缺失（记入 needs-approval.md）: " + (", ".join(opt) if opt else "none"))
PY

# ------------------------------------------------------- 5. 功能级验证（不是只 import）
sect "5. 功能级验证"
"$PY" - <<'PY' && ok "python 逆向库功能级（unicorn 执行 / z3 求解 / cv2）" || bad "python 逆向库功能级"
import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RAX
mu = Uc(UC_ARCH_X86, UC_MODE_64); mu.mem_map(0x1000, 0x1000)
mu.mem_write(0x1000, b"\x48\xc7\xc0\x2a\x00\x00\x00")     # mov rax,42
mu.emu_start(0x1000, 0x1007)
assert mu.reg_read(UC_X86_REG_RAX) == 42, "unicorn 执行结果不对"
import z3
s = z3.Solver(); x = z3.Int("x"); s.add(x * x == 49, x > 0); s.check()
assert s.model()[x].as_long() == 7, "z3 求解结果不对"
import cv2
assert hasattr(cv2, "QRCodeDetector"), "cv2 无 QRCodeDetector"
print("    unicorn/z3/cv2 功能正常")
PY
if r2 -q -c 'iI' /bin/true 2>/dev/null | grep -q ELF; then ok "r2 反汇编"; else bad "r2 反汇编"; fi
# 注意：这里不能用 `binwalk ... | grep -q`。本脚本开了 pipefail，grep -q 命中即退出，
# 上游 binwalk 收到 SIGPIPE 后整条管道状态变 141，于是"明明有输出"却被判成 MISS
# （实测踩过：同一管道 `wc -c` 有 469 字节，而 `grep -qi ELF` 返回 NOMATCH）。
# 一律先落变量再匹配。
_bw="$(binwalk /bin/true 2>/dev/null || true)"
case "$_bw" in *ELF*) ok "binwalk 签名扫描" ;; *) bad "binwalk 签名扫描（无输出或未识别 ELF）" ;; esac

# ------------------------------------------------ 5.5 能力断言（--capabilities）
# 为什么不用 command -v：**装了 != 能跑**（Java/.NET/浏览器都踩过"存在但起不来"）。
# 断言 = 真的执行一次，用退出码判定。
caplack=()
cap() { # cap <p0|p1> <名字> <影响的题型> <命令...>
  local prio="$1" name="$2" impact="$3"; shift 3
  if "$@" >/dev/null 2>&1; then
    printf '  \033[32mOK\033[0m    %-22s %s\n' "$name" "$impact"; pass=$((pass+1))
  elif [ "$prio" = "p0" ]; then
    printf '  \033[31mMISS\033[0m  %-22s %s  ← P0 阻塞\n' "$name" "$impact"; fail=$((fail+1))
  else
    printf '  \033[33mMISS\033[0m  %-22s %s\n' "$name" "$impact"; caplack+=("$name")
  fi
}

if [ "$CAPS" = "1" ]; then
  sect "5.5 能力断言（--capabilities：真跑一次，不看 command -v）"

  # --- P0：缺了会直接失去一整类题 ---
  cap p0 "fw-decompile"     "原生二进制反编译"       bash -c "command -v fw-decompile >/dev/null && test -f '$WS/scripts/DecompileScript.java'"
  cap p0 "squashfs 链"      "固件解包（标准+非标准）" bash -c "command -v unsquashfs >/dev/null && command -v mksquashfs >/dev/null && command -v sasquatch >/dev/null"
  cap p0 "python 逆向库"    "unicorn/z3/cv2 功能级"  "$PY" -c "import unicorn,z3,cv2;assert hasattr(cv2,'QRCodeDetector')"
  # 注意：chromium-path 是 web-env.sh 定义的 shell 函数，`bash -c` 里看不到它，
  # 必须在当前 shell 求值后再把路径传给 test（否则永远 MISS）。
  _chrome="$(chromium-path 2>/dev/null || true)"
  cap p0 "浏览器"           "Web / 前端逆向"          test -x "$_chrome"
  # 出网必须用 HEAD 探测。**不要**探 pypi.org/simple/：那是 47.6MB 的索引页，
  # 即便 `-o /dev/null` 也照收 body，实测 8.6~13.9s；撞上超时就被误判成"断网"
  # （2026-10-25 实际踩过：出网 200 却报 P0 MISS，差点记进 needs-approval.md）。
  cap p0 "出网"             "拉附件 / 查资料"         bash -c "curl -sSfI -o /dev/null --max-time 8 https://pypi.org/"
  cap p0 "qemu 异构"        "异构仿真"                qemu-mipsel-static -version

  # 代码托管可达性：只报不拦。本机 github.com / raw.githubusercontent.com 常被干扰
  # 而 api.github.com 通 —— 需要取文件时走 `/repos/<owner>/<repo>/contents/<path>`（返回 base64）。
  _probe() { curl -sSfI -o /dev/null --max-time 6 "$1" >/dev/null 2>&1 && echo "通" || echo "不通"; }
  printf '  \033[36mINFO\033[0m  代码托管可达性          github.com %s / raw %s / api.github.com %s\n' \
    "$(_probe https://github.com/)" "$(_probe https://raw.githubusercontent.com/)" "$(_probe https://api.github.com/)"

  # --- P1：按题型需要（缺了记 needs-approval.md，不阻塞开赛）---
  cap p1 "pyzipper"         "加密 ZIP（WinZip-AES）"  "$PY" -c "import pyzipper"
  cap p1 "pyewf/libewf"     "E01 取证镜像"            "$PY" -c "import pyewf"
  # ASTC：二进制 astcenc 或纯 Python 的 texture2ddecoder，任一即可（后者免 sudo）
  _astc_ok=0
  command -v astcenc >/dev/null 2>&1 && _astc_ok=1
  "$PY" -c "import texture2ddecoder" >/dev/null 2>&1 && _astc_ok=1
  cap p1 "ASTC 解码"        "UE/移动纹理（astcenc 或 texture2ddecoder）" test "$_astc_ok" = 1
  cap p1 "tesseract"        "OCR（需 sudo apt install）"  bash -c "command -v tesseract >/dev/null"
  cap p1 "adb"              "Android 静态/真机"       adb version
  cap p1 "android emulator" "Android 动态"            bash -c "command -v emulator >/dev/null"
  cap p1 "wine"             "Windows PE 轻量"         wine --version
  cap p1 "unblob"           "现代固件解包"            bash -c "command -v unblob >/dev/null"
  cap p1 "gadget 工具"      "pwn gadget"              bash -c "command -v one_gadget >/dev/null || command -v ROPgadget >/dev/null"
  cap p1 "WP 出 PDF"        "交付物"                  bash -c "command -v pandoc >/dev/null || test -f '$WS/scripts/md2pdf.py'"

  if [ ${#caplack[@]} -gt 0 ]; then
    echo
    echo "  以下 P1 能力缺失（按题型决定装不装，需人类批准）:"
    for c in "${caplack[@]}"; do echo "    - $c"; done
    echo "  → 复制到 needs-approval.md 再决定"
  fi
fi

# ------------------------------------------------------- 6. 端到端冒烟（--full）
if [ "$FULL" = "1" ]; then
  sect "6. 端到端冒烟（--full）"
  rm -rf "$TMPD"; mkdir -p "$TMPD/rootfs/etc"
  trap 'rm -rf "$TMPD"' EXIT

  # 6a. gcc → Ghidra 反编译（真跑，验证"装了 != 能用"）
  printf '#include <stdio.h>\nint add(int a,int b){return a*b+7;}\nint main(int c,char**v){printf("%%d\\n",add(c,42));return 0;}\n' > "$TMPD/t.c"
  if gcc -O0 -o "$TMPD/t" "$TMPD/t.c" 2>/dev/null; then
    ( cd "$TMPD" && env -u FW_SCRIPTS timeout 300 fw-decompile ./t 40 > fw.log 2>&1 )
    # 收尾行在【产物 .c】里，不在 fw-decompile 的控制台输出里（控制台只有统计数字）。
    # 早期版本误 grep 了 fw.log，导致明明成功却报 MISS——日志与产物要分清。
    _art="$TMPD/decompiled/t_.c"
    if grep -qa '### DECOMPILED_COUNT' "$_art" 2>/dev/null; then
      ok "fw-decompile 端到端（$(grep -aoE 'DECOMPILED_COUNT: [0-9]+' "$_art" | head -1)）"
    else
      bad "fw-decompile 端到端（产物缺 DECOMPILED_COUNT 收尾行）"
      grep -aE 'Path element|ERROR REPORT|找不到' "$TMPD/fw.log" 2>/dev/null | head -3
    fi
  else
    bad "gcc 编译测试样本失败（无法验证 fw-decompile）"
  fi

  # 6b. squashfs 双向解包
  echo 'flag{selfcheck}' > "$TMPD/rootfs/etc/secret.conf"
  if mksquashfs "$TMPD/rootfs" "$TMPD/t.sqfs" -noappend -quiet >/dev/null 2>&1; then
    unsquashfs -d "$TMPD/out1" -no-progress "$TMPD/t.sqfs" >/dev/null 2>&1 \
      && [ "$(cat "$TMPD/out1/etc/secret.conf" 2>/dev/null)" = 'flag{selfcheck}' ] \
      && ok "unsquashfs 解包" || bad "unsquashfs 解包"
    sasquatch -d "$TMPD/out2" "$TMPD/t.sqfs" >/dev/null 2>&1 \
      && [ "$(cat "$TMPD/out2/etc/secret.conf" 2>/dev/null)" = 'flag{selfcheck}' ] \
      && ok "sasquatch 解包" || bad "sasquatch 解包"
  else
    bad "mksquashfs 造样本失败（无法验证解包链）"
  fi

  # 6c. 浏览器 / web-probe（web-probe 是 shell 函数，不能被 timeout 直接执行）
  mkdir -p "$TMPD/webroot"
  printf '<title>ENVCHECK</title><script>fetch("/api/hidden").catch(()=>{})</script>' > "$TMPD/webroot/index.html"
  python3 -m http.server 18099 --directory "$TMPD/webroot" >/dev/null 2>&1 &
  SRV=$!; sleep 1
  _probe="$(web-probe http://127.0.0.1:18099/ --wait 1200 -o "$TMPD/probe" 2>&1 || true)"
  case "$_probe" in
    *api/hidden*) ok "web-probe + chromium 端到端（抓到隐藏 API 请求）" ;;
    *) bad "web-probe + chromium 端到端" ;;
  esac
  kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null

  # 6d. qemu 静态二进制可执行
  qemu-mipsel-static -version >/dev/null 2>&1 && ok "qemu-mipsel-static 可执行" || bad "qemu-mipsel-static 可执行"
fi

# ---------------------------------------------------------------------- 汇总
printf '\n\033[1m=== 汇总: %d 项通过, %d 项缺失 ===\033[0m\n' "$pass" "$fail"
if [ "$fail" -eq 0 ]; then
  echo "环境自检通过 ✅"
  [ "$MODE" = "quick" ] && echo "（端到端: --full；能力断言: --capabilities）"
  exit 0
else
  echo "仍有缺失 ❌ —— 替代方案见 needs-approval.md；需人类安装的记到那里，不要自行安装。"
  exit 1
fi
