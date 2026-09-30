#!/usr/bin/env bash
# smoke-test.sh —— 赛前/赛中的工具链冒烟测试
#
# 用一个可解的模拟题，把 AGENTS.md 的标准流程完整跑一遍，
# 逐项报告通过/失败。目的是在真题到来前发现"哪一步会断"。
#
# 用法:
#   bash scripts/smoke-test.sh              # 全流程（含 Ghidra 反编译，约 1-2 分钟）
#   bash scripts/smoke-test.sh --quick      # 跳过 Ghidra 反编译
#
# 依赖: ~/ctf/firmware/openwrt-x86-64.img（夹具镜像）
#   没有夹具时会跳过镜像相关步骤，仅做环境自检。
set -uo pipefail

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

WORK="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="${FIXTURE:-$HOME/ctf/firmware/openwrt-x86-64.img}"
DIR="$WORK/work/smoke"
FLAG='flag{sm0ke_t3st_0k}'
PASS=0; FAIL=0; SKIP=0

ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "  [SKIP] $1"; SKIP=$((SKIP+1)); }
hr()   { echo; echo "=== $1 ==="; }

# ---------- 1. 环境自检 ----------
hr "1. 环境自检"
if ! source "$HOME/re-tools/fw-env.sh" >/dev/null 2>&1; then
  bad "fw-env.sh 无法 source"
else
  ok "fw-env.sh 已激活"
fi

V=$(rea --version 2>/dev/null)
[ "$V" = "3.1.0" ] && ok "rea $V" || bad "rea 版本异常: ${V:-缺失}"

qemu-mipsel-static --version >/dev/null 2>&1 && ok "qemu-mipsel-static 可执行" || bad "qemu-mipsel-static 不可用"

MISSING=""
for t in fw-decompile unsquashfs rea python3; do
  command -v "$t" >/dev/null 2>&1 || MISSING="$MISSING $t"
done
[ -z "$MISSING" ] && ok "核心工具齐全" || bad "缺失:$MISSING"

[ -n "${XDG_CONFIG_HOME:-}" ] && ok "XDG_CONFIG_HOME=$XDG_CONFIG_HOME" || bad "XDG_CONFIG_HOME 未设置（Ghidra 会写工作区外）"

python3 -c 'import capstone,unicorn,lief,angr,pwn' 2>/dev/null \
  && ok "Python 逆向库 (capstone/unicorn/lief/angr/pwntools)" || bad "Python 逆向库导入失败"

# ---------- 2. 搭建模拟题 ----------
hr "2. 搭建模拟题"
if [ ! -f "$FIXTURE" ]; then
  skip "夹具不存在，跳过镜像流程: $FIXTURE"
else
  rm -rf "$DIR"; mkdir -p "$DIR"
  cp "$FIXTURE" "$DIR/challenge.bin" && ok "复制夹具为 challenge.bin" || bad "复制夹具失败"

  rm -rf "$DIR/rootfs.orig"; mkdir -p "$DIR/stage"
  dd if="$DIR/challenge.bin" of="$DIR/p2.bin" bs=512 skip=33792 count=212992 status=none
  # 注意：unsquashfs 的退出码实测会在 0/2 之间波动（即使完全成功），
  # 因此按"解出的文件数"判定，不看退出码。这与 fw-decompile 那次的教训一致：
  # 只信退出码会误判，必须校验产物本身。
  unsquashfs -d "$DIR/rootfs.orig" -no-progress "$DIR/p2.bin" >/dev/null 2>&1
  NFILES=$(find "$DIR/rootfs.orig" -type f 2>/dev/null | wc -l)
  [ "$NFILES" -gt 100 ] && ok "夹具 p2 解包成功（$NFILES 个文件）" || bad "夹具 p2 解包失败（仅 $NFILES 个文件）"

  mkdir -p "$DIR/rootfs.orig/etc/config"
  printf 'config backdoor\n\toption token %s\n' "'$FLAG'" > "$DIR/rootfs.orig/etc/config/backdoor"
  mksquashfs "$DIR/rootfs.orig" "$DIR/p2-new.sqfs" -comp xz -b 262144 -no-progress >/dev/null 2>&1 \
    && ok "重打包 squashfs" || bad "mksquashfs 失败"

  dd if="$DIR/p2-new.sqfs" of="$DIR/challenge.bin" bs=512 seek=33792 conv=notrunc status=none \
    && ok "植入并回写镜像" || bad "回写镜像失败"
fi

# ---------- 3. 标准流程解题 ----------
hr "3. 标准流程（切分区 → 拆包 → 找 flag）"
if [ -f "$DIR/challenge.bin" ]; then
  # Step1 识别
  file "$DIR/challenge.bin" | grep -qi 'MBR boot sector' && ok "Step1 识别为 MBR 镜像" || bad "Step1 识别失败"

  # Step2 切分区
  PARTS=$(python3 - "$DIR/challenge.bin" <<'PY'
import struct,sys
mbr=open(sys.argv[1],'rb').read(512)
n=0
for i in range(4):
    e=mbr[446+i*16:446+(i+1)*16]
    if e[4]: n+=1
print(n)
PY
)
  [ "$PARTS" -ge 1 ] && ok "Step2 解析出 $PARTS 个分区" || bad "Step2 未解析出分区"

  # Step3 拆文件系统
  dd if="$DIR/challenge.bin" of="$DIR/p2b.bin" bs=512 skip=33792 count=212992 status=none
  rm -rf "$DIR/rootfs"
  unsquashfs -d "$DIR/rootfs" -no-progress "$DIR/p2b.bin" >/dev/null 2>&1
  NFILES=$(find "$DIR/rootfs" -type f 2>/dev/null | wc -l)
  [ "$NFILES" -gt 100 ] && ok "Step3 unsquashfs 拆包成功（$NFILES 个文件）" || bad "Step3 unsquashfs 失败"

  # Step4 找敏感信息
  FOUND=$(grep -rhoE 'flag\{[^}]*\}' "$DIR/rootfs/etc" "$DIR/rootfs/root" 2>/dev/null | head -1)
  if [ "$FOUND" = "$FLAG" ]; then
    ok "Step4 成功取出 flag: $FOUND"
  else
    bad "Step4 flag 未取出 (期望 $FLAG, 得到 '${FOUND:-空}')"
  fi

  # Step5 定位主程序（用 file {} + 批量调用，比逐个 -exec 快得多）
  NELF=$(find "$DIR/rootfs" -type f -exec file {} + 2>/dev/null | grep -c 'ELF')
  [ "$NELF" -gt 0 ] && ok "Step5 发现 $NELF 个 ELF" || bad "Step5 未发现 ELF"

  # Step6 反编译
  if [ "$QUICK" = "1" ]; then
    skip "Step6 反编译（--quick）"
  else
    TGT="$DIR/rootfs/usr/sbin/uhttpd"
    if [ -f "$TGT" ]; then
      FW_OUTDIR="$DIR/dec" FW_PROJ="$DIR/proj" fw-decompile "$TGT" 20 > "$DIR/decompile.log" 2>&1
      if [ $? -eq 0 ] && grep -q '### DECOMPILED_COUNT' "$DIR/dec/uhttpd_.c" 2>/dev/null; then
        ok "Step6 反编译成功 ($(grep -aoE 'DECOMPILED_COUNT: [0-9]+' "$DIR/dec/uhttpd_.c" | head -1))"
      else
        bad "Step6 反编译失败，见 $DIR/decompile.log"
      fi
    else
      skip "Step6 目标不存在，跳过"
    fi
  fi

  # Step7 仿真
  if [ -x "$DIR/rootfs/lib/ld-musl-x86_64.so.1" ] || [ -L "$DIR/rootfs/lib/ld-musl-x86_64.so.1" ]; then
    # 注意：不能写成 `... | grep -q Usage`，因为脚本启用了 pipefail，
    # 而 uhttpd 因 `-h` 缺参数会 exit 1，会把管道判定为失败（即使 grep 匹配到）。
    # 先把输出抓下来，再单独判定。
    DOUT=$( cd "$DIR/rootfs" && ./lib/ld-musl-x86_64.so.1 \
              --library-path ./lib:./usr/lib ./usr/sbin/uhttpd -h 2>&1 )
    case "$DOUT" in
      *Usage:*) ok "Step7 二进制可动态执行（打印出 usage）" ;;
      *)        bad "Step7 动态执行失败: $(echo "$DOUT" | head -1)" ;;
    esac
  else
    skip "Step7 无 musl loader，跳过（非 x86_64 目标请用 qemu -L）"
  fi
else
  skip "无夹具，跳过 Step1-7"
fi

# ---------- 4. 结论 ----------
hr "结论"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
if [ "$FAIL" -eq 0 ]; then
  echo "  ✅ 工具链可用"
else
  echo "  ❌ 有 $FAIL 项失败，先修再开赛"
fi
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
