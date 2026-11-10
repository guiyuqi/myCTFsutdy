#!/usr/bin/env bash
# install-android-sdk.sh —— 装 Android emulator + x86_64 system image
#
# 前提：/dev/kvm 存在（WSL2 需在 .wslconfig 里开 nestedVirtualization=true + wsl --shutdown）
# 不需要 sudo：装到 $ANDROID_HOME，wrapper 放 ~/re-tools/bin/
#
# 用法:
#   bash scripts/install-android-sdk.sh                 # 完整安装
#   bash scripts/install-android-sdk.sh --check         # 只查前提，不下载
#   bash scripts/install-android-sdk.sh --wrappers-only # SDK 已装在别处时，只写 PATH wrapper
#
# 为什么必须检查 /dev/kvm：没有它 emulator 只能走 TCG 软件模拟，
# 启动 UE 类 APK 往往十几分钟起不来 —— 装了也是摆设（2026-10-25 实测本机无 /dev/kvm）。
#
# 2026-10-25 踩过的两个坑（已修）：
#   1) ANDROID_HOME 被系统 /etc/profile.d/android-sdk.sh 设成 /opt/android-sdk，
#      而 fw-env.sh 又把它改成 ~/re-tools/android（那里没有 emulator）→
#      wrapper 必须**硬编码**真实 SDK 根，不能运行时再读 $ANDROID_HOME。
#   2) wrapper 曾写到 dirname(ANDROID_HOME)/bin = /opt/bin（不存在，不可写）→
#      改为固定写 ~/re-tools/bin（fw-env 的 PATH 首位，必然可写）。
set -uo pipefail

MODE="install"
case "${1:-}" in
  --check)         MODE=check ;;
  --wrappers-only) MODE=wrappers ;;
  "")              ;;
  *) echo "用法: $0 [--check|--wrappers-only]"; exit 2 ;;
esac

ANDROID_HOME="${ANDROID_HOME:-$HOME/re-tools/android}"
SDK_ROOT="$ANDROID_HOME"
BIN_DIR="$HOME/re-tools/bin"
CMDLINE_URL="https://dl.google.com/android/repository/commandlinetools-linux-16111833_latest.zip"
SYSIMG="system-images;android-30;google_apis;x86_64"
AVD="ctf"

ok()  { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
bad() { printf '  \033[31mMISS\033[0m  %s\n' "$1"; }
info(){ printf '  ..    %s\n' "$1"; }
sect() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }

echo "=== Android SDK 安装（mode=$MODE）==="
echo "  SDK_ROOT = $SDK_ROOT"
echo "  BIN_DIR  = $BIN_DIR"

SDKM="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
AVDM="$SDK_ROOT/cmdline-tools/latest/bin/avdmanager"

write_wrappers() {
  sect "4. 写入 PATH wrapper（硬编码 SDK 根，避免被 fw-env 覆盖）"
  if [ ! -x "$SDK_ROOT/emulator/emulator" ]; then
    bad "$SDK_ROOT/emulator/emulator 不存在 —— 先用不带 --wrappers-only 的方式装 SDK"
    return 1
  fi
  mkdir -p "$BIN_DIR"
  mk() { # mk <名字> <真实二进制>
    local n="$1" real="$2"
    if cat > "$BIN_DIR/$n" 2>/dev/null <<EOF
#!/usr/bin/env bash
# 由 install-android-sdk.sh 生成。**硬编码** SDK 根：
# fw-env.sh 会把 ANDROID_HOME 改成 \$HOME/re-tools/android（没有 emulator）。
export ANDROID_HOME="$SDK_ROOT"
export ANDROID_SDK_ROOT="$SDK_ROOT"
exec "$real" "\$@"
EOF
    then
      if chmod +x "$BIN_DIR/$n" 2>/dev/null; then ok "$BIN_DIR/$n"; return 0; fi
    fi
    bad "写不进 $BIN_DIR/$n（目录只读？）"; return 1
  }
  local rc=0
  mk emulator "$SDK_ROOT/emulator/emulator" || rc=1
  [ -x "$SDKM" ] && { mk sdkmanager "$SDKM" || rc=1; }
  [ -x "$AVDM" ] && { mk avdmanager "$AVDM" || rc=1; }
  return $rc
}

verify() {
  sect "5. 验证"
  case ":$PATH:" in *":$BIN_DIR:"*) ok "$BIN_DIR 已在 PATH" ;;
    *) bad "$BIN_DIR 不在 PATH —— 先 source ~/re-tools/fw-env.sh 再测" ;; esac
  command -v emulator >/dev/null 2>&1 && ok "emulator 在 PATH" || bad "emulator 不在 PATH"
  timeout 30 "$BIN_DIR/emulator" -version 2>/dev/null | head -1 | sed 's/^/  /'
  command -v adb >/dev/null 2>&1 && ok "adb 可用" || bad "adb 缺失"
  if [ -e /dev/kvm ]; then ok "/dev/kvm 存在（可用硬件加速）"; else
    bad "/dev/kvm 缺失 —— 只能 TCG 软件模拟，UE 类 APK 基本跑不动"; fi
}

# ---------------------------------------------------------------- 0. 前提
sect "0. 前提检查"
if [ -e /dev/kvm ]; then ok "/dev/kvm 存在"; KVM=1; else bad "/dev/kvm 不存在"; KVM=0; fi
command -v java >/dev/null 2>&1 && ok "java: $(java -version 2>&1 | head -1)" || bad "缺 java"
command -v unzip >/dev/null 2>&1 && ok "unzip 可用" || bad "缺 unzip"
FREE_G=$(df -BG "$HOME" | awk 'NR==2{gsub(/G/,"",$4); print $4}')
[ "${FREE_G:-0}" -ge 10 ] && ok "磁盘余量 ${FREE_G}G（需 ≥10G）" || bad "磁盘余量 ${FREE_G}G < 10G"

# 只写 wrapper：跳过 KVM 与下载
if [ "$MODE" = "wrappers" ]; then
  write_wrappers || exit 1
  verify
  exit 0
fi
if [ "$MODE" = "check" ]; then
  echo; echo "前提检查完成（--check，不下载）"; [ "$KVM" = 1 ] && exit 0 || exit 3
fi

if [ "$KVM" = "0" ]; then
  cat <<'EOF'

  ⚠️ 没有 /dev/kvm，先做这一步（在 Windows 侧）：

    1) C:\Users\<你>\.wslconfig 的 [wsl2] 下加：nestedVirtualization=true
    2) Windows PowerShell：wsl --shutdown
    3) 重开 WSL，确认：ls -l /dev/kvm
    4) 有 /dev/kvm 后再跑本脚本

  若 .wslconfig 已改且已重启仍无 /dev/kvm，用**管理员** PowerShell 查：
    Get-CimInstance Win32_Processor | Select Name, VirtualizationFirmwareEnabled
      → False 表示 BIOS 里 SVM/AMD-V 没开（AMD 平台常见）
    Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform | Select State
      → Disabled 则：Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All
EOF
  exit 3
fi

# ---------------------------------------------------------------- 1. cmdline-tools
sect "1. cmdline-tools"
mkdir -p "$SDK_ROOT"
if [ -x "$SDKM" ]; then
  ok "已存在，跳过下载"
else
  TMP=$(mktemp -d)
  info "下载 $CMDLINE_URL"
  if curl -sSL --retry 3 --retry-delay 2 -o "$TMP/cmdline-tools.zip" "$CMDLINE_URL"; then
    mkdir -p "$SDK_ROOT/cmdline-tools"
    ( cd "$TMP" && unzip -q cmdline-tools.zip )
    rm -rf "$SDK_ROOT/cmdline-tools/latest"
    mv "$TMP/cmdline-tools" "$SDK_ROOT/cmdline-tools/latest"
    ok "解包到 $SDK_ROOT/cmdline-tools/latest"
  else
    bad "下载失败（网络/代理）。可手动下载后解到 $SDK_ROOT/cmdline-tools/latest"
    rm -rf "$TMP"; exit 1
  fi
  rm -rf "$TMP"
fi

# ---------------------------------------------------------------- 2. emulator + 镜像
sect "2. 安装 emulator + system image（约 2–3 GB，慢）"
export ANDROID_HOME="$SDK_ROOT" ANDROID_SDK_ROOT="$SDK_ROOT"
yes 2>/dev/null | "$SDKM" --licenses >/dev/null 2>&1 && ok "licenses 已接受" || info "licenses 步骤有告警（继续）"
if "$SDKM" "emulator" "$SYSIMG" 2>&1 | tail -6; then
  ok "emulator + $SYSIMG 安装完成"
else
  bad "sdkmanager 安装失败"; exit 1
fi

# ---------------------------------------------------------------- 3. AVD
sect "3. 创建 AVD（$AVD）"
if "$AVDM" list avd 2>/dev/null | grep -q "Name: $AVD"; then
  ok "AVD '$AVD' 已存在"
else
  echo no | "$AVDM" create avd -n "$AVD" -k "$SYSIMG" -d pixel_5 --force >/dev/null 2>&1 \
    && ok "已创建 AVD '$AVD'" || { bad "AVD 创建失败"; exit 1; }
fi

write_wrappers || exit 1
verify

cat <<EOF

=== 下一步（手动）===
  source ~/re-tools/fw-env.sh          # 必需：让 $BIN_DIR 进 PATH
  emulator -avd $AVD -no-window -no-audio -gpu swiftshader_indirect > /tmp/emu.log 2>&1 &
  timeout 300 adb wait-for-device && adb devices    # 一定要带 timeout，否则会永久挂住

  # 无 KVM 时只能试 TCG（慢，10 分钟不 booted 就放弃）：
  emulator -avd $AVD -no-window -no-audio -no-snapshot -accel off -gpu swiftshader_indirect &

  # 安装 APK / 放 OBB
  adb install -r <app.apk>
  adb shell mkdir -p /sdcard/Android/obb/<pkg>
  adb push <main.obb> /sdcard/Android/obb/<pkg>/main.<ver>.<pkg>.obb

  验证能力断言：
  bash ~/ctf-2026/scripts/selfcheck.sh --capabilities
EOF
