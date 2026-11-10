#!/bin/bash
# 在"能跑 wine 的沙箱"里执行任意命令，工作目录给成你要的目录（可写）。
#
# 为什么需要它：本进程所在的 DSH 沙箱把 `/` 挂只读，wine 需要写
# /run/user/<uid>/wine 建 wineserver socket，直接跑会死。pi-sandbox 里已经
# 加了顶替 tmpfs，所以借它算出的 bwrap 参数来跑——顺便让 wine 看到
# 你指定的 workspace（bwrap 只对该目录给可写绑定）。
#
# 用法：
#   tools/wine_run.sh <工作目录> '<要执行的命令>'
#   例：tools/wine_run.sh .tmp/li 'wine ./chall.exe a.bin b.bin 00112233'
#
# 约定：命令里用绝对路径或先 cd；WINEPREFIX 建议放 $PWD/.wp，
# 第二次起启动约 0.2s（首次建 prefix 约 10s）。
set -euo pipefail
WS=${1:?用法: wine_run.sh <工作目录> <命令>}
CMD=${2:?用法: wine_run.sh <工作目录> <命令>}
WS=$(cd "$WS" && pwd)
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export PATH="$ROOT/ctfagent/bin:$PATH"
cd "$WS"
DUMP=$(PI_SANDBOX_WORKSPACE_ROOTS="$WS" PI_SANDBOX_DUMP=1 PI_SANDBOX_SELFTEST=1 \
       pi-sandbox --selftest 2>&1)
ARGS=$(printf '%s' "$DUMP" | sed \
  's#^bwrap ##; s#~/.nodejs/bin/node ~/.ctfagent/.s1-tools/lib/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js --selftest##')
exec bwrap $ARGS /bin/sh -c "export WINEPREFIX=\${WINEPREFIX:-\$PWD/.wp} WINEDEBUG=-all; cd '$WS'; $CMD"
