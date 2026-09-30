#!/usr/bin/env bash
# tools-env.sh —— 【已迁移】工作区自带工具现已提升为跨比赛共享层
#
# 本文件保留仅为向后兼容：历史笔记/脚本里可能写了
#   source ~/ctf-2026/scripts/tools-env.sh
# 现在它只是委派到共享层，命令完全一致（jq / pwpython / pwrun / chromium-path
# 另加 web-probe）。
#
# 新位置（推荐直接使用）:
#   source ~/re-tools/tools/web-env.sh     # 只激活 Web 工具层
#   source ~/re-tools/fw-env.sh            # 固件 + Web 一起激活（最常用）
#
# 为什么迁移:
#   原先把 jq + playwright venv + chromium(658M) 装在每个比赛工作区里，
#   每场比赛都会重复几百 MB。现在统一放在 ~/re-tools/tools/，一次装到处用。

SHARED="$HOME/re-tools/tools/web-env.sh"
if [ -f "$SHARED" ]; then
  # shellcheck source=/dev/null
  . "$SHARED"
else
  echo "[!] 找不到共享工具层: $SHARED" >&2
  echo "    重建步骤:" >&2
  echo "      python3 -m venv ~/re-tools/tools/venv" >&2
  echo "      ~/re-tools/tools/venv/bin/pip install playwright" >&2
  echo "      PLAYWRIGHT_BROWSERS_PATH=~/re-tools/tools/ms-playwright \\" >&2
  echo "        ~/re-tools/tools/venv/bin/playwright install chromium" >&2
  return 1 2>/dev/null || exit 1
fi
