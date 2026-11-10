# 赛中临时补的三件工具（下次直接复用）

## 1) 把宿主工具链挂进 worker 沙箱
worker 跑在 bwrap 里，`$HOME` 被 tmpfs ⇒ `~/re-tools`（unblob/sasquatch/jefferson/ubireader/qemu-*/ghidra/pwntools）看不见。
`ctfagent/bin/pi-sandbox` 已支持清单式回绑（本场加的）：
- `engine/muteki/ctf-tools/extra-ro.txt`：每行一个路径 → `--ro-bind`
- `engine/muteki/ctf-tools/worker-env.txt`：每行 `KEY=VALUE` → `bwrap --setenv`
改清单不用重启后端，下一次 spawn 生效。

## 2) wine（PE 题）
- 沙箱里 `/run/user/<uid>` 只读 ⇒ wineserver 建不了 socket，报
  `wineserver: mkdir /run/user/1000/wine: Read-only file system`。
  `pi-sandbox` 里已用 `--tmpfs /run/user/<uid>` 顶掉（只影响沙箱）。
- 用法：`export WINEPREFIX=$PWD/.wp WINEDEBUG=-all; wine "$PWD/x.exe" args`
  **必须绝对路径**；相对路径在空 cwd 下会假报 `c0000135`（其实是找不到文件）。
- 本仓库 `scripts/tools/wine_run.sh <工作目录> '<命令>'` 把这套包好了。

## 3) 离线 oracle 与事件流瘦身
- PE 校验器可以逆成纯 Python 判定（本场 last_ignition：0.115 ms/候选，比跑 wine 快约 1000×，
  8 核 ≈69k/s）——**先逆出判据再扫，别拿 exe 当黑盒跑批量**。
- 面板卡顿根因：`/api/runs/<id>/events` 从 seq=1 全量重放，而事件流 99% 是 `reasoning.delta`。
  `scripts/tools/keep_light.py` 每 180s 压缩（删 reasoning + 黑板按文本去重）：
  本场 438MB → 34MB，重放 38KB/3s → 1.5MB/3s。
