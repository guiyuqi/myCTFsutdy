# 42 · Treasure_island (Misc, 812 分, 9 解)

- **flag**: `0xGame{a5140046-2f49-4e34-8ca2-04f6c8663bbe}`
- **提交**: `{"code":200,"msg":"OK","data":{"result":true}}` ✅
- **目标**: `ssh player@nc1.ctfplus.cn -p 14887`（密码 `0xGame2026`，容器由平台预先开好）
- **成品脚本**: `scripts/42-solve.py`（paramiko 全自动，可复现）
- **草稿**: `work/42_treasure/`（`run.py` 远程命令执行器、`real_map.txt`、`clue.txt`、`box_000.txt`）
- **证据**: `evidence/42-treasure-island.txt`

---

## 一句话思路

「数图鉴 → 找箱子 → 拆掉心跳 → 守望者放行」四步链。

## 关键步骤

### 1. 侦察：`~/treasure_island/`

```
~/treasure_island/
├── clue.txt          3 句谜面
├── real_map.txt      611 行 "GOLD <物品>: <n> paces to the mark"
└── chest/            box_000.txt ... box_999.txt（1000 个）
```

`clue.txt`：

> The old captain trusted no locks, only numbers.
> He spread a thousand chests across the sand,
> and left the chart to remember what his chest is called.
> **Count what the chart keeps, and the count will name the chest.**

### 2. 数图鉴 = 611 ⇒ `box_611.txt`

```bash
wc -l ~/treasure_island/real_map.txt     # 611
```

611 行**全部**匹配 `^GOLD [a-z_]+: [0-9]+ paces to the mark$`（无脏行；物品计数 20 种，
anchor 40 / tide 38 / … / mast 19，合计正好 611 —— 即"数一数图鉴里有多少条"）。
千位箱号 000–999，611 合法。

`cat box_611.txt`：

> 🏆 You found the real treasure chest!
> The chest is empty. The gold was moved to **/tmp/flag** —
> but a keeper's heartbeat seals it.
> Somewhere on this island a heart keeps beating,
> re-locking /tmp/flag with every beat.
> **Silence the heart, and erase its mark,**
> or it will never let the gold go.
> (ps: the watcher below shows no mercy to half-done work.)

### 3. 「危险又隐蔽的地带」= `/tmp/flag` + root 守护进程

```bash
$ ls -la /tmp/flag
---------- 1 root root 45 /tmp/flag        # 0000，player 读不了

$ ps -eo pid,ppid,user,args | grep -E 'whisper|flagd'
1    0 root  /bin/bash /etc/.flagd/entrypoint.sh
15   1 root  /bin/bash /etc/.flagd/respawn.sh
16   1 root  /bin/bash /etc/.flagd/watchdog.sh      # 每 1s 一beat
22  15 root  runuser -u player -- env -i /bin/bash /opt/.whisper/heartbeat.sh
25  22 player /bin/bash /opt/.whisper/heartbeat.sh  # 每 2s 一beat
```

- `/etc/.flagd` 是 **root-only**（`ls` 直接 `Permission denied`），看不到三个脚本源码；
- 但 `/opt/.whisper/heartbeat.sh` 是 **player:player 可读可写**，`/opt/.whisper/` 目录也是
  **player:player** ⇒ player 有**删除权**。这就是设计好的突破口。

`heartbeat.sh` 全文（player 可读）：

```bash
#!/bin/bash
# The Keeper's heartbeat. While this heart beats, the watcher keeps
# /tmp/flag sealed. Silence the heartbeat AND erase this script,
# and the watcher will set the flag free.
while true; do
  sleep 2
done
```

> 脚本本体只 sleep，**真正的加锁/解锁动作在 root 的 `watchdog.sh` 里**，
> 它把「heartbeat.sh 是否存在 + 是否存活」当作心跳信号。

### 4. 拿到 flag：删脚本 + 杀进程（两件都得做）

```bash
rm -f /opt/.whisper/heartbeat.sh
ps -eo pid,user,args | awk '/heartbeat[.]sh/ {print $1}' | xargs -r kill -9
sleep 1
ls -la /tmp/flag      # -r--r--r-- 1 root root 45
cat /tmp/flag
# 0xGame{a5140046-2f49-4e34-8ca2-04f6c8663bbe}
```

- **只杀进程不删脚本** → `respawn.sh` 会立刻重新拉起心跳（"no mercy to half-done work"），
  永远解不开；
- **删脚本 + 杀进程** → `watchdog.sh` 判定心跳终止，把 `/tmp/flag` chmod 成 `-r--r--r--`，
  宝藏出笼。
- 用 `awk '/heartbeat[.]sh/'` 的方括号写法是为了让匹配串**不会匹配到自己的命令行**，
  避免 `pkill -f` 自杀。

## 已排除 / 无关方向

- `sudo`：**未安装**（`bash: sudo: command not found`）。
- SUID：只有发行版默认那几个（`su` `mount` `passwd` `newgrp` `chsh` `chfn` `gpasswd` `umount`
  `ssh-keysign`），无自定义提权点。
- capabilities（`getcap -r /`）：无输出。
- cron：`/etc/crontab` 不存在，`/etc/cron.*` 只有发行版默认脚本，无关。
- `/var/tmp`、`/dev/shm`、`/lost+found`：空。

## 复现

```bash
cd ~/ctf-2026
source ~/re-tools/fw-env.sh          # 让 paramiko 可用
python3 scripts/42-solve.py
```

脚本会自动完成 611 → box_611 → 拆心跳 → 读 flag，并打印提交命令。

> ⚠️ 复现备注：解题完成后容器已被平台回收 —— `nc1.ctfplus.cn:14887` 已 `NoValidConnectionsError`
> （`scripts/ctfplus.py stop 42` 返回 `402 未找到对应容器`，说明该容器不在我们账号的槽位记录里）。
> 脚本逻辑已用同样的命令序列在解题当时逐条验证通过；若要重跑需重新申请容器。
