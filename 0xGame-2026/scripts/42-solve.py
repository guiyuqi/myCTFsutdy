#!/usr/bin/env python3
"""
Challenge 42 - Treasure_island (Misc, 812 pts) - 0xGame2026

Target : ssh player@nc1.ctfplus.cn -p 14887   (password 0xGame2026, container fixed pre-started)
Flag   : 0xGame{a5140046-2f49-4e34-8ca2-04f6c8663bbe}

Kill chain
----------
1. ~/treasure_island/clue.txt hints: "Count what the chart keeps, and the count will name the chest."
2. ~/treasure_island/real_map.txt holds 611 "GOLD <item>: <n> paces to the mark" lines
   -> the chest is box_611.
3. ~/treasure_island/chest/box_611.txt: the real chest is empty, gold moved to /tmp/flag,
   sealed by "a keeper's heartbeat".
4. /tmp/flag is ------- root:root.  Root-spawned infrastructure:
     /etc/.flagd/entrypoint.sh  (PID 1)
     /etc/.flagd/respawn.sh     (PID 15)  -> runuser -u player /opt/.whisper/heartbeat.sh
     /etc/.flagd/watchdog.sh    (PID 16)  -> re-locks /tmp/flag while the heart beats
   /etc/.flagd is root-only, but /opt/.whisper/heartbeat.sh is player-owned & player-writable,
   and /opt/.whisper is player-owned so the file can be unlinked.
5. heartbeat.sh says: "Silence the heartbeat AND erase this script, and the watcher will set
   the flag free."  Doing only one half is punished by respawn.sh ("no mercy to half-done work").
6. rm /opt/.whisper/heartbeat.sh  +  kill -9 the player heartbeat process
   -> watchdog.sh chmods /tmp/flag to -r--r--r-- and the flag is readable.

Usage: python3 scripts/42-solve.py
Requires paramiko (`source ~/re-tools/fw-env.sh` first if the import fails).
"""
import re
import sys
import time

import paramiko

HOST = "nc1.ctfplus.cn"
PORT = 14887
USER = "player"
PASS = "0xGame2026"

ISLAND = "/home/player/treasure_island"
MAP = f"{ISLAND}/real_map.txt"
CHEST_DIR = f"{ISLAND}/chest"
HEARTBEAT = "/opt/.whisper/heartbeat.sh"
FLAG = "/tmp/flag"


def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS, timeout=25)
    return c


def run(c, cmd, timeout=120):
    _, out, err = c.exec_command(cmd, timeout=timeout)
    o = out.read().decode(errors="replace")
    e = err.read().decode(errors="replace")
    return o, e


def main():
    c = connect()
    try:
        # --- step 1/2: read the chart, count what it keeps -------------------
        o, _ = run(c, f"cat {MAP}")
        lines = [l for l in o.splitlines() if l.strip()]
        n = len(lines)
        print(f"[*] real_map.txt has {n} entries -> chest box_{n:03d}")

        # --- step 3: read that chest ----------------------------------------
        o, _ = run(c, f"cat {CHEST_DIR}/box_{n:03d}.txt")
        print("[*] chest says:\n" + o.strip())

        # --- step 4/5/6: silence the heart and erase its mark ---------------
        print(f"[*] erasing {HEARTBEAT} and killing the heartbeat process")
        cmd = (
            f"rm -f {HEARTBEAT}; "
            "ps -eo pid,user,args | awk '/heartbeat[.]sh/ {print $1}' "
            "| while read p; do kill -9 \"$p\" 2>/dev/null; done; "
            "ps -eo pid,user,args | awk '/heartbeat[.]sh/ {print $1}' "
            "| while read p; do kill -9 \"$p\" 2>/dev/null; done; true"
        )
        run(c, cmd)

        # --- wait for the watchdog to set the gold free ---------------------
        flag = None
        for i in range(120):
            o, _ = run(c, f"cat {FLAG} 2>/dev/null")
            m = re.search(r"0xGame\{[^}]+\}", o)
            if m:
                flag = m.group(0)
                print(f"[+] flag readable after ~{i}s")
                break
            time.sleep(1)

        if not flag:
            print("[-] /tmp/flag never became readable", file=sys.stderr)
            return 1

        print(f"FLAG: {flag}")
        print("submit: python3 scripts/ctfplus.py submit 42 '%s'" % flag)
        return 0
    finally:
        c.close()


if __name__ == "__main__":
    sys.exit(main())
