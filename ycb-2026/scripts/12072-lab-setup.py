#!/usr/bin/env python3
"""Build a persistent local lab rootfs for 12072 justledger.

Topology (same as remote):
  client --TCP--> listener --exec--> justledger (SQL front-end + ledgerprobe.so, fd3=broker)
                                   ledgerbroker --serve (fd0/1=justledger, fd3=vault)
                                   ledgervault  --serve

Only local-only patches (all same byte length, code offsets unchanged):
  * setgid()/setuid() calls in listener/ledgerbroker/ledgervault -> xor eax,eax;nop;nop;nop
    (in a user namespace uid 1000/1001/1002 are unmapped, so the real calls would abort)
  * listener TCP port 9999 -> PORT below
"""
import os, shutil, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "t")
ROOT = os.path.join(HERE, "root")
PORT = int(os.environ.get("LAB_PORT", "31337"))

# call site file offsets (offset == vaddr for .text in these binaries; verified below)
PATCHES = {
    "listener":     [0x13c7, 0x13d5],           # setgid, setuid
    "ledgerbroker": [0x1936, 0x1944],           # setgid, setuid
    "ledgervault":  [0x15f7, 0x1609],           # setgid, setuid
}
XOR_EAX = b"\x31\xc0\x90\x90\x90"

def build():
    if os.path.isdir(ROOT):
        shutil.rmtree(ROOT)
    for d in ("home/ctf", "tmp", "dev", "lib64", "lib/x86_64-linux-gnu", "etc"):
        os.makedirs(os.path.join(ROOT, d), exist_ok=True)

    # real files
    for f in ("justledger", "ledgerprobe.so", "ledgerbroker", "ledgervault",
              "listener", "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6",
              "libsqlite3.so.0"):
        dst = os.path.join(ROOT, "home/ctf", f)
        shutil.copyfile(os.path.join(SRC, f), dst)
        os.chmod(dst, 0o755)

    # loader locations so PT_INTERP works if a binary is exec'd directly
    for p in ("lib64/ld-linux-x86-64.so.2", "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"):
        shutil.copyfile(os.path.join(SRC, "ld-linux-x86-64.so.2"), os.path.join(ROOT, p))
        os.chmod(os.path.join(ROOT, p), 0o755)
    for lib in ("libc.so.6", "libm.so.6", "libsqlite3.so.0"):
        shutil.copyfile(os.path.join(SRC, lib), os.path.join(ROOT, "lib/x86_64-linux-gnu", lib))

    # /dev/null as a regular file (mknod is not permitted in a userns)
    with open(os.path.join(ROOT, "dev/null"), "wb"):
        pass
    os.chmod(os.path.join(ROOT, "dev/null"), 0o666)

    # dummy flag for local runs (NEVER used as the real answer)
    with open(os.path.join(ROOT, "home/ctf/flag"), "wb") as f:
        f.write(b"flag{local_lab_dummy_0123456789abcdef}\n")
    os.chmod(os.path.join(ROOT, "home/ctf/flag"), 0o444)

    # byte patches
    for name, offs in PATCHES.items():
        p = os.path.join(ROOT, "home/ctf", name)
        with open(p, "r+b") as f:
            for off in offs:
                f.seek(off)
                cur = f.read(5)
                assert cur[0] == 0xE8, (name, hex(off), cur.hex())
                f.seek(off)
                f.write(XOR_EAX)
        os.chmod(p, 0o755)

    # listener port patch: `mov QWORD PTR [rsp+0x10], 0xf270002` at 0x12f7
    # -> imm32 (file off 0x12fb..0x12fe) holds sa_family(2) + big-endian port
    p = os.path.join(ROOT, "home/ctf/listener")
    data = bytearray(open(p, "rb").read())
    assert data[0x12fc:0x1300] == b"\x02\x00\x27\x0f", data[0x12fc:0x1300].hex()
    data[0x12fc:0x1300] = struct.pack("<I", (int.from_bytes(struct.pack("<H", PORT), "big") << 16) | 2)
    # keep the qword (0x12f7) consistent: it zero-extends imm32, fine
    open(p, "wb").write(bytes(data))
    os.chmod(p, 0o755)
    print(f"[+] lab root built at {ROOT}  port={PORT}")
    print(f"    flag dummy at root/home/ctf/flag")

if __name__ == "__main__":
    build()
