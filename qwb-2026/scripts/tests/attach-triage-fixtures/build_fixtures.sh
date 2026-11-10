#!/usr/bin/env bash
# 重建 attach-triage.py 的自测样本（全部为假内容，不含真 flag）
set -u
cd "$(dirname "$0")"
rm -f *.7z *.zip *.png inner.txt s.txt sample_elf
printf 'SELFTEST-ONLY-not-a-flag\n' > s.txt
printf 'SELFTEST-NESTED-not-a-flag\n' > inner.txt
7z a -pPass123 -mhe=on enc_header.7z s.txt -bso0 -bsp0      # 头加密
7z a -pPass123 enc_names.7z s.txt -bso0 -bsp0               # 仅内容加密
zip -q -P Pass123 enc_zipcrypto.zip s.txt                   # ZipCrypto
7z a -pInner9 inner.7z inner.txt -bso0 -bsp0                # 另一密码（测 FAIL 路径）
7z a -pPass123 nest_inner.7z s.txt -bso0 -bsp0
python3 -c "import zipfile;z=zipfile.ZipFile('nest_outer.zip','w');z.write('nest_inner.7z');z.close()"
python3 - <<'PY'
import struct, zlib
def chunk(t,d): return struct.pack('>I',len(d))+t+d+struct.pack('>I',zlib.crc32(t+d)&0xffffffff)
png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',1,1,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b'\x00\xff\x00\x00'))+chunk(b'IEND',b'')
open('pic.png','wb').write(png)
import zipfile
z=zipfile.ZipFile('outer.zip','w'); z.write('inner.7z'); z.write('pic.png'); z.close()
PY
cp /usr/bin/true sample_elf
echo "fixtures rebuilt"
