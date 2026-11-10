## 工具清单（开工前先看这里）

### ★ 开工第一步：盘点（强制，30 秒）

**不要上来就手写解析器** —— 先确认有什么可用。实测中 agent 因跳过这一步，
把已有的 qemu / Ghidra / 15 项系统工具全部闲置，硬写 Python 绕路。

```bash
source ~/re-tools/fw-env.sh            # 一次激活全部工具

# ① 环境层自带命令
ls ~/re-tools/bin | head -40

# ② 系统工具（需 sudo 装，已就位）
command -v ffmpeg zbarimg tshark tcpdump upx pdftotext exiftool \
          sqlite3 nasm r2 radare2 binwalk foremost pngcheck steghide

# ③ Python 库
python3 -c "import capstone,unicorn,lief,angr,cv2,pyzbar,z3,pwn,scapy; print('libs ok')"

# ④ 移动题 / 语言运行时 / 字典（2026-10-13 扩充）
command -v jadx apktool adb frida go rustc cargo dotnet
ls $WORDLISTS/seclists/Discovery/Web-Content | head
```

**缺什么 → 记进 `needs-approval.md`**，并先想替代方案（见下方对照表）。

| 附件类型 | 首选路径 |
|---|---|
| 固件镜像 / rootfs | `unsquashfs` → `sasquatch`（非标准）→ `jefferson`（JFFS2）→ `ubireader_*`（UBI）；异构架构用 `qemu-*-static -L` |
| 原生二进制（ELF/PE/Mach-O） | `readelf`/`strings` → `fw-decompile`（Ghidra）或 `objdump -d -M intel`；动态行为用 `gdb`/`unicorn` |
| 加壳二进制 | 先试 `upx -d`；无 upx 或魔改时用 **Unicorn 跑壳 stub 定位 OEP** 自行脱壳 |
| Python 打包（PyInstaller） | 解析 CArchive（魔数 `MEI\x0c\x0b\x0a\x0b\x0e`）→ 裸 marshal 流 → `marshal.loads` + `dis` |
| 模型权重（.pth/.pt/safetensors） | **绝不直接 `torch.load`/`pickle.load`**；用 `pickletools.dis`/`genops` 静态分析 |
| 图片 / 音频 / 文档 | `file`/`exiftool`/`pngcheck`；隐写按「通道/位平面/元数据/尾部」四路并查 |
| **QR / 条码** | `cv2.QRCodeDetector`（零依赖、最快）或 `pyzbar`（zbar 引擎、抗畸变更强）；**两者均已可用，建议互为交叉验证**。一维条码另可用 `cv2.barcode.BarcodeDetector` 或 `zbarimg` |
| PDF | `pypdf`；**必须走 `/ToUnicode` CMap**，否则中文子集字体全乱码 |
| pcap | `scapy`（已装 2.8.0，pcap 读写/解析实测通过；**注意本沙箱无 RAW socket，只能离线解析，不能 live 抓包**）；缺则自写解析器（Ethernet→IPv4→TCP→四元组重组） |
| Web / 平台 | `curl -i` + 读前端 JS → `web-probe <url>`（抓 DOM/网络请求/cookie）；先看**响应头** |
| **APK / Android** | **先跑静态管线**：`python3 scripts/mobile-static.py app.apk --textures`（剥 APK → 按魔数递归解嵌套 zip/OBB → 解析 UE `.pak` → carve/decode ASTC → 出 PNG；**不需要 KVM/模拟器**）。再看 `jadx -d out app.apk`（→ Java 源码）→ `apktool d app.apk`（→ smali + Manifest）→ 改后 `apktool b` 重打包；动态：`adb` + `frida`（**本机无 `/dev/kvm`，Android 模拟器不可用**，见 needs-approval.md） |
| **Go / Rust / C# 程序** | Go：`go version` 后读 `pclntab`/符号；Rust：`cargo build` 复现 + panic 字符串；.NET：`dotnet --list-sdks`，用 `dnSpyEx`/`ilspycmd` 反编译（技能 `dotnet-reverse`） |
| **爆破 / 目录扫描** | 字典在 `$WORDLISTS/seclists/`（`Discovery/Web-Content/` 目录爆破、`Passwords/rockyou.txt` 口令）；**本沙箱无 RAW socket**，SYN 扫描需走 `docker --cap-add=NET_RAW --cap-add=NET_ADMIN --network host` |
| 交互式服务（nc） | 先**只读不写**连一次保存 banner，摸清协议再写脚本 |

**先判断有没有现成工具；没有就自己写，不要卡住也不要擅自安装。**
自写实现必须：① 留 `evidence/` 证据；② 与第二种方法交叉验证
（例：手写解码器 vs unicorn 跑真机码）；③ 若通用（PDF 提取器 / pcap 解析器 / QR 解码器），
放 `scripts/` 并注明可复用。

**把"希望人类安装的工具"汇总到 `needs-approval.md`，不要自己装。**

> ⚠️ `fw-decompile` / Ghidra 的输出落在**当前目录**的 `decompiled/`。
> 多代理共享工作区时，**先 `cd work/<题号>_*/` 再跑**，否则会互相覆盖。
> 允许把只读附件 `cp` 到自己的工作目录后再 `chmod +x`（不要在 `firmware/` 里改权限）。

---

