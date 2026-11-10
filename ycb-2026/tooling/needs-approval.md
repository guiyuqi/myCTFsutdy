# 需要人类安装 / 授权的工具

> 生成：2026-10-13 赛前自检（`bash scripts/selfcheck.sh --full`）
> 规则：**agent 不自行安装**。缺什么记在这里，并先给出现状可用的替代方案。
> 详细自检结果见 `~/ctf/ENV-SELFCHECK.md`（跨比赛环境基线，放在工作区之外）。

## 结论：无阻塞项

核心链路（反编译 / 固件解包 / 模拟执行 / Web 侦察 / 隐写取证 / Python 逆向库）
**全部端到端实测通过**，自检 **71 项 0 缺失**（`bash scripts/selfcheck.sh --full`）。下面都是"按题型才需要"的补充件，
**等真出现对应题型再决定装不装**，不必赛前一股脑装。

## 可选补充（按优先级）

| 优先级 | 缺项 | 影响的题型 | 现状可用替代 | 安装方式（需你确认） |
|---|---|---|---|---|
| ~~高~~ | ~~i386 运行时~~ | ~~32 位 PWN~~ | ✅ **2026-10-18 已装**（`~/re-tools/i386`，GLIBC 2.43；`i386-run ./bin` 直接跑） | — |
| ~~高~~ | ~~`bkcrack`~~ | ~~ZIP 真加密~~ | ✅ **2026-10-18 已装**（1.8.1，官方预编译） | — |
| ~~高~~ | ~~`sshpass`~~ | ~~ssh 类题~~ | ✅ **2026-10-18 已装**（1.09）。⚠️ `ssh` 会报 `/etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf` 权限警告（系统问题，不影响功能） | — |
| ~~中~~ | ~~`scapy`~~ | ~~pcap / 流量分析~~ | ✅ **2026-10-13 已补装 2.8.0**（`~/re-tools/pylibs`，功能级验证通过） | — |
| ~~中~~ | ~~`jadx` / `apktool` / `adb` / `frida`~~ | ~~APK 逆向~~ | ✅ **2026-10-13 已装**（`~/re-tools/android/`）；jadx/apktool 已用真实 crackme APK 端到端验证（含重打包） | — |
| ~~中~~ | ~~字典~~ | ~~web 爆破 / 口令~~ | ✅ **2026-10-13 已装** SecLists 子集 1.4GB（`~/re-tools/wordlists/seclists/`，含预解压 rockyou.txt） | — |
| ~~低~~ | ~~`ropper`~~ | ~~pwn gadget~~ | ✅ 不再需要：`ROPgadget`（ropgadget 7.7，在 `~/re-tools/pylibs/bin/`）与 pwntools 的 `checksec`/`asm`/`disasm`/`elfpatch` 等 **约 30 个 wrapper 已生成到 `~/re-tools/bin/`**；两者都在 PATH 上（`source fw-env.sh` 后直接可用） | — |
| 低 | `socat` | 交互式服务脚本化 | `nc` 已在；`pwntools.remote()` 更适合写脚本 | `sudo apt install socat` |
| 低 | `unblob` | 现代固件解包（binwalk 的补充） | `binwalk 2.4.3` + `unsquashfs` / `sasquatch` 已覆盖常见格式 | `pip install unblob` |
| 不需要 | `ida` | — | 走 Ghidra 12.1.3（`fw-decompile`）或 `rea` 3.1.0 | — |
| 不需要 | `rizin` | — | `radare2 6.0.7` 已覆盖 | — |

### 2026-10-18 已补齐（第二批复核出的 6 项）

| 工具 | 状态 | 备注 |
|---|---|---|
| `fcrackzip` | ✅ 1.0 | ZipCrypto 字典/暴力；实测在加密 zip 上命中 |
| `john` (**jumbo**) | ✅ 1.9.0-Jumbo-1（**303 格式**） | 实测破解 raw-md5 与 `$pkzip$`；Ubuntu 自带的 classic 版降级为 `john-classic` |
| `zip2john` | ✅ | 实测：造 ZipCrypto zip → 提 hash → john 解出密码 → pyzipper 解包拿到内容 |
| `expect` | ✅ 5.45.4 | 实测 `expect -c 'puts ...'` 正常 |
| `pyzipper` | ✅ 0.4.0 | **AES-ZIP 读写**（实测往返） |
| `hashcat` | ⚠️ **已装 6.2.6，但 0 个 OpenCL 设备** | 本机无 GPU 且未装 pocl → **当前不能实际破解**；CPU 破解用 john。要启用需补 pocl（约 +150MB，clang/LLVM 依赖链） |

> 三项 john 相关（john / zip2john / 12 个 `*2john`）来自 Kali 包：该包把
> `/etc/john/john.conf` 与 `/usr/share/john/` **硬编码进二进制**，已用同长度字符串替换改成相对路径
> （`./jc`、`./`），所以 wrapper 必须 `cd` 到数据目录，并先把路径参数绝对化——
> 这两点已写进 `~/re-tools/bin/john` 的注释，改 wrapper 前先看。

### 需要设备/外部条件（不是安装问题）

| 项 | 说明 |
|---|---|
| `frida-server` | 需按目标设备架构（arm64/arm/x86_64）单独推入设备；本机只有 host 侧 `frida` |
| `adb` 实际连设备 | 需要真机（USB 调试）或模拟器；本机无 Android SDK 模拟器镜像 |
| RAW socket | 沙箱内不可用（`bwrap --cap-drop`）；**替代方案已实测**：`docker run --cap-add=NET_RAW --cap-add=NET_ADMIN --network host`（见 `~/ctf/ENV-SELFCHECK.md` §7.4） |

## 沙箱外事项（agent 改不了，需在 Windows / systemd 侧处理）

| 项 | 状态 |
|---|---|
| systemd OOM 防护 `OOMPolicy=continue` + `MemoryMax=12G` + `MemoryHigh=8G` + `MemorySwapMax=2G` | ✅ **已生效**（drop-in `/etc/systemd/system/dsh-web.service.d/oom.conf`，2026-10-04）；本次实测 cgroup `memory.max=12GiB` |
| WSL 内存 / swap 上限 | ✅ `.wslconfig`：`memory=10GB` / `swap=8GB` / `processors=8` |
| `dsh-web` 健康检查 timer（30s，自动重启） | ✅ 运行中；最近三次自动重启在 10-05 / 10-08，之后无异常 |
| 系统工具（`ffmpeg`/`tshark`/`upx`/`radare2`/`binwalk` 等 15 项） | ✅ 已装齐（沙箱内 `sudo` 被 `no_new_privs` 挡住，装不了，故需在沙箱外装） |

## 已知遗留（与 CTF 无关，仅记录）

- ~~14 个 `strix-sandbox` 容器处于 `Exited`~~：**2026-10-13 已清理**（容器占用 2.97GB→195MB，回收 ~2.8GB）。
  `snowluma` 容器常驻（QQ bot 用，**不要删**）；`ocrbox` / `bold_rhodes`（非 strix 的旧残留）保留未动，需要时自行处理。
- `pwntools` 每次 import 会联网查更新（~0.4s + stderr 噪音）。消除办法：新建 `~/.pwn.conf` 写入
  ```ini
  [update]
  interval=never
  ```
- `fl-studio` MCP 本会话未暴露工具（依赖 Windows 侧 bridge 常驻），不影响比赛。

---

## 2026-10-23 羊城杯赛前复核（父代理）

环境层面**无新增阻塞**：`bash scripts/selfcheck.sh --full` → **71 项通过 / 0 缺失**（`evidence/selfcheck.log`）。
本次针对性复核了"开赛才给密码的 misc 附件"这条链路，结论与依据如下。

| 项 | 状态 | 依据 | 结论 |
|---|---|---|---|
| `7z`（压缩包+密码） | ✅ **7-Zip 26.00**（非旧 p7zip） | `7z i` 列出 `Rar` / `Rar5` 解码器 | 7z/zip/rar 均可解；**不需要装 `unrar`** |
| `bsdtar` / libarchive | ✅ 3.8.5（含 rar 读） | `bsdtar --version` | RAR 备选通道 |
| `unrar` / `unar` / `rar` | ❌ 缺 | `command -v` | **不申请安装**：上面两条已覆盖；仅"加密 RAR 头"未实测（无样本），真遇到再评估 |
| `pyzipper`（AES-ZIP） | ✅ 0.4.0 | `source ~/re-tools/fw-env.sh` 后 `import pyzipper` | 作为 7z 失败时的 AES-ZIP 兜底 |
| `bkcrack` / `fcrackzip` / `john`+`zip2john` | ✅ | `source` 后 `command -v` 全部命中 | ZipCrypto 已知明文/字典路线可用 |
| `rarfile`（python） | ❌ 缺 | `import rarfile` | 不申请：用 `bsdtar`/`7z` 子进程即可 |
| `ropper` | ⚠️ 缺 | selfcheck §4 可选包 | 已有 ROPgadget（pwntools 系），不申请 |
| `hashcat` OpenCL | ⚠️ 0 设备 | 旧记录 | CPU 破解走 `john`，不申请 pocl |

### 需要人类（不是安装，是外部输入）

1. **羊城杯平台域名**——目前不存在 `work/platform-<域名>.md`，`CTFD_BASE` 未设。
2. **一次平台登录**（session cookie / token 只能由人类提供）：
   - 交互式：`python3 scripts/ctfd.py login --user <用户名>`（密码走 stdin，不落工作区）；
   - 或直接把 `CTFD_TOKEN=` / `CTFD_COOKIE=` 写进 `~/.config/ctf/creds.env`（工作区之外，0600）。
3. **misc 附件的开赛密码**——附件到位后 `python3 scripts/attach-triage.py` 先判格式，
   拿到密码再 `--password '<密码>'` 一键解包（实测见 `evidence/attach-triage-smoke.log`）。

---

## 2026-10-23 羊城杯附件落地后（父代理）

预发附件里有 **64 GB 的取证镜像 `YCB_linxiao.E01`（EWF/EnCase 格式）**，本机**没有** libewf/pyewf：

```
ewfinfo / ewfexport / ewfmount → MISSING
python3 -c "import pyewf" → ModuleNotFoundError
```

没有它这张 E01 **完全打不开**（sleuthkit 的 mmls/fls 只吃 raw，不吃 E01），对应的 misc 取证题会直接卡死。
**两个方案，请你选一个（我不自行安装）**：

| 方案 | 命令 | 优点 | 缺点 |
|---|---|---|---|
| **A（推荐）纯 Python，装进工作区** | `pip install --target ~/ctf-2026/work/pylibs work/pkgs/dissect_*.whl`<br>（三个 wheel 我已下好在 `work/pkgs/`：`dissect.evidence 3.13` + `dissect.cstruct 4.7` + `dissect.util 3.24`） | 不需要 root；不进系统；只影响 `PYTHONPATH`；可随时删 | 解析速度比 libewf 慢（64 GB 可能要十几分钟） |
| B 系统级 | `sudo apt install ewf-tools`（仓库版本 20140816） | `ewfexport`/`ewfmount` 快、可只读挂载 | 需要你输 sudo；改系统 |

选 A 时我不会自己跑 pip，**你批准后我再执行**（或你直接跑上面那条命令）。

> 附：`ycb-BabyMenu` 的 vmdk 已用系统自带 `qemu-img` 转成 raw（`work/babymenu/babymenu.raw`，64 GiB），
> sleuthkit 可直接读——**这部分不缺工具，不需要安装**。

---

## 12070 · BabyMenu（Windows 驱动提权，2026-10-24）

本题需要**两个我这边不具备的能力**，请人类决定（我不自行安装）：

1. **Windows x64 编译工具链**（本机无 `x86_64-w64-mingw32-gcc`、无 MSVC/`clang-cl`+MSVC 头，
   所以 `work/12070_babymenu/exploit/babymenu_lpe.c` **无法在此编译**）。
   - 方案 A（推荐，轻）：`sudo apt install mingw-w64`（约 200 MB），之后
     `x86_64-w64-mingw32-gcc -O2 -o babymenu_lpe.exe babymenu_lpe.c`；
   - 方案 B：在有 VS2022 Build Tools 的 Windows 机器上编译（题目本来就要求在 Windows 里跑 EXP）。
   - 注：**PoC 不需要编译**——`poc/BabyMenuProbe.ps1` 用 PowerShell + 内联 C#（Add-Type），
     在题目 VM 里以 `ctfer` 直接可跑。

2. **运行题目 VM 的能力**（可选）：本机 `/dev/kvm` 不存在，64 GiB 的 Win11 镜像用 TCG 跑
   不现实；且驱动利用的正确性验证需要**两机内核调试（WinDbg + 串口/网络）**。
   建议由人类在 VMware 里跑（题目 README 本来就是这样设计的），我这边只做离线分析与
   EXP/PoC 产出。

---

## 2026-10-24 赛后：为下一场准备的"人类侧"清单

> 本次结论：**不追求 AK，摸清环境与缺陷**。VM 类题全部放掉（宿主 9.7 GB 跑不动 16 GB 的 Win11 VM）。
> 详细复盘见 `notes/ENV-DEFECTS.md`。

### 必须准备（下次开赛前）

| # | 项目 | 现状 | 需要人类做 |
|---|---|---|---|
| 1 | **≥32 GB 内存的 Windows 机器**（或 16 GB + 足够 pagefile） | 本机 9.7 GB，VM 起不来 | 准备机器 + **赛前把官方 VM 装好并开机验证**（`ctfer/123` 能登录、`sc query ycb` 存在） |
| 2 | **Windows 编译环境**（VS2022 或 mingw-w64） | Linux 侧没有，驱动 EXP 骨架编不了 | 在 Windows 侧装好 |
| 3 | **WinDbg Preview**（内核调试） | 无 | 装好 + 验证 `bcdedit /debug on` + `dbgsettings local` 能连 |
| 4 | **无线 adb**（Android 11+ 配对码） | USB 在 WSL 看不到；本次靠 Windows adb + interop 打通 | 手机常备"无线调试"配对流程；或保持 Windows adb server 方案 |
| 5 | **VM 文件传输通道** | 本次用 HTTP（`:8000`/`:8001`）+ `curl.exe` 可行 | 首选 VMware 共享文件夹（需 Tools）；**禁止在资源管理器里"剪切"WSL 里的 VM 目录**（本次因此丢过 vmdk） |

### 已就绪、下次可直接用的资产（无需再准备）

- `scripts/attach-triage.py`（密码闸门附件分诊）、`scripts/batch-triage.py` / `batch-diff.py`（放题分诊）
- `scripts/ycb.py`（DASCTF 平台客户端：creds/list/detail/download/submit/env/notice/watch/log）
- `scripts/12084b-pak-extract.py`（UE5 pak v11 通用解包器）
- `scripts/12084-oodle-ucas-dump.py`（零依赖 Oodle IoStore 解压器）
- `work/12070_babymenu/win/`（BabyMenuKit.ps1 + WINDBG-CARDS.md + LPE 骨架）
- `scripts/12068-solve.py`、`scripts/12082-solve.py`、`scripts/12083-solve.py`、`scripts/12072-solve.py`、`scripts/12078-solve.py`、`scripts/12067-solve.py`、`scripts/12063-solve.py`

---

## 2026-10-24 羊城杯赛后实测缺口（覆盖上面"无阻塞项"的赛前口径）

> 本次逐项实测（`source ~/re-tools/fw-env.sh` 后 `import` / `command -v`）。赛前那句"无阻塞项"只对**当时的题库类型**成立。

### 真缺（按本场损失排序）

| 缺项 | 本场损失 | 安装/准备方式 |
|---|---|---|
| **Android x86_64 模拟器**（只有 adb/jadx/apktool/frida） | 12084 动态侧全废（真机 content 未挂载；该题 120 队解出） | `sdkmanager "emulator" "system-images;android-30;google_apis;x86_64"` + KVM |
| **Windows 模板 VM（≥32 GB 宿主）** | 12070/12068 无法本地打通（重建 vmx 两次、误删 28 GB vmdk 一次） | 宿主扩容；预装 VS2022+WinDbg 的差分盘 |
| **`astcenc`**（或保留 venv 里的 `texture2ddecoder`） | 12084 前 3 轮无法看图 | `apt install astcenc` 或保留 `work/12084e/venv` |
| **`playwright` python 模块** | `web-probe`/`pwpython` 一跑就 `ModuleNotFoundError`（chromium 本体其实可用，需可写 `HOME`） | `pip install playwright`（项目级 venv） |
| **`pandoc` 或 LibreOffice** | WP 从零写渲染器 ~40 分钟（还踩 CJK 字体坑） | `apt install pandoc texlive-xetex` 或保留 `scripts/md2pdf.py` |
| `tesseract` | 需要 OCR 的题只能自写聚类 | `apt install tesseract-ocr tesseract-ocr-chi-sim` |

### 以为缺、其实有（别再重复造轮子）

`z3 / angr / cv2 / pyzbar / pyzipper / pwn / scapy / unicorn / lief / socat / 7z / adb / frida / chromium`
—— 全部在 `~/re-tools`，**前提是先 `source ~/re-tools/fw-env.sh`**；本场 12080 手写 20 行 AES 校验而 `pyzipper` 就在环境里。

### 自检要升级

现在 `selfcheck.sh` 只测"命令存在"，应增加三项：
1. **库能 import**（`python3 -c "import z3, angr, pwn, scapy, pyzipper"`）；
2. **浏览器能起**（`HOME=<可写目录> chromium --headless --dump-dom data:text/html,ok`）；
3. **解码器能出图**（ASTC/Oodle 各跑一张样图，断言输出尺寸/长度）。

---

## 2026-10-25 更新（内化落地后复核）

### 已解决

| 项 | 处理 | 验证 |
|---|---|---|
| `pyzipper` | **本来就有**（`~/re-tools/pylibs`）；此前"缺失"是在**未 source fw-env** 的环境里测的 | `import pyzipper` → 0.4.0 |
| ASTC 解码 | 装 `texture2ddecoder`（纯 Python，免 sudo） | `import texture2ddecoder`，`decode_astc` 可用 |
| E01 取证 | `libewf-python` → `~/re-tools/pylibs`（提供 `pyewf`） | `import pyewf` OK |
| 现代固件解包 | `unblob 26.6.4` → `~/re-tools/tools/unblob-venv`，软链 `~/re-tools/bin/unblob` | `unblob --version` → 26.6.4 |
| 自检升级 | `selfcheck.sh --capabilities`：16 项能力断言（真跑一次） | **80 项通过 / 0 缺失** |

### 仍待人类

| 项 | 为什么 agent 装不了 | 命令 |
|---|---|---|
| `tesseract` | 需要 sudo（本会话无免密 sudo） | `sudo apt install tesseract-ocr tesseract-ocr-chi-sim` |
| `astcenc` 二进制 | GitHub Release CDN 在本机反复断流（SSL EOF / 超时）；`texture2ddecoder` 已覆盖同一能力 | `sudo apt install astcenc`（源里有 5.3.0+ds-5） |
| Android 模拟器 | **无 `/dev/kvm`**（WSL2 未开嵌套虚拟化），装了也只能 TCG 软件模拟 | 见下 |

### Android 模拟器：先开嵌套虚拟化

现状：`/dev/kvm` 不存在、`/proc/cpuinfo` 无 `vmx/svm` 标志；CPU 是 AMD Ryzen 9 8940HX（硬件支持 AMD-V）。

在 Windows 侧 `%UserProfile%\.wslconfig` 的 `[wsl2]` 段加一行：

```ini
nestedVirtualization=true
```

然后 `wsl --shutdown` 重启（**会中断当前 DSH 会话，请在比赛间隙做**）。之后 `ls /dev/kvm` 应存在，再：

```bash
sdkmanager "emulator" "system-images;android-30;google_apis;x86_64"
```

> 备选：若只是要看 12084 的纹理，`texture2ddecoder` + OBB 解包可能就够了，不必等模拟器。
