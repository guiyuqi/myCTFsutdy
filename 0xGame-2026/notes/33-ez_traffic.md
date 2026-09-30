# 33 · ez_traffic

- **分类**: Misc / 流量分析（离线题，无容器）
- **分值**: 584 | 解出 23
- **flag**: `0xGame{tr@ff1c_ana1y5is_i5_fUn_h77p!}`
- **提交**: `code=200, msg=OK, result=true` ✅
- **附件**: `firmware/33_ez_traffic/ez_traffic.zip`
  → `ez_traffic/ez_traffic/traffic_http.pcap`（25914 B，pcap v2.4 LE，Ethernet，295 包，
  sha256 `e28cdb0a5318446b0b5d349787a88e239cc45d743935421cfabcacaffebd1eb8`）

## 环境备注

本机 **没有 `tshark` / `capinfos` / `tcpdump` / `scapy` / `binwalk`**
（`~/re-tools/bin` 只有 qemu/固件工具）。所以直接在 Python 里手写了一个极简
pcap 解析器（Ethernet → IPv4 → TCP → 按四元组重组流），没有装任何新工具。

## 解题过程

1. **重组 TCP 流**：295 包 → **15 条流**，其中 14 条是 `10.10.10.23:* → 10.10.10.80:80` 的
   HTTP，1 条是 `10.10.10.23:49166 → 10.10.10.80:9001` 的自定义协议。

2. **筛 HTTP 请求**（14 条，绝大多数是 decoy）：

   | 请求 | 响应大小 | 说明 |
   |---|---|---|
   | `/health.txt` | 3 | decoy |
   | `/` | 56 | decoy（Training Files） |
   | `/assets/site.css` | 61 | decoy |
   | `/assets/app.js` | 58 | decoy（`fetch('/api/status')`） |
   | `/assets/logo.png` | 16 | decoy（只有 PNG magic + IHDR） |
   | `/api/status` | 52 | decoy |
   | `/api/recent?limit=5` | 51 | decoy，列了 `readme.txt/report.txt/backup.log` |
   | `/reports/report.txt` | 37 | decoy |
   | `/logs/access.log` | 64 | decoy |
   | `/assets/readme.txt` | 48 | decoy（"intentionally uninteresting"） |
   | `/download/backup.log` | 36 | decoy |
   | `/favicon.ico` | 19 | decoy（"not really an icon"） |
   | **`/download/secret.zip`** | **172** | **← 真载荷** |
   | `/robots.txt` | 32 | decoy（`Disallow: /admin/`） |

3. **诱饵协议**：`10.10.10.80:9001` 上跑的是自制文本协议

   ```
   TELEMETRY/1.0 HELLO device=browser-sync
   request-id=7f3a2c91

   TELEMETRY/1.0 200 OK
   node=cache-03; status=nominal; next=60
   note=payload-is-not-http
   ```

   `note=payload-is-not-http` 是**误导**：真正的文件恰恰是普通 HTTP 下载的 zip。
   `request-id=7f3a2c91` 也不是密码（zip 根本没用密码）。

4. **取出 secret.zip**：`GET /download/secret.zip` 响应体（HTTP 头之后 172 字节）就是完整 zip。
   单条目 `secret.txt`，`flags=0x0000`（**未加密**），`method=8`（deflate），
   压缩 54 B → 原始 52 B，CRC32 `0x41375968`。

   ```bash
   unzip -o evidence/33-ez_traffic-secret.zip -d /tmp/x && cat /tmp/x/secret.txt
   # MHhHYW1le3RyQGZmMWNfYW5hMXk1aXNfaTVfZlVuX2g3N3AhfQ==
   ```

5. **base64 解一层**：

   ```
   MHhHYW1le3RyQGZmMWNfYW5hMXk1aXNfaTVfZlVuX2g3N3AhfQ==
     -> 0xGame{tr@ff1c_ana1y5is_i5_fUn_h77p!}
   ```

## 复现

```bash
cd ~/ctf-2026
unzip -o firmware/33_ez_traffic/ez_traffic.zip -d work/33_ez_traffic
python3 scripts/33-solve.py            # 自带 pcap 解析器，无需 tshark/scapy
# FLAG: 0xGame{tr@ff1c_ana1y5is_i5_fUn_h77p!}
```

`scripts/33-solve.py` 也可直接指定 pcap：`python3 scripts/33-solve.py <path.pcap>`。

## 关键命令

```bash
# 重组流 + 抽 HTTP body + 解 zip + base64（全部在成品脚本里）
python3 scripts/33-solve.py

# 手工等价步骤
unzip -o evidence/33-ez_traffic-secret.zip -d /tmp/x && base64 -d /tmp/x/secret.txt
```

## 证据

- `evidence/33-ez_traffic-solve.log` —— 成品脚本完整输出（含 14 条请求清单 + 诱饵流 + flag）
- `evidence/33-ez_traffic-secret.zip` —— 从 pcap 里抠出来的 secret.zip（172 B）
- `evidence/33-ez_traffic-secret.txt` —— 解压出的 base64 字符串
- `evidence/33-ez_traffic-hashes.txt` —— pcap / zip 的 sha256
- 草稿：`work/33_ez_traffic/parse.py`（流重组的探路版）、`work/33_ez_traffic/unz/`

## 踩坑记录

- 一开始把 deflate 数据切错偏移（`local header` 30 B **+ 文件名 10 B** 才是数据起点，
  见 `body[40:94]`），误以为 zip 是加密的。
- `Content-Disposition: attachment` 这个头出现在**所有**响应上（包括 decoy），不是敏感标记。
- 别被 `note=payload-is-not-http` 骗去挖 9001 端口的"非 HTTP 载荷"——那条流只有一次
  问候/应答，没有任何后续数据。
