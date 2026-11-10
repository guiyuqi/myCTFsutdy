# Ik_y7i9Zazs2MsSc · cwp（Web）

- 平台：1339 队解出（快照 2026-11-01 11:52）；我方状态：平台已解出（队友提交，我方无 submit-log 正确记录）
- flag：未在本地记录（我方**没有拿到 flag、没有解出过程、没有任何动态探测数据**，不编）
- 性质：**不是零留痕**——我方做过约 30% 的源码静态审计，但**从未跑出过一条结果**；解法与证据在队友彭艺棋处。

## 我方实际做了什么

已做（可核查，全在 `work/Ik_y7i9Zazs2MsSc_cwp/`）：

1. **下载并解包源码附件** → `work/Ik_y7i9Zazs2MsSc_cwp/src/blog-src/`（8 个 PHP，共 1269 行）。
2. **读了全部 8 个文件的入口与路由骨架**：`index.php` / `article.php`（`?id=` + 评论）/ `feed.php`（JSON API 路由，
   `?route=` + `$verb`，`route_bind`→`op_check`→`op_respond`）/ `manage.php`（先 `staff_session_valid()`）/ `bulk.php`（无鉴权）/ `engine.php` / `lib.php` / `storage.php`。
3. **写了两个 recon 探测脚本** `recon1.py` / `recon2.py`（`^/`、`/feed.php?route=…`、`/manage.php?action=accounts`、`/bulk.php`、`/api/articles`）。
4. **审计完成度约 30%**：`manage_dispatch()` 各 endpoint、`changeset_*`/`hooks_fire`/`ops_run_all` 回环链、`ROUTE_TABLE` 12 条路由的 perm 归属表，**均未还原**。

明确**没做**（比"做过什么"更重要）：

- **recon 脚本从未跑出过任何结果**：全工作区搜不到该题任何一次 HTTP 响应体，`evidence/` 该题 0 个文件。
- 唯一落盘的动态尝试是 **09:14:16 被门禁拒绝的那条**（`evidence/gate-log.jsonl` 的 `deny`/`tag:"sleep"` 行）：
  带 `sleep 1` 的 curl 循环被硬规则 §1 直接拒 ⇒ **连一个 HTTP 状态码都没拿到**。
- **未尝试任何利用、未起容器、未提交、未写过任何 flag**（我们确实不知道）。

审计初稿立起的四条可疑点，**全部未验证、不得当结论**：① `auth_salt()` 读不到 `/etc/site/auth_salt` 时返回空串 ⇒ HMAC 密钥退化可能离线伪造 cookie（`lib.php:362`）；② `PUBLISH_AS` 全局快路径可绕过鉴权（`lib.php:141`）；
③ `skin_editor_write()` 明文写 PHP 到 `/var/www/uploads/skins/`（`lib.php:477`，破一层鉴权即 webshell）；④ `bulk.php` 无文件内鉴权 + `ROUTE_TABLE` 是否有路由误挂 `perm_public`（未逐条核完）。
（`storage.php` 全程 PDO prepared + 关多语句 ⇒ SQLi 面很窄，这条已排除。）

**为什么停**：平台 10-31 09:13:59 记队友已提交 ⇒ 父代理按停手规则停掉当时审计的代理（`work/AGENT-STATE.md`、`work/TEAM-BOARD.md` 均记已停）。

## 交接口径

需**彭艺棋**提供 5 样（`team/cwp/README.md` §解法待补 那张表，全为 ⬜ 未拿到）：
1. **flag 原文**（或脱敏后半段 + 长度）——我方台账该题 0 条，`notes/FLAGS.md:22` 现记 ⬜；
2. **平台提交回包 `result:true`** 或平台截图（按"台账为骨"，这才是唯一凭证）；
3. **一句话解法链路**（入口 → 绕过 → 落点）——决定上节四条可疑点是**采纳**还是**作废**；
4. **截图**（成功的请求/响应、命令回显）→ 进 `evidence/`；
5. **解题脚本 / 手敲命令**（哪怕一串 curl）→ 收敛后放 `scripts/Ik_y7i9Zazs2MsSc-solve.py`。
拿到 1+2 后回填 `evidence/submit-log.jsonl` 一条（**注明"队友账号提交"，不是代理提交**），再改 `notes/FLAGS.md:22` ✅。
题面仅一句 **`flag在/root/flag.txt`**，镜像 `eci_2026qwb_cwp`。

## 证据

- `work/Ik_y7i9Zazs2MsSc_cwp/src/blog-src/{engine,lib,storage,article,index,feed,bulk,manage}.php`（8 个，1269 行）+ `recon1.py`、`recon2.py`（**写了但从未产出结果**）
- `evidence/gate-log.jsonl` 的 `tag:"sleep"` deny 行（09:14:16，唯一落盘的动态尝试，被拒）
- `team/cwp/README.md`（163 行叙事 + 5 行索要表）、`team/cwp/EVIDENCE.md`、`notes/FLAGS.md:22,46`；**`evidence/` 本题 0 个文件、`submit-log.jsonl` 0 条**
