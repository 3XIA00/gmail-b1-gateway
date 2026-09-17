# Gmail Gateway 实现计划草案 v0.2（repo-independent 部分）

> **v0.2（2026-09-01）**：依 测试姬 方向 review 增补 **§8**（egress 正向可观测 / health 可导出 / `provider_result_ref` 字段集 / E2b 口径）。crypto 族与库选型（google-auth↔authlib）待 Chris/impl 复审。v0.1 正文保留。

对齐规范：**DESIGN.md v0.1，sha256 `45925f6d…731253`（32667B）**。
本草案只覆盖 JARVIS 明确放行、且**不依赖目标仓库选择**的三块：
① OAuth loopback+PKCE 库选型 ② token 加密落盘方案 ③ send 状态机。
外加：与已验收 M2 canonicalizer 的接线、动作集投影层、测试策略。

**§10 待仓库定案后再钉（本草案不臆造）**：前端/Agent↔Gateway 的
transport/端口发现/认证 wire format、逻辑接口最终 endpoint/tool 名、
OS 凭据库跨平台最终实现、Agent 授权 UI 字段、`outcome_unknown` 人工
裁定 UI 与保留期、最终目录结构。下面的接口都按“可被这些决定填充而
不需重构”来设计。

工作语言：**Python**（与已验收 canonicalizer 一致）。若 repo/host
约束要求换语言，契约（字节级 JCS、状态语义、可观测面）语言无关，可移植。

---

## 0. 组件边界（本 owner 的范围拆成模块）

延续 M2 的做法，每块是可独立测试的模块，互不越界：

| 模块 | 职责 | 对应 DESIGN |
|---|---|---|
| `canonicalizer/`（**已交付/验收**） | JCS + payload_digest + v1 附件门 | §5.1/§8.5 |
| `oauth/`（本草案①） | loopback listener + PKCE + code 交换 + refresh single-flight | §2/§4 |
| `keystore/`（本草案②） | 信封加密 token 落盘 + OS 凭据库 DEK + fail-closed | §3门6/§7 |
| `sendfsm/`（本草案③） | 发送状态机 + 幂等账本 + 重校 | §6 |
| `actionset/`（横切） | 向 Agent 投影的闭集动作 + 确认/自动开关投影 | §3门4/§3门7/§5 |
| `store/` | proposal/connection/audit 持久化（schema=§7） | §7 |
| `transport/`（**§10 挂起**） | wire format / endpoint 名 | §10 |

---

## 1. ① OAuth loopback + PKCE

### 选型结论：**复用 token 管线，自控安全关键路径**

- **复用** `google-auth`（token 交换/刷新、`Credentials` 对象、过期判定）——不自己手写 OAuth token 解析与刷新。
- **不使用** `google-auth-oauthlib` 的 turnkey `run_local_server()`——它对 §2 硬约束（**只接受本轮 loopback URI、精确端口、state+PKCE 本地生成/校验/销毁、attempt 单次消费、fail closed**）暴露的控制不够，且会隐藏 listener 生命周期。
- **自建**极小 loopback listener + 自己的 state/PKCE/attempt 校验，拿到 code 后交给 `google-auth` 的 `fetch_token(code_verifier=…)`。

> 载重决策：DESIGN §2 的 fail-closed 语义是发布硬门（门2/门3），必须显式可测；turnkey helper 做不到精确控制。但 token 交换/刷新是成熟且易错的密码学/协议代码，值得复用。备选：`authlib`（PKCE+loopback 控制更显式），若 `google-auth` 的 PKCE/loopback 控制过于死板则切换——契约不变。

### 关键实现点（映射硬约束）

- **PKCE**：`S256`。verifier = `secrets.token_urlsafe(64)`；challenge = `b64url(sha256(verifier))` 去 padding。
- **loopback**：`bind(("127.0.0.1", 0))` 取 OS 分配的临时端口，读回真实端口再拼 `redirect_uri`。**只**绑数值 `127.0.0.1`（不走 `localhost` DNS，避免 DNS-rebinding 歧义；DESIGN 允许二者，我取更严的）。单次请求 handler：
  - 校验 path、`state` 逐字相等、attempt 未过期未消费；
  - 任一不符 → **fail closed**（不发 token、不重试、返回错误页、销毁 listener）;
  - 成功后立即销毁 `state`/verifier/listener，attempt 标记已消费。
- **attempt_id**：非秘密、短 TTL、单次消费（§4.1）。
- **禁止项（门3/§2）**：不配置任何 Puffo 域名 callback；code/token 交换全程 Gateway 直连 Google，云端零触点。
- **refresh**（§4.2）：单连接 single-flight 串行；`last_verified_at` 只由**真正行使 grant 成功的调用**推进，探测不推进；授权类失败统一报“授权已失效，请重新授权”，不单凭时间戳/`invalid_grant` 猜因（§9 归因纪律）。
- **断开**（§4.2）：先请求 Google 撤销，按返回语义记录，再删本地 token；删本地**不冒充**远端撤销成功；清理幂等。
- **健康四态**（§4.2）：`active / stale_unverified / reauthorization_required / disconnected`——投影层不得互相塌缩。

### 可观测面（对 E0/E1）
- E0：Desktop client 创建页有无 redirect URI 栏——控制台观察项，非代码（已由 Jeremy 记：无该栏）。
- E1：连接结果**不含 token**；可核“只连 Google + loopback、无云端 callback”；暴露签发时 publishing status + 端口。

---

## 2. ② token 加密落盘

### 方案：信封加密（DEK 在 OS 凭据库，密文在盘）

满足 §7“**密钥不能与密文放在同一无保护位置**”+ §3门6“密钥缺失 fail closed，禁止退回明文/仅告警继续”：

- **DEK** 存 OS 凭据库（`keyring`：Windows Credential Manager / macOS Keychain / Linux Secret Service）。
- **密文**（refresh token + `issued_at`/scope/publishing_status 快照）写盘，用 **ChaCha20-Poly1305** AEAD 加密（与 Puffo 附件加密同族、不依赖 AES-NI）。每次写用随机 96-bit nonce；AAD = 记录类型+版本，防跨上下文重用。
- **access token**：内存/受控本机存储，不必持久化（§4.1 步7）。
- **fail closed**：凭据库取不到/建不了 DEK → Gateway 拒绝运行，**无明文回退、无告警续跑**。

> **载重决策（吃过的亏，硬性要求）**：keystore 的一切密钥/密文文件 I/O **必须二进制模式**（`open(..., "rb"/"wb")`、`os.O_BINARY`），**绝不文本模式**。历史上 keystore 文本模式在 Windows 触发 `0x1A` 当 EOF 截断 DEK、`0x0A`→`0x0D0A` 撑大文件，造成静默解密失败。写盘不做任何换行转码；hash/长度自校。

- **§10 挂起**：跨平台凭据库“最终实现”待定 → `keystore/` 只定 `KeyStore` 接口 + ChaCha20 信封方案，backend 可插拔（`keyring` 为默认 backend），§10 定案后替换 backend 不动上层。
- **同 UID 诚实边界**（§2.6）：共享 OS 用户下文件权限不构成硬隔离；凭据库+加密只缩小泄漏面。v1 **如实记录**此限，不声称已解决；独立 OS 身份/服务化属后续加固。

---

## 3. ③ send 状态机

### 状态与转移（逐字对齐 §6）

```
prepared -> pending_approval -> approved -> dispatched -> succeeded
             |        |             |            |-> failed
             |        |             |            `-> outcome_unknown
             |        |             `-> revalidation_failed
             |        `-> expired
             `-> rejected
```

显式 FSM，非法转移拒绝并记审计。规则：

1. proposal 落盘将执行的**确切规范化 payload + digest（来自 M2 canonicalizer）+ 连接/策略快照 + idempotency_key**（§6.1）。
2. 调 Gmail **前**持久化 `dispatched` 并占住幂等键（§6.2）。
3. Gmail 明确成功 → `succeeded`，存 message/thread id 的**哈希/最小引用**（§6.3）。
4. Gmail 明确拒绝 → `failed`（§6.4）。
5. 超时/连接中断/崩溃/无法判断 → `outcome_unknown`：**幂等键继续占住、状态不可退回可执行、禁止自动重发**（§6.5）。
6. 执行前重校（§5.1）：连接有效、proposal 未过期、策略仍允许、**digest 未变**、幂等键未被其他 payload 占用 → 否则 `revalidation_failed`。
7. 同幂等键+同 digest → 返回原 proposal/result；同幂等键+不同 digest → **冲突失败**（§6 末/§8.5）。
8. **读回/搜索不到只是观察证据**，不证明“没发”、不触发自动重试（§6.7）。自定义 `Message-ID` 未经 E3/E4 实测不当 Google 去重保证（§6.6）。
9. 自动发送从完成同等重校的 `approved` 语义点进入，**不伪造人类批准记录**（§6/§5.2）。

- **崩溃恢复**：状态持久化保证 `dispatched` 后崩溃/超时恢复仍停在 `outcome_unknown`、不自动重发（§8.5 验收项）。

---

## 4. 横切：动作集投影（§3门4/门7）——本 owner 范围，独立模块

- **闭集 + 参数级封闭（门4）**：Agent 只见 `PrepareEmail`（确认模式下**看不到直接发送**）。收件人/主题/正文/预留附件字段只进固定 text/plain MIME 模板固定槽位；**无 raw MIME / 任意 header / 任意 URL / pass-through**。M2 `payload.py` 已 reject-unknown + 无 pass-through 槽，是这层的 schema 基座。
- **确认/自动开关投影（门7）**：开关只在**下一次建立动作集**时改变暴露哪套闭集（当前 turn 不增权）；开关只有用户可改，**Agent 无任何可达写路径**。这是 tool-surface 层，与 canonicalizer 纯函数解耦（M2 README 已声明）。
- v1.1 附件/HTML：只预留 DESIGN 已定的槽位，**不提前设计**（§5.3）。

---

## 5. 测试策略（按模块 + 对齐 E1–E7 可观测契约）

沿用 M2 风格：`hypothesis` 属性测试 + 边界正/反例 + 理论容差。每模块把 测试姬 `c2ede3d2` 列的可观测点作为**接口验收目标**建进去（别建出来测不了）：

- `oauth/`：PKCE challenge 正确性；loopback **精确 URI/端口/state fail-closed**；attempt 过期/重用/state 不匹配全 fail-closed；refresh single-flight；健康四态不塌缩。→ E1。
- `keystore/`：信封往返；**缺 DEK→fail-closed（无明文回退）**；密钥与密文**不同位置**；**二进制模式/无换行转码回归测**（防 `0x1A`/`0x0A` 历史 bug）；token 不出现在任何输出面。→ E7。
- `sendfsm/`：转移合法性；同键同 digest 返回原、同键异 digest 冲突；`outcome_unknown` 不重试；`dispatched` 后注入崩溃仍 `outcome_unknown`；执行前重校四条件。→ E2a/E3/E4。
- `actionset/`：确认模式下直接发送动作**不在** Agent 工具列表；Agent 改不了开关；切换不影响当前 turn。→ 横切 confirm-then-send 门。
- 端到端：E5 规范化 Unicode payload 走 send，接 M2 canonicalizer，§8.5 摘要端到端跑通。
- **E7 泄漏扫描纪律**：日志/消息/错误栈/报告四面各自 `active-positive-control`；**先植入假 token 证命中，再证真 token 零命中**——空扫描是搜索假设不是证据（正对照优先）。代码需让错误对象可扫 + 支持植入正对照；错误分“用户安全信息/本机诊断”，上送对象**永不含 Google 原始 token response**（§7/§8.1-E7）。
- 我要 测试姬 那份更细的「Gateway 可测性验收面」（每项对应 DESIGN 行 + 期望可观测字段），当模块接口的验收目标。

---

## 6. Tradeoffs / 已知限制 / 挂起

- **复用 vs 手写**：复用 `google-auth` token 管线，自控 loopback/PKCE/attempt 生命周期（安全硬门要求）。备选 `authlib`。
- **同 UID 限制**：v1 记录不解决（§2.6）。
- **§10 挂起**：transport/endpoint 名/跨平台凭据库最终实现/授权 UI/`outcome_unknown` 裁定 UI+保留期/最终目录结构——接口留空位，仓库定后填充不重构。
- 不预设计 v1.1（附件/HTML），只留 DESIGN 已钉的前向兼容槽。

---

## 7. 落地顺序（repo 定案前可做）

1. `oauth/`：PKCE 工具 + loopback listener + fail-closed 校验（纯本地，可测，不需 repo）。
2. `keystore/`：信封加密 + `keyring` backend + fail-closed（可测）。
3. `sendfsm/`：FSM + 幂等账本 + 重校（纯逻辑，用 fake Gmail client 测）。
4. `actionset/`：闭集投影 + 开关投影（接 M2 `payload.py`）。

repo 一定 → 补 `transport/`（wire format/endpoint 名）+ 最终目录 + 跨平台凭据库最终实现，串成可跑 Gateway，交 测试姬 E0–E7。

---

## 8. 依方向 review 的设计增补（v0.2，2026-09-01）

测试姬（可测性 lane，msg_d163f216）与 Chris（QA，msg_1704c295）均 **方向 PASS**；两方 review **收敛到同一实质缺口**（门3 云端零触点的正向可观测）。crypto 族/库选型（google-auth↔authlib）归 Chris/impl code-时复审，不在此列。v0.1 正文保留；本节是可 1:1 对 review 的 delta。

### 8.1 [实质缺口 · 两方收敛] 出站「云端零触点」的正向可观测（补进 `oauth/` 与发送路径）
否定命题不能靠缺席证明——§1 L53/L60 是 **code-path 层正确判定**（结构上不连云端），但**不足以让 E1「可核」**（同 E7「空扫描是假设不是证据」纪律）。Chris 原表给门3 一个 ✓ 属 code-path 层，正确判定不撤；只在 E1 观测层加正向 artifact。增两层：
- **Gateway 进程自证 egress allow-list（强制 + 自记录）**：所有 Gateway 出站 HTTP 走单一受控 client，host **allow-list**——OAuth 阶段 = `{oauth2.googleapis.com}`（code 交换/refresh/revoke），发送阶段 = `{gmail.googleapis.com}`；非白名单 host **fail-closed** 且记录（allow-list 表达边界，非逐条 deny；零 Puffo/云端 host by construction）。每次 connect/send 产出脱敏 `egress_hosts` 集合作为**正向 artifact** 供核。
- **精度更正**：`accounts.google.com` 是**浏览器侧**同意页（用户点授权），**不是** Gateway 进程 egress；它由 E1 已计划的「仅 Google+loopback 脱敏网络证据」（机器级 egress 抓取，覆盖浏览器+Gateway）观测。loopback 是**入站**，不计 egress。
- 合起来：E1「只连 Google+loopback」= 机器级网络证据 **+** Gateway 自证 allow-list，双向可验。**E1 时缺此项 = BLOCK**（Chris code-时③ / 测试姬实质缺口①）。

### 8.2 [澄清 · 测试姬①] 健康四态可查询/可导出
四态（§4.2）不仅内部不塌缩，还必须在**脱敏输出面可读**，供 E6 观测 `active→reauthorization_required→active` 迁移。

### 8.3 [澄清 · 测试姬②] `provider_result_ref` 最小字段集
= `{ message_id_sha256, thread_id_sha256 }`（Gmail send 响应 `id`/`threadId` 的小写 SHA-256 hex；**不**存原始 id / labelIds / 正文 / 地址）。字段清单不依赖 repo；最终 wire 挂 §10。供 E2a/E5 断言「存了非秘密的最小引用」。

### 8.4 [口径对齐 · 测试姬③] E2b
E2b 的 403 = Jeremy 用**原始 token 直打** `messages.list` 的 **scope 探测**（证授予 scope 真只有 `gmail.send`），**非** `actionset` 投影层的被测项。投影层无任何读能力（门4）是**独立**且正确的另一件事。口径一致。

### 8.5 [Chris code-时项 · 落设计承诺]
code 时闭合，先在设计里锚定判据：
- **① `actionset/` 无绕过路径**：不得包一层加 header dict、不得新增 `extra_params`；`actionset/` 只做**投影**不做扩容，门4 schema 基座仍是 M2 `payload.py` reject-unknown。独立测试面：`PrepareEmail` schema 外任何字段→拒绝；所有已知字段 round-trip。
- **② `store/` 审计记录 schema**：按 §7 展 **FSM 每转移的最小审计字段清单 + PII/token 零命中断言**，与 E7 四扫描面对齐。
- **③ AEAD nonce 无重用测试面**：96-bit 随机 nonce + AAD=类型+版本；测试须覆盖**跨记录 / 跨版本 nonce 无重用**（AAD 覆盖旋转/迁移/版本变更三情境）。
- **④ `last_verified_at` 推进判据**：「探测不推进、只 grant 成功推进」需在 `oauth/` 给**可测的「什么算探测」判据**，防 refresh 分支塌成「凡刷新即推进」。
