# 架构一页纸 v0.1（草案，待拍板）

> 日期：2026-11-20。依据：三份调研报告（先例全景 / 动作库选型 / 靶场与防守栈选型）+ 已拍板决议（Apache-2.0、Go 单二进制、planner 走 API、day-one 自主双模式、融合成熟方案不验证未验证道路）。
> 项目暂名，仓库未建；本页为仓库首份 docs/architecture.md 的底稿。

## 一、产品定义

无头智能体引擎：在自带靶场内自主执行完整攻击链（Web/API 入口 → 凭据获取 → 内网横向 → 端点/EDR），双模式：

- **验证模式（AEV）**：证明/证伪暴露可利用 + 检测命中判定（该响没响 / 响了没报），输出证据链 findings
- **渗透模式**：开放目标下的自主探索与利用，输出渗透报告 + TTP 时间线

**10 秒故事（草案）**："It breaks in like a real attacker — and proves it. A headless AI agent that chains web exploits into lateral movement, then tells you exactly which detections missed it. Every finding ships with replayable evidence."

中文一句：像真攻击者一样打穿，用可复跑证据告诉你哪道防御没接住。

**差异化楔子（调研结论）**：端点/EDR 检测验证闭环——Strix（76.7k）/Decepticon/ARTEX 血统全部不做，开源 agent 赛道白地；叙事主打验证模式，渗透模式为第二支柱，正面避开 Strix 主场。

## 二、形态与循环

无头引擎；壳可换（CLI / IM / MCP / CI），机器可消费 API 进出。
循环：侦察 → 规划 → 执行 → 取证 → 判定/复测。人只在两个点出现：授权审批（开工 / 扩权 / 硬停止）与证据复核。
两种模式同一循环，差异只在目标函数与终止条件。

## 三、五不变量（定稿）

1. **technique = 声明式动作单元**：ATT&CK 映射 + 前置条件 + 动作 + 产物；动作 schema 采用 TTPForge YAML（MIT，Meta）为参考格式——不发明未验证格式。
2. **执行适配层**：planner 决定"做什么"，adapter 决定"怎么执行"（三层：Go 内嵌库 / 外部进程 / VM 代理）。
3. **证据一等公民**：每动作强制产物，无产物 = 未发生；一次交战 = 可确定性重放的完整证据包。
4. **授权内核**：scope manifest 是 planner 每步决策的必经闸；默认仅授权目标 + 自带靶场；公网目标需显式旗标；fail-closed；全程审计日志。（ARTEX 教训：治理即产品，不是道德装饰。）
5. **planner 模型无关**：只走 API，模型可换可降级，不绑 agent 框架。

## 四、动作库（三层管理，来源标注即产品机制）

- **嵌入层**（逐卡三元组：来源仓库 + commit + 许可证）：Atomic Red Team（MIT，主库）/ nuclei-templates（MIT，Web 入口主力）/ Certipy（MIT）/ Impacket（Apache-1.1 改版）/ Rubeus、Inveigh（BSD-3）/ PurpleSharp（BSD-3，Windows 端点执行代理，47 个 ATT&CK 技术）/ SecLists（MIT）/ TTPForge schema 参考 / ATT&CK STIX（MITRE 声明）。
- **外部调用层**（进程隔离）：NetExec（BSD-2）/ Nuclei 引擎（MIT）/ LaZagne（LGPL）/ mimikatz（CC BY 4.0，可选）/ SharpHound（GPL-3.0，必须外进程）/ Metasploit（兜底）。
- **数据借鉴层**：PayloadsAllTheThings（MIT）/ PowerSploit 单脚本移植（BSD-3，逐函数标注）/ Caldera stockpile 结构参考。
- **规避**：RTA（AGPL+停更 7 年）/ PEASS-ng（自定义条款"解析即衍生"）/ SharpView（已 404）/ Exploit-DB（归档）。

## 五、靶场（双档位）

| 档位 | 组成 | 内存 | 用途 |
|---|---|---|---|
| **轻配（首跑演示默认）** | VAmPI + DVWA（Web/API）+ Metasploitable 2（Linux）+ MINILAB/单 DC + vulnerable-AD 注入 + 离线检测链（chainsaw/hayabusa） | 约 8–10GB | 16GB 机器可跑；30 秒演示与首跑体验 |
| **全配** | DVWA + juice-shop + VAmPI + Metasploitable 2 + GOAD-Light（3VM）+ Velociraptor 判定 | 约 24–27GB | 32GB 机器；完整横向链 |
| **零 VM 档** | EVTX-ATTACK-SAMPLES 静态回放 | 零 | CI 与检测规则预验证 |

**硬约束（如实）**：AD 必须落 VM 层（vagrant/VirtualBox 或 Proxmox+Ludus）；Windows 评估版 ISO 需人工下载（许可不可再分发）→ 安装器做成向导，非全自动。SIEM 不进桌面靶场（Wazuh 8GiB / SecurityOnion 16GB+ 太重）——命中判定走 Velociraptor 内置 Sigma（200–300MB）或离线扫描。

## 六、证据判定链（核心机制）

**Join key = ATT&CK 技术编号**（社区成熟模式）：

动作（ART 测试 / PurpleSharp / nuclei 模板 id） → Sigma 规则（attack.tXXXX tag） → Velociraptor sigma() 命中（或 chainsaw/hayabusa 离线） → finding

- finding = 断言 + ATT&CK ID + 证据产物（命令输出 / 请求响应原文 / EVTX+命中规则）+ 复现步骤 + Sigma 规则作者（DRL-1.1 署名义务做成字段，恰好符合证据链）
- **"该响没响"判定**：动作成功 + 产物落盘 + 对应规则零命中 → 检测缺口 finding
- **模型说了不算，产物说了算**：模型自述仅为假设，判定必须挂产物；固定靶场同时是回归评测集，每次迭代可量化 agent 能力

## 七、技术栈（已定案）

Apache-2.0；Go 单二进制内核（分发零依赖）；planner 走 API（OpenAI 兼容 + Anthropic，模型无关）；Windows 侧执行代理复用/借鉴 PurpleSharp（C#）；文档英文优先。

## 八、分发四件套（stars 引擎，来自先例共性）

1. 30 秒演示（轻配靶场，零授权歧义）；
2. 硬验证承诺：所有自报数字可复算（对标 T3MP3ST 的 verify-claims 27/27）；
3. MCP / npx / CI 接入编码 agent 生态；
4. ATT&CK 映射 + 可复跑证据链 = 可信度与被引用前提。

## 九、待决与下一步

- **待用户拍板**：①仓库位置（GitHub 账号 / 本地路径）；②定名——候选（全部待撞名核查）：Krait / Boomslang / Vesper，标准：单词、可作 CLI 命令、GitHub 与搜索引擎无重大撞名。
- **就绪后立即**：初始化仓库（LICENSE / README / docs/research 迁入三份报告）→ 目录骨架 → 靶场 compose + Vagrant 初稿 → 首个端到端全链切片（验证模式优先，轻配靶场）。
