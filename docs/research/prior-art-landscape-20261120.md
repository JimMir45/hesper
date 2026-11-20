# 先例全景摸底：2024-2026 LLM/智能体自主渗透测试与攻击模拟开源赛道

> 调研日期：2026-11-20。由后台调研 agent 完成（GitHub API + HN Algolia + Reddit + 厂商公告 + 第三方审计清单交叉验证）。
> 数据口径：star 数、创建/推送时间、许可证均取自 GitHub API 实时查询，许可证逐仓库核对，未凭记忆填写。
> 注：项目暂无独立仓库，本报告暂存于会话附件区，仓库建立后迁入 docs/research/。

---

## 1. 全景对比表

### A. 自主/半自主渗透 Agent（主赛道）

| 项目 | 自主度 | 形态/技术栈 | 攻击链覆盖 | 证据链/结构化输出 | Stars（2026-11-20） | 创建 | 近期活跃 | 许可证（已核） |
|---|---|---|---|---|---|---|---|---|
| usestrix/strix | 全自主多智能体 | CLI + Cloud/Enterprise 开核（Python，LiteLLM+Caido+Nuclei+Playwright+TUI，Docker 沙箱） | Web/API/OWASP、云配置错误；无内网横向、无端点/EDR | 结构化 findings+CVSS+OWASP 分类+可复跑 PoC+合规报告；本地 dashboard+JSON | 76,749（全球 #256） | 2025-08-05 | 极活跃（周增约 1.6k star） | Apache-2.0 |
| KeygraphHQ/shannon | 全自主（白盒：先读源码再打） | CLI 一键 npx 启动（TypeScript） | Web/API（源码辅助攻击路径） | 口号即定位："No exploit, no report"，以真实利用证明漏洞 | 52,113 | 2025-09-27 | 活跃（2026-11-20 当日有推送） | AGPL-3.0 |
| vxcontrol/pentagi | 全自主（Automation 模式）+ Assistant 半自主模式 | Docker Compose 平台 + Web UI + GraphQL API（Go+React+pgvector+可选 Neo4j+Langfuse） | 20+ 工具容器化执行；README 明确声明不是 BAS/对手仿真，未声称全链 | 报告支持 Web/Markdown/PDF；JSON 流报告导出未见文档；动作/产物存 Postgres | 34,658 | 2025-01-06 | 活跃 | MIT |
| GreyDGL/PentestGPT | Copilot（人机交互逐步引导，2023 一代） | Python CLI | Web 渗透测试方法论引导 | Markdown 报告；无证据链 | 16,523 | 2023-02-27 | 低（最后推送 2026-07-14） | MIT |
| 0x4m4/hexstrike-ai | 非完整 agent：MCP 工具桥，自主性在外部 agent | Python MCP Server，150+ 工具、12+ 角色预设；OTT Cybersecurity LLC 所有 | 不自成链；给外部 agent 供工具（Web/网络/云/二进制/CTF/OSINT） | 漏洞卡片式可视化输出；非结构化 findings 引擎 | 13,773 | 2025-07-10 | 活跃 | MIT |
| aliasrobotics/cai | 全自主框架（研究向） | Python 框架（基于 openai-agents-python），PyPI cai-framework | CTF/渗透/bug bounty | 研究产出丰富；非产品化证据链 | 9,869 | 2025-03-31 | 已归档（2026-08，转入闭源商业产品 CSI） | API 显示 NOASSERTION，README 徽章 "MIT + Proprietary" |
| AIPentest/CyberStrikeAI（原 Ed1s0nZ） | 人监督下的受治理自主执行 | Go 平台 + Web UI（Pi agent + MCP + RAG + 可视化工作流 + 攻击链建模） | 含 WebShell/C2 能力，偏安全运营/红队一体化 | 明确主打"证据成为运营记忆 + 回放"的可审计工作区 | 8,876 | 2025-11-08 | 活跃 | Apache-2.0 |
| elder-plinius/T3MP3ST | 全自主 harness（借用已登录编码 agent 当大脑） | TypeScript harness，驱动 Claude Code/Codex/本地模型；recon→exploit→report | XBOW 104 题套件与 CTF 为主要验证域 | 自报 XBOW 套件 pass@1 90.1%（高于 XBOW 自报 85%），数字可 npm run verify-claims 复算（27/27） | 7,088 | 2026-07-02 | 活跃 | AGPL-3.0 |
| BitterSecurity/Decepticon | 有界全自主（RoE+计划文档，16 个专业 agent 按杀伤链分相） | Docker CLI + 云控制台 + MCP（Kali 沙箱+tmux、LangGraph+Deep Agents、LiteLLM、Neo4j、BloodHound CE、Sliver C2） | 全场最宽：recon→利用→提权→横向→C2，AD/云/智能合约；README 明确未含 EDR 逃避/端点 tradecraft | 无报告生成器（查不到已发布导出格式）；findings 存 Neo4j 攻击链图谱；自报 XBOW 验证集 102/104 | 6,656 | 2025-06-06 | 极活跃 | Apache-2.0 |
| oritera/Cairn | 全自主（通用状态空间搜索引擎，渗透为首个验证域） | Python；Fact/Intent/Hint 显式图 + 共享黑板 + 动态 worker | 渗透测试验证域 | 图状态可追溯（偏机制而非报告产品） | 5,438 | 2026-04-19 | 疑似放缓（最后推送 2026-09-07） | AGPL-3.0 + 商业授权 |
| gadievron/raptor | Claude Code 之上的攻防研究 agent | Claude Code 配置/框架 | 静态/二进制分析、漏洞验证、PoC、补丁生成 | PoC 与验证流程内置 | 4,039 | 2025-10-17 | 活跃 | README 称 MIT（API NOASSERTION，待细核） |
| Armur-Ai/Pentest-Swarm-AI | 全自主蜂群（自称开源 XBOW 替代） | Go，黑板协调 | API/Web 利用链（BOLA/IDOR/JWT 伪造/SSRF） | 攻击路径构建与评分、证明真实漏洞 | 3,269 | 2024-03-26 | 活跃 | AGPL-3.0 |
| GH05TCREW/pentestagent | 半自主框架 | Python + MCP，黑盒测试 | 渗透/赏金/红队工作流 | 查不到证据链细节 | 3,315 | 2025-05-15 | 活跃 | MIT |
| N1nEmAn/sapper-v2 | 全自主多智能体军团（指挥官/将军/士兵） | 编排 harness（驱动 Claude Code/Codex/DeepSeek 等 CLI） | 赛事/CTF 域（腾讯云第三届智能攻防线上赛第一：634 队 80.18 分 8h 无人值守；GeekCon 2026 AI 挑战一等奖） | 赛事计分验证；报告模板面向 CTF | 2,500 | 2026-10-30 | 极活跃 | MIT |
| protectai/vulnhuntr | 全自主（静态代码审计，非攻击链） | Python LLM 审计器 | Python 源码零样本漏洞发现 | — | 2,825 | 2024-10-15 | 停滞（最后推送 2025-02-06） | AGPL-3.0 |
| SanMuzZzZz/LuaN1aoAgent | 全自主（认知驱动 P-E-O 架构） | Node/TypeScript | 渗透 agent（腾讯智能渗透榜首项目徽章） | 查不到证据链细节 | 1,494 | 2025-12-04 | 活跃 | AGPL-3.0 |
| xalgorix/xalgorix | 全自主 + 逐条利用验证 | Go CLI + Cloud 开核 | 渗透测试 | 主打 "exploit-verified findings"（定位正面相撞的新锐） | 1,377 | 2026-03-13 | 极活跃 | Apache-2.0 |
| s0ld13rr/pentestcode | 全自主终端多 agent | 终端 CLI | 渗透（持续交战状态跟踪） | engagement 状态持久化 | 1,204 | 2026-07-08 | 活跃 | MIT |
| H-mmer/pentest-agents | 半自主（编码 agent 子 agent 集） | 各编码 agent 的 agent 框架 | 赏金/渗透 | 查不到 | 1,212 | 2026-04-01 | 停滞（最后推送 2026-06-12） | 无许可证文件 |
| yv1ing/Z3r0 | 半自主工作台（专家 agent + 沙箱） | 工作台 | 授权渗透与漏洞研究 | 证据记录 + 可回放时间线（README 原文） | 1,025 | 2026-04-27 | 活跃 | MIT |
| berylliumsec/nebula | 半自主：operator 掌舵的 harness（审批/预算/范围控制） | 桌面应用（安全浏览器+拦截+Repeater、Kali 容器、VPN 出口、SKILL.md、语音 Butler） | 浏览器/终端人工+辅助混合 | 证据式报告：哈希工件+执行溯源+findings 挂证据+报告/交战包导出 | 1,161 | 2023-09-30（老仓库，2025-2026 演进为 harness 形态） | 极活跃（当日有推送） | BSD-2-Clause |
| ARCANGEL0/Mitsu | 半自主 CLI（自设范围后自主跑） | CLI | 红队操作 | 查不到 | 541 | 2025-12-15 | 活跃 | MIT |

### B. ARTEX 现象（2026 年最大单一事件）

| 仓库 | Stars | 创建 | 说明 |
|---|---|---|---|
| 上游 Autumn-27/ARTEX | 已 404（下架） | — | 中文多智能体自主渗透系统（Go+Next.js 单二进制，planner/worker/retester）；下架前约 1.5k star，获百度 agent+ 赛事奖项；2026-10-08 作者因滥用而移除并闭源（韩国银行攻击后，Reuters 报道）；11 月 FBI FLASH 警告；WorkOS 被入侵事件中攻击者使用 ARTEX；Amazon 威情观测到 ARTEX 活动 |
| BaaRai/ARTEX（英文翻译续作） | 12,705 | 2026-10-08 | AGPL-3.0；findings 绑定捕获的请求/响应原文、POE 等级+验证状态+复测闭环、资产/探索双图、MITM 代理——全赛道最深的"findings+证据"设计，但链路以 Web 为主 |
| jiwoochris/artex-global | 4,218 | 2026-10-03 | 蓝队理解向全球版 |
| RuoJi6/ARTEX | 2,348 | 2026-10-09 | 持续维护国际化版 |
| Hinln/ARTEX | 1,725 | 2026-10-08 | 源码备份（v0.3.15 保留提交史） |
| cskwork/scopeweaver | 1,142 | 2026-10-02 | 英/韩本地化 |
| failsafe-security/artex 等 | 887 / 822 | 2026-10/11 | 发行版/二开 |

fork 家族 7+ 仓库合计约 2.38 万 star / 6 周——赛道需求强度的最强单一信号，同时是被滥用反噬的完整案例。

### C. BAS/AEV 平台与基础设施（品类基准）

| 项目 | 定位 | Stars | 许可证（已核） | 关键事实 |
|---|---|---|---|---|
| OpenAEV-Platform/openaev（OpenBAS 更名） | AEV 品类"官方"开源占位平台：场景驱动攻击模拟/控制验证/桌面演练，非自主 agent；AI 只在商业版 | 1,852 | Apache-2.0 社区版 + 企业版 | Filigran 2025-10-29 官宣更名并发布 AI 企业版；OpenBAS 2024 年发布；仓库 created_at 2016-09-12 为迁移工件 |
| redcanaryco/atomic-red-team | 非 LLM 的 BAS 测试库基线（ATT&CK 对齐） | 12,890 | MIT | 持续维护（2026-11-16 有推送） |
| FunnyWolf/Viper | 中文对手仿真/红队平台 + AI 加持 | 5,358 | 无许可证文件 | 2020 年创建，AI 后加 |
| infobyte/faraday | 老牌漏管平台转型 "AI-powered" | 6,856 | GPL-3.0 | 2013 年创建 |

### D. 相邻层（AI 红队/LLM 安全，增长率对照）

| 项目 | 定位 | Stars | 许可证 |
|---|---|---|---|
| promptfoo/promptfoo | LLM/agent 红队扫描 | 27,483 | MIT |
| NVIDIA/garak | LLM 漏洞扫描器 | 10,113 | Apache-2.0 |
| Tencent/AI-Infra-Guard | AI 基础设施红队平台 | 7,595 | Apache-2.0 |
| microsoft/PyRIT | AI 红队工具包 | 4,970 | MIT |
| confident-ai/deepteam | LLM/agent 红队框架 | 3,112 | Apache-2.0 |
| Yeti-791/Awesome-Offensive-AI-Agentic-Landscape | 领域全景审计清单（60 agent/129 论文/15 benchmark，2026-11-18 更新） | 495 | MIT |

### E. 闭源商业参照

- XBOW（闭源）：2025-06-24 登顶 HackerOne US #1；2026-03 融资 1.2 亿美元；2026 年连出 Exim 无鉴权 RCE CVE-2026-45185 与 Chromium full chain；发布 Mythos 评测（2026-05）。
- MindFort（YC X25，Launch HN 2025-05-28）：持续 AI 渗透即服务。
- AWS Security Agent（2026-04-17 GA）：云厂商入场按需渗透测试。
- 研究信号：2026-11-16 HN 出现"1,698 个暴露在公网的 AI 攻防端点"——真实部署存在但暴露风险已成公共议题。

---

## 2. 结论："自主全链验证 + 证据链 + 结构化 findings" 是否已被占位？

没有被单一项目占位。组合中的每一块都分别有人做到 80 分，但三块交集是空的，且"端点/EDR 检测验证"这条腿在整个开源 agent 赛道几乎无人做。

| 最接近者 | 已占据 | 缺口 |
|---|---|---|
| Strix | 自主 + 利用验证 + 结构化 findings + 合规报告 + 开核商业化，品类第一 | 链路止步 Web/API/云配置；无内网横向、无端点/EDR 验证；形态是"安全扫描产品"非无头引擎 |
| Decepticon | 链路最宽（横向、AD/BloodHound、C2、云、16 agent 按杀伤链分相） | 无报告/证据链产品化输出（只有 Neo4j 图谱存储）；同样未做 EDR 检测验证 |
| ARTEX 血统（BaaRai 等 forks） | 全赛道最深证据设计：findings 绑定原始请求/响应、POE 等级、验证状态、复测闭环 | 链路以 Web 为主；上游已死、闭源化，fork 家族法律与社区基础不稳；带 UI 平台而非无头引擎 |

外围占位：OpenAEV 独占 "AEV" 这面旗，但它是场景驱动的 BAS 平台（AI 仅企业版），与"自主 agent 引擎"是两个物种——反而验证了品类术语；CyberStrikeAI/Z3r0/Nebula 各摸到"证据/回放"概念但形态是平台/工作台、体量小或偏运营；PentAGI 自我声明"不是 BAS/对手仿真"，主动留出空位。

差异化空间（按防御性排序）：
1. 端点/EDR 检测验证闭环：agent 打完整链的同时，对端点遥测/EDR 告警做"该响没响/响了没报"的关联判定——BAS 厂商的地盘，开源 agent 阵营无人做，两个世界交接处的白地。
2. 无头优先：头部竞品都在往 UI/平台/云控制台长；"引擎形态、CI/定时任务、机器可消费 API 进出"无人以产品对待。
3. 可复跑证据链：ARTEX 的 POE/复测 + CyberStrikeAI 的回放 + Z3r0 的可回放时间线各自零散存在；"一次交战 = 确定性可重放的完整证据包"无人做成一等公民。
4. 治理默认内建：ARTEX 因滥用下架/FBI 点名是赛道公开伤疤；范围/RoE 硬约束、审计日志、fail-closed 权限做成默认卖点，既是差异化也是品类活下去的前提。
5. 结构化 findings schema：只有 Strix（CVSS+OWASP）做得像样；"机器可消费、可去重、ATT&CK 映射、可回灌防御侧"的 findings 中间格式是空的。

这个组合在 2026-11 是空位，但窗口正在以月为单位关闭——Strix 的增长曲线和 Decepticon 的链路扩张都指向同一交汇点。

---

## 3. "一年 1 万 GitHub star"现实校准

结论：在这个子品类里，1 万/年不是幻想——2025-2026 至少 4 个先例在创建后 12-17 个月内到达或接近 1 万。但同期审计清单收录的 60+ 项目大多数停在 3k 以下，先例全部具备可复制成功要素，也全部有不可复制的运气成分。

| 增长案例 | 创建→当前 | star 曲线已知节点 | 做对了什么 |
|---|---|---|---|
| Strix | 2025-08-05 → 76.7k（15.5 个月） | 2025-08-18 Show HN 仅 102 分（HN 不是主引擎）；2026-11 现 +1.6k/周、全球 #256；中间里程碑查不到 | "复刻 5 万美元渗透服务"的 10 秒故事（病毒式 X 帖）；"PoC 验证、不是误报"硬承诺；开核公司（CLI 免费→Cloud/Enterprise 收费）；"每次 PR 持续渗透"绑进开发者工作流；MCP/skills 接入编码 agent 生态 |
| Shannon | 2025-09-27 → 52.1k（约 14 个月） | 中间节点查不到 | 差异化楔子（白盒：先读源码再攻击）；狠口号 "No exploit, no report"；npx 一键启动零摩擦 |
| PentAGI | 2025-01-06 → 34.7k（22.5 个月） | 2026-06 第三方盘点 14.7k → 2026-11 34.7k：最后 5 个月涨约 2 万（后程加速） | 企业级平台完整度（Compose 一键、UI、观测栈）；迪拜公司开核；长期慢热后吃品类整体热度 |
| HexStrike | 2025-07-10 → 13.8k（16.5 个月） | 2025-09-02 Check Point 报告 + 2025-09-04 滥用报道 = 引爆点 | "给所有编码 agent 的 150+ 工具桥"纯实用主义；威胁情报报告恶名流量（双刃剑） |
| CyberStrikeAI | 2025-11-08 → 8.9k（12 个月） | 中间节点查不到 | 中文社区主场；"治理执行 + 证据记忆 + 回放"叙事直接对齐企业采购语言 |
| CAI（反例） | 2025-03-31 → 9.9k（17 个月）后归档闭源 | 2025-12 最后开源版 0.5.10；2026-08 归档 | 研究公信力换增长；开源→付费→全面闭源的压力路径 |

对本项目的含义：
- 可达性：1 万/年在本品类有 4-6 个先例支撑，"踮脚可及"；AI 安全红队工具（promptfoo 3.5 年 27k、garak 3.5 年 10k）速度差一个量级——品类选择本身已是最大增长杠杆。
- 可复制共性：① 一句话 + 演示视频/GIF 的 10 秒价值主张；② 硬验证承诺（PoC 或 benchmark 回执，T3MP3ST 的 verify-claims 27/27 是新标杆）；③ 背后有商业实体持续投入（Strix/PentAGI/HexStrike/Cairn/xalgorix 全部有公司）；④ 接入编码 agent 生态（MCP/skills/npx/CI）。
- 不可复制共性：威胁情报报告点名（HexStrike）、FBI 警告（ARTEX）、赛事冠军（sapper/LuaN1aoAgent）、大 V 人格（T3MP3ST/pliny）。
- 风险提示：ARTEX 全链案例证明知名度和滥用风险同源；"一年 1 万 star"若靠攻击性演示换来，可能同时换来厂商警告与下架压力（CAI 归档、ARTEX 闭源是同一结局的两个版本）。治理内建不是道德装饰，是可持续增长前提。

---

## 4. 查不到 / 不确定项

- 所有项目的逐月 star 曲线：GitHub stargazers 时间戳接口不可用，仅有创建日、当前值和有日期的第三方数据点；各里程碑日期查不到。
- Decepticon 背后公司 BitterSecurity 团队详情查不到；其"102/104 XBOW 验证集"为 README 自报，未见独立复现。
- PentestGPT 2023-2024 中途 star 节点查不到。
- r/vibehacking 等社区规模查不到。
- Shannon、CyberStrikeAI 的中途增长归因只有结果无过程来源，归因未验证。

## 5. 主要来源

- 仓库元数据/许可证/README：GitHub API（gh 认证接口，2026-11-20 实查）与各仓库 README 原文。
- 品类全景交叉验证：Yeti-791/Awesome-Offensive-AI-Agentic-Landscape（2026-11-18 数据）、blog.spark42.tech Top 10 盘点。
- HN 讨论：Strix Show HN (44945113)、XBOW 登顶 (44367548)、FBI 警告 ARTEX (50520796)、MindFort Launch (44117465)、AWS Security Agent GA (47805865)、1698 个暴露的 AI 攻防端点 (50515662)、WorkOS 入侵 (50345712)、ARTEX Amazon 威情 (50507199)、Exim CVE (48111748)、Chromium full chain (50076503)、XBOW 融资 (47458177)。
- Reddit：ARTEX 翻译帖、自主渗透 agent 是否有用、渗透测试是否被 AI 取代。
- 厂商与威胁情报：Filigran OpenBAS→OpenAEV 公告、Check Point HexStrike 报告、OpenBAS 2024 发布（Help Net Security）。
- 正名：任务清单中 "hackingBuddyGND" 实为 ipa-lab/hackingBuddyGPT（TU Wien，arXiv:2310.11409）；"Nebula" 实为 berylliumsec/nebula。
