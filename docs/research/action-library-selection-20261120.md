# 可复用攻击动作库深度选型调研报告

> 调研日期：2026-11-20。后台调研 agent 完成。
> 核实方法：GitHub REST API 仓库元数据 + CDN 直读每个仓库 LICENSE 文件原文（非凭记忆）。
> mitre/caldera、SecureAuthCorp/impacket、BloodHoundAD/SharpHound 三个旧地址均已 301 重定向，一律使用现址。
> 注：项目暂无独立仓库，暂存会话附件区，仓库建立后迁入 docs/research/。

## 一、对比总表

| # | 对象 | 现址（2026-11） | 许可证 SPDX（核实来源） | 语言/形态 | Star | 维护状态 | ATT&CK 映射 | 关系判定 | Apache-2.0 宿主 | AGPL-3.0 宿主 |
|---|------|-----------------|------------------------|-----------|------|----------|-------------|----------|------------------|----------------|
| 1 | Atomic Red Team | redcanaryco/atomic-red-team | MIT（LICENSE.txt 原文已核） | 数据集+脚本（YAML/PS1/PY/C#） | 12,890 | 活跃（push 2026-11-16，持续发版） | 原生按 technique ID 组织（精确条目数待核实 §五-1） | 可直接嵌入复用 | 兼容 | 兼容 |
| 2 | invoke-AtomicRedTeam | redcanaryco/invoke-atomicredteam | MIT（已核） | PowerShell 执行模块 | 1,098 | 放缓（push 2025-09-08） | 继承 ART | 可直接嵌入复用（作执行器） | 兼容 | 兼容 |
| 3 | MITRE Caldera | apache/caldera（已迁移） | Apache-2.0（已核） | 引擎（Python）+插件 | 7,542 | push 2026-11-20；最新 release v5.3.0 停在 2025-04-24（待核实 §五-2） | stockpile 插件 ability 按 ATT&CK 组织（总数待核实 §五-11） | 仅作外部集成调用（ability YAML 可作数据借鉴） | 兼容 | 兼容 |
| 4 | Caldera atomic 插件 | mitre/atomic | Apache-2.0（已核） | Caldera 插件（桥接 ART） | 57 | push 2026-05-27 | 桥接 ART | 仅作外部集成调用 | 兼容 | 兼容 |
| 5 | Stratus Red Team | DataDog/stratus-red-team | Apache-2.0（已核） | Go 库+CLI（云） | 2,453 | 非常活跃（v2.38.1，2026-11-16） | 云 ATT&CK 映射（README 确认） | 可直接嵌入复用（一期不涉及云，二期启用） | 兼容（NOTICE+声明变更） | 兼容 |
| 6 | Metasploit Framework | rapid7/metasploit-framework | GitHub 显示 NOASSERTION；LICENSE 原文核实：主体 BSD-3-clause（DEP-5），但捆绑大量第三方组件各自许可（含 LGPL-2.1、MIT、APSL 条款段，明细待核实 §五-8） | Ruby 框架+exploit 库 | 39,625 | 非常活跃（6.5.11，2026-11-18） | 无原生 ATT&CK 字段（第三方映射，待核实） | 仅作外部集成调用 | 主体兼容，但整包不可嵌入（第三方许可混杂） | 同左 |
| 7 | Impacket | fortra/impacket（SecureAuthCorp 已 301 迁移） | LICENSE 原文核实："略作修改的 Apache License 1.1"（仅替换署名方为 Fortra） | Python 库（SMB/WMI/DCOM/Kerberos 协议族） | 16,291 | 活跃（0.13.1，2026-05-19） | 无原生映射；社区实践对应 secretsdump≈T1003.003、wmiexec≈T1047 等（待核实） | 可直接嵌入复用（库形态理想） | 兼容（保留声明） | 兼容（FSF 认定 Apache-1.1 兼容 GPLv3） |
| 8 | NetExec | Pennyw0rth/NetExec（CrackMapExec 生态继任者） | BSD-2-Clause（LICENSE 原文已核） | Python 工具+模块框架 | 6,035 | 非常活跃（push 2026-11-20；v1.5.1，2026-02-23） | 无原生映射 | 仅作外部集成调用（法律上允许嵌入，工具形态按子进程更稳） | 兼容 | 兼容 |
| 9 | BloodHound CE | SpecterOps/BloodHound | Apache-2.0（已核） | 平台引擎（Go+React） | 3,585 | 活跃（push 2026-11-20；最新 release 版本号查不到 §五-3） | 攻击路径对应横向/提权类，无逐条映射（待核实） | 仅作外部集成调用（attack-path 逻辑可借鉴） | 兼容 | 兼容 |
| 10 | SharpHound（新版收集器） | SpecterOps/SharpHound（BloodHoundAD 已 301 迁移） | GPL-3.0（LICENSE 原文已核，非 Apache） | C#/.NET 收集器 | 1,383 | 活跃（push 2026-11-12） | 收集方法对应 ATT&CK 发现类（社区映射，待核实） | 仅作外部集成调用（Apache 宿主下不可嵌源码） | 不兼容（嵌入即触发 GPL 传染） | 兼容（并入后整体转 AGPL） |
| 11 | Certipy | ly4k/Certipy | MIT（已核） | Python 库+CLI（ADCS） | 3,732 | 正常（5.1.0，2026-06-23） | ESC1-15 滥用场景，ATT&CK 对应不完整（待核实） | 可直接嵌入复用 | 兼容 | 兼容 |
| 12 | PowerSploit（含 PowerView） | PowerShellMafia/PowerSploit | BSD-3-Clause（已核，2012 Matt Graeber） | PowerShell 模块集 | 13,069 | 已归档（最后 push 2020-08-17） | 无原生映射 | 作数据借鉴（单脚本移植+标注来源） | 兼容（声明+不背书） | 兼容 |
| 13 | SharpView | dmejo/SharpView | 仓库 404，已消失（API+HTML 双重确认） | C#（PowerView 移植） | - | 不存在 | - | 不可用；替代需另寻社区 fork（待核实 §五-5） | - | - |
| 14 | Nuclei 引擎 | projectdiscovery/nuclei | MIT（已核） | Go 扫描引擎 | 33,140 | 非常活跃（push 2026-11-20） | 无 | 仅作外部集成调用（MIT 也允许嵌入，引擎体量大按服务调用更稳） | 兼容 | 兼容 |
| 15 | Nuclei 模板库 | projectdiscovery/nuclei-templates | MIT（已核） | YAML 模板数据集 | 13,372 | 非常活跃（v10.5.2，2026-11-12；每日更新） | 无（按 CVE/tag 组织） | 可直接嵌入复用（一期 Web/API 入口主力数据源） | 兼容 | 兼容 |
| 16 | PayloadsAllTheThings | swisskyrepo/PayloadsAllTheThings | MIT（已核——不是传闻的 GPL） | 知识库（方法+载荷文本） | 82,811 | 正常（push 2026-10-30） | 无 | 作数据借鉴（方法→动作卡） | 兼容 | 兼容 |
| 17 | SecLists | danielmiessler/SecLists | MIT（已核） | 字典数据集 | 74,853 | 非常活跃（push 2026-11-20） | 无 | 可直接嵌入复用（数据） | 兼容 | 兼容 |
| 18 | PEASS-ng（linPEAS/winPEAS） | peass-ng/PEASS-ng | GPL-2.0-or-later + 自定义 COPYING（原文已核）：明确把"执行 peass-ng 并解析其结果"也定义为衍生作品，且卖商业双授权 | Shell/PS 收集脚本 | 20,862 | 活跃（滚动发布，2026-11-17） | README 未体现 ATT&CK 映射（待核实 §五-6） | 仅作外部集成调用，且风险高 | 不兼容/高风险（其解释下连子进程+解析输出都算衍生） | 可并入（选 v3 路径，整体转 AGPL），但商业双授权方解释从严，建议法务确认 |
| 19 | LaZagne | AlessandroZ/LaZagne | LGPL-3.0（已核） | Python 凭据回收工具 | 11,097 | 放缓（push 2025-09-18） | 单一目的（对应 T1555 类，无官方映射） | 仅作外部集成调用（子进程） | 弱兼容（LGPL 链接豁免；整并入需转 LGPL） | 兼容 |
| 20 | mimikatz | gentilkiwi/mimikatz | CC BY 4.0（README "## Licence" 声明，已核；仓库无 LICENSE 文件，不是传闻的 WTFPL） | C 工具（凭据提取） | 21,984 | 正常（push 2026-10-30） | 单一目的（T1003 类，无官方映射） | 仅作外部集成调用 | 弱兼容（署名即可；但 CC 官方不建议将 CC 许可用于软件，适用性待核实 §五-12） | 弱兼容（同左） |
| 21 | PurpleSharp | mvelazc0/PurpleSharp | BSD-3-Clause（已核） | C# 端点侧攻击模拟器 | 851 | 放缓（push 2026-02-23；最后 release 2022） | README 明确：支持 47 个 ATT&CK 技术（精确数字已核实） | 可直接嵌入复用（作为 Windows 端点执行代理） | 兼容 | 兼容 |
| 22 | TTPForge | facebookincubator/TTPForge | MIT（已核，Meta Platforms） | Go 引擎+TTP 库（YAML） | 448 | 正常（v1.5.0，2026-06-03） | TTP 按 ATT&CK 组织（覆盖数待核实） | 可直接嵌入复用（引擎或 TTP 数据） | 兼容 | 兼容 |
| 23 | RTA（Endgame） | endgameinc/RTA | AGPL-3.0（LICENSE.txt 原文已核） | PS/C# 检测验证脚本集 | 1,103 | 停更（最后 push 2019-05-01） | 按 ATT&CK 组织 | 作数据借鉴需防传染；建议直接排除 | 不兼容 | 兼容（同为 AGPL） |
| 24 | AtomicTestHarnesses | redcanaryco/AtomicTestHarnesses（原 Cisco-Talos 地址已 404，已迁 Red Canary） | BSD-3-Clause（已核，2023 Red Canary） | PowerShell 验证 harness 库 | 查不到（API 限额） | 自述 "currently isn't open to public development"（公开开发停滞） | 按技术逐条 harness | 作数据借鉴 | 兼容 | 兼容 |
| 25 | Sigma 规则库 | SigmaHQ/sigma | 规则=DRL-1.1（SPDX 官方标识，LICENSE 已核：基于 MIT，允许商用，义务=署名作者+匹配展示含作者）；规范=公有领域 | 检测规则数据集（YAML） | 11,538 | 非常活跃（push 2026-11-18） | 规则自带 ATT&CK tag | 可直接嵌入复用（作为检测验证的"靶子"数据） | 兼容（带 DRL 署名义务） | 兼容 |
| 26 | ATT&CK STIX 数据 | mitre-attack/attack-stix-data | MITRE 自定义许可（LICENSE.txt 已核：研究/开发/商业用途可用，须复现 MITRE 版权声明） | STIX 数据集 | 724 | 持续更新（push 2026-11-05） | ATT&CK 本体 | 可直接嵌入复用（动作卡映射底座） | 兼容（带声明） | 兼容 |
| 27 | Responder | lgandx/Responder | GPL-3.0（已核） | Python（LLMNR/NBT-NS/MDN 投毒） | 6,686 | 正常（push 2026-06-10） | 无原生映射 | 仅作外部集成调用 | 不兼容 | 兼容 |
| 28 | Inveigh | Kevin-Robertson/Inveigh | BSD-3-Clause（已核） | PS/C#（同上场景 .NET 实现） | 3,062 | 放缓（push 2025-11-19） | 无原生映射 | 可直接嵌入复用 | 兼容 | 兼容 |
| 29 | Rubeus | GhostPack/Rubeus | BSD-3-Clause（LICENSE 已核，"3-clause BSD"） | C#（Kerberos 请求/滥用） | 5,235 | 正常（push 2026-05-21） | 无原生映射 | 可直接嵌入复用 | 兼容 | 兼容 |
| 30 | Exploit-DB | offensive-security/exploitdb 已归档（2022-11）；exploitdb/exploitdb 404；官方疑似迁至 GitLab（待核实 §五-7） | GPL-2.0（归档仓库 API 显示） | PoC 库 | 7,858（归档值） | 归档 | 无 | 作数据借鉴（仅索引参考） | 不兼容 | 兼容（GPL-2.0 路径并入需整体转 GPL-2.0，与 AGPL-3.0 组合有版本冲突风险，不推荐） |

### 再分发义务细则（按许可证分组）

- MIT 组（#1/2/11/14/15/16/17/22/24）：所有副本须保留原版权声明与 MIT 许可文本。无其他义务。
- BSD-2/BSD-3 组（#8/12/21/28/29）：保留版权+许可声明；BSD-3 不得用原作者名义做推广背书。
- Apache-2.0 组（#3/4/5/9）：保留许可文本与 NOTICE 文件；分发时须声明修改；含专利授权条款（对防御产品有利）。
- Apache-1.1 改版（#7 Impacket）：保留声明即可；产品文档中应如实写 "Apache License 1.1 (modified)" 而非 2.0。
- GPL-3.0（#10/27）：凡嵌入/链接/合并即整包传染——Apache 宿主下禁止嵌入，仅可独立进程隔离调用；AGPL 宿主下并入后整体转 AGPL-3.0 并开放对应源码。
- GPL-2.0-or-later + 扩展解释（#18 PEASS-ng）：除 GPL 常规义务外，其 COPYING 明确把"执行并解析结果"也认定为衍生作品，Apache 宿主下即便外部调用也应视为高风险；官方提供付费替代许可。
- AGPL-3.0（#23）：Apache 宿主禁用；AGPL 宿主并入无额外负担；再分发须附 AGPL 文本并开放源码（含网络交互）。
- LGPL-3.0（#19）：以库形态链接/独立进程调用可保持宿主许可不变；对 LGPL 部分的修改须回赠。
- CC BY 4.0（#20）：署名义务；非典型软件许可，代码再分发适用性建议单独确认。
- DRL-1.1（#25）：允许商用；再复制规则须标注规则作者；在展示规则命中结果的界面中须显示作者（可作为字段实现）。
- MITRE 自定义（#26）：任何副本须复现 "© 2026 The MITRE Corporation..." 版权声明与许可文本；商业用途明确允许。
- BSD-3 主体+混杂第三方（#6 Metasploit）：主体 BSD-3 义务轻微，但 DEP-5 LICENSE 列明数十个第三方组件许可；整体打包再分发须逐项保留全部声明，实际不可作为宿主子模块嵌入。

## 二、分层推荐（一期四环节）

### 1. Web/API 入口（利用已知漏洞类）
- 首选：nuclei-templates（MIT）作数据嵌入 + Nuclei 引擎（MIT）作外部集成调用。理由：许可证双向干净；模板数据集日更覆盖 CVE/默认口令/暴露面，模板 YAML 天然就是"确定性技术动作"的载体，每个模板自带 id/author 字段使来源标注成本为零；引擎按服务调用可隔离其迭代风险。
- 备选：PayloadsAllTheThings（MIT）作方法学借鉴（把利用方法沉淀为自家动作卡），SecLists（MIT）提供枚举字典。两者均 MIT，可放心搬入并在动作卡注明来源仓库与文件路径。
- 说明：Metasploit 仅作最后兜底的外部集成（多许可混杂、Ruby 技术栈与无头智能体形态不匹配）。

### 2. 凭据获取
- 首选：Certipy（MIT，ADCS 滥用，库形态可直接嵌入）+ Impacket（Apache-1.1 改版，secretsdump/ntlmrelayx 等，Python 库嵌入最顺）。理由：两者都是可导入的库而非"黑盒工具"，智能体可以直接编排其 API；Impacket 维护活跃（Fortra 接手，0.13.1）。
- 备选：Rubeus（BSD-3，Windows 侧 Kerberos 操作）、Inveigh（BSD-3，NET-NTLMv2 捕获）、LaZagne（LGPL-3.0，端点密码回收，子进程调用避免 LGPL 传染）、PowerSploit 的 Get-GPPPassword 等单脚本按 BSD-3 移植进动作库（原仓库已归档，移植时逐函数标注来源）。
- 规避：PEASS-ng 不做宿主内解析（其 COPYING 的"解析即衍生"解释在 Apache 宿主下风险过高）；mimikatz 因 CC BY 4.0 的非典型性，仅作可选外部工具引用而非依赖。

### 3. 内网横向
- 首选：Impacket（嵌入，WMI/SMB/DCOM 远程执行族）+ NetExec（BSD-2，子进程执行面；其模块划分作数据借鉴）。理由：Impacket 提供协议层原语（嵌入层），NetExec 提供横扫编排与横向模块生态（执行层），互补且许可证均可承载。
- 备选：Rubeus（Kerberos 横向）；BloodHound/SharpHound 数据采集线需许可证决策：新版 SharpHound 是 GPL-3.0，Apache 宿主下只能作为独立外部收集器进程调用（不链接、不嵌源码），若采用 AGPL-3.0 宿主则可整体并入——这是"宿主许可证选 Apache 还是 AGPL"的最重砝码之一。
- 放弃：SharpView（仓库已 404 消失）；PowerView 以"BSD-3 移植"方式保留能力。

### 4. EDR 检测验证
- 首选：Atomic Red Team（MIT）整体作为一期确定性动作主库。理由：ATT&CK 原生映射、Red Canary 持续维护（2026-11 仍活跃）、社区事实标准（下游执行器生态最全）；嵌入 atomics YAML+脚本并在每张动作卡记录 "technique ID + 源仓库 + commit" 即满足来源标注要求。
- 备选：TTPForge（MIT，Meta）——其 YAML TTP 结构比 ART 更适合作为无头智能体的动作 schema 参考，甚至可直接采用其格式；PurpleSharp（BSD-3）——C# 端点侧模拟器，README 明确支持 47 个 ATT&CK 技术，可作为 Windows 靶端执行代理嵌入；AtomicTestHarnesses（BSD-3）——"每技术一个验证 harness"的思路可借鉴（但公开开发已停滞）。
- 检测侧对照数据：Sigma 规则（DRL-1.1）作为被验证检测的样本输入，命中展示界面按 DRL 要求显示规则作者。
- 规避：endgameinc/RTA（AGPL-3.0 + 2019 年停更，双重否决）；Caldera 整机引入过重且 release 停在 2025-04，若参考仅借鉴其 stockpile ability 的 YAML 结构（Apache-2.0）。

### 总体架构结论
宿主选 Apache-2.0 是可行的，前提是把动作库分三层管理：嵌入层（MIT/Apache/BSD/MITRE 声明类，共 12+ 个对象）逐卡携带"来源仓库+commit+许可证"三元组；外部调用层（GPL/AGPL/LGPL/CC 对象，6 个）进程隔离、不解析或经法务确认口径；数据借鉴层（方法学文本与结构参考）。AGPL-3.0 备选能换来 SharpHound/Responder 的并入自由，但会显著抬高下游商用集成门槛，且换不来 Metasploit（其第三方混杂包两种宿主都不能整体嵌入）和 PEASS-ng（其自定义解释比许可证本身更严格）的安心使用——因此维持 Apache-2.0 首选、外部调用层隔离的路线。

## 三、待核实清单

1. ART 精确技术/测试条目数（GitHub API 限额耗尽，未能完成 atomics/ 目录计数）→ github.com/redcanaryco/atomic-red-team
2. Caldera 迁入 apache 组织后的 ASF 正式状态（是否 Incubator 池）及 2025-04 v5.3.0 之后的发版渠道 → github.com/apache/caldera/releases
3. BloodHound CE 最新 release 版本号（releases.atom 抓取连续失败）→ github.com/SpecterOps/BloodHound/releases
4. AtomicTestHarnesses 的 star 数与最近提交时间（查不到，API 限额）→ github.com/redcanaryco/AtomicTestHarnesses
5. SharpView 消失后的活跃社区 fork → github.com/dmejo/SharpView
6. PEASS-ng 输出中 ATT&CK ID 的覆盖范围（README 无陈述）→ github.com/peass-ng/PEASS-ng
7. Exploit-DB 官方 GitLab 归档确切位置 → offsec.com/blog/exploit-database-update
8. Metasploit LICENSE 中第三方组件明细（含 APSL 条款段归属）→ 仓库 LICENSE 文件
9. Legacy BloodHound（BloodHoundAD 组织）仓库现状
10. nuclei-templates 模板总数（README 无可核实计数）→ github.com/projectdiscovery/nuclei-templates
11. Caldera stockpile ability 总数 → github.com/apache/caldera
12. mimikatz 的 CC BY 4.0 对二进制再分发的适用性（CC 官方不推荐 CC 许可用于软件）→ github.com/gentilkiwi/mimikatz
13. Stratus Red Team 云技术清单条目数 → stratus-red-team.cloud/attack-techniques/list/

## 四、关键纠错（相对行业常见认知）

- mitre/caldera 已整体迁至 apache/caldera；
- 新版 SharpHound 是 GPL-3.0 而非 Apache-2.0（BloodHound CE 平台本身才是 Apache-2.0）；
- Impacket 现址在 Fortra，且是 Apache-1.1 改版；
- PayloadsAllTheThings 是 MIT（常见误传为 GPL）；
- PEASS-ng 自定义 COPYING 把"执行并解析输出"定义为衍生作品；
- mimikatz 是 CC BY 4.0（非 WTFPL）；LaZagne 是 LGPL-3.0（非 GPL-3.0）；
- Metasploit 主体为 BSD-3-clause（DEP-5 格式 + 第三方组件清单），GitHub API 因格式无法识别而显示 NOASSERTION；
- EDR 测试框架 RTA 是 endgameinc/RTA（AGPL-3.0，已停更 7 年），microsoft/RTA 并不存在。
