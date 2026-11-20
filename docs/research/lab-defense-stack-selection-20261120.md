# AI-native AEV 智能体"自带靶场"成熟方案选型调研报告

> 调研日期：2026-11-20。后台调研 agent 完成。
> 所有许可证均通过 GitHub API JSON、仓库 LICENSE 原文或官网页面实查确认；资源占用凡无官方数字的一律标"估算"。
> 注：项目暂无独立仓库，暂存会话附件区，仓库建立后迁入 docs/research/。

## 0. 结论速览

推荐"单机一链"组合（32GB 桌面机可跑全配）：

| 环节 | 选型 | 许可证 | 内存预算 |
|---|---|---|---|
| Web 入口（Docker） | DVWA（compose.yml 一条命令）+ juice-shop（官方镜像）+ VAmPI（API 测试） | GPL-3.0 / MIT / MIT | 约 0.5–1GB（估算） |
| API 进阶（可选） | crAPI | Apache-2.0 | 约 1.5–2GB（估算） |
| Linux 侧目标 | Metasploitable 2 VM | 免费（非标准 OSI 许可） | 256MB–512MB（官方口径） |
| AD 域环境 | GOAD-Light（3 VM，1 forest 2 domains） | GPL-3.0（项目本体）；Windows VM 为 180 天评估版 | 官方要求宿主 ≥20GB |
| 防守侧检测 | Windows VM 内装 Sysmon + sysmon-modular（MIT）→ Velociraptor（AGPL-3.0）内置 Sigma 引擎做命中判定；离线兜底 chainsaw/hayabusa 扫 EVTX | 见 C 节 | server 容器约 0.5–1GB（估算），客户端 200–300MB（官方数据） |
| 虚拟化/Docker 底座开销 | — | — | 约 2–3GB（估算） |
| 合计 | | | 约 24–27GB，32GB 机型可跑全配；16GB 必须降配 |

关键事实：GOAD-Light 官方最低 20GB、GOAD 完整版 24GB（官方安装文档原文）；SecurityOnion 最低 16GB、Wazuh 官方全装 8GiB、Elastic 更重——三者都不适合与 AD 靶场在同一台桌面机上共存，AEV 的命中判定应走 Velociraptor 内置 Sigma / 离线 Sigma 扫描路线，而不是塞一个 SIEM。

## A. Web/API 靶场素材

| 项目 | 许可证（实查） | 维护状态 | 漏洞覆盖 | compose 成熟度 | 资源占用 |
|---|---|---|---|---|---|
| Vulhub | MIT | 活跃：2026-07-22，21.2k stars | 按 CVE 组织的预构建环境（数百场景） | 每目录自带 docker-compose.yml，`docker compose up -d` 即起 | 估算 100–500MB/场景 |
| DVWA | GPL-3.0 | 活跃：2026-11-17，14.1k stars | SQLi/XSS/文件上传/RFI/LFI/命令注入/CSRF/暴力破解/弱会话/API 实验，含难度分级 | 很成熟：根目录 compose.yml（web+MariaDB），GHCR 预构建镜像，端口 4280 | 估算 200–400MB |
| WebGoat | GPL-2.0-or-later | 活跃：2026-11-09（OWASP Lab；旧仓库 OWASP/WebGoat 已自述 defunct，必须用新 org） | 课程制服务端漏洞教学 | 仓库无 compose（探测 404），官方单容器 docker run——compose 化需自己包一层 | 估算 500MB–1GB |
| crAPI | Apache-2.0 | 活跃：2026-11-09，1.6k stars | OWASP API Security Top 10（BOLA、认证缺陷、mass assignment） | 成熟：deploy/docker/docker-compose.yml（实查 200），多容器栈 | 估算 1.5–2GB |
| VAmPI | MIT | 推送 2026-04-07，1.4k stars（低频但稳定） | OWASP API Top 10：SQLi/BOLA/mass assignment/调试接口暴露/用户枚举/RegexDOS/弱 JWT；带 vulnerable=1/0 开关（可做假阴性对照） | compose 含双实例（安全 5001 / 不安全 5002），官方镜像 | Flask 单进程，估算 <100MB |
| Mutillidae II | GPL-3.0 | 主仓库 2026-09-24 更新；docker 仓库 2026-04-20 | OWASP Top 10 教学式覆盖 | 成熟且重：5 容器（Apache/PHP、MySQL、OpenLDAP、phpMyAdmin、PHPLDAPAdmin） | 估算约 1GB |
| juice-shop | MIT | 非常活跃：2026-11-20 当天仍有提交，14.5k stars，OWASP Flagship | OWASP Top 10 + 真实应用缺陷，100+ challenges，自带 CTF 模式 | 仓库内无 compose（4 个变体全 404 实查），官方单容器镜像 docker run 一行即起 | 估算 200–500MB |

建议取舍：全收。DVWA + juice-shop 做"Web 入口主机"，VAmPI（或 crAPI）做"API 入口"。均作独立容器运行。

## B. 内网/AD 靶场

### GOAD（Orange-Cyberdefense/GOAD）— 首选
- GPL-3.0；8.6k stars；最近推送 2026-10-23，活跃维护。
- 规格：GOAD 5VM/2forest/3domains；GOAD-Light 3VM/1forest/2domains（小机器）；MINILAB 2VM（1×Server2019 DC + 1×Win10）；另有 SCCM/NHA/DRACARYS。
- 资源（官方原文）：内存 "at least 20GB for GOAD-Light and 24GB for GOAD"（指宿主总内存）；磁盘 VM 镜像总计约 115GB（视 lab 与快照）。
- 许可注意（README 原文）："This lab use free Windows VM only (180 days)"——Windows 评估版，到期重装或换 key；ISO 按官方指引自行下载，不可再分发——因此"一条命令拉起"在 AD 环节做不到全自动（首次部署需人工下 ISO）。
- provider：VirtualBox（vagrant ≤7.1.x）、VMware、Proxmox、AWS/Azure、Ludus。
- 16–32GB 结论：GOAD 完整版在 32GB 机器上偏紧；GOAD-Light（20GB）是 32GB 机器现实上限（含宿主全部负载口径）。16GB 只能 MINILAB 或自组单 DC（估算 6–8GB，待核实）。
- WSL2 注意（社区结论，GOAD issue #38）：WSL2 内跑 KVM/libvirt 仅 Intel CPU 可行，AMD 基本不可用；建议 Windows 宿主直接 VMware/VirtualBox。

### Metasploitable 3（rapid7/metasploitable3）
- BSD-3-clause（LICENSE 实查，含第三方 MIT 清单）。要求 4.5GB RAM / 65GB 磁盘；两 VM（Win2008R2 + Ubuntu 14.04）；预构建 Vagrant box 提供。
- 最近推送 2025-02-13，维护放缓；Win2008 靶机过时，对"现代 EDR 检测验证"价值有限。

### Metasploitable 2
- 免费用于安全训练/测试（Rapid7 文档表述，非标准 OSI 许可——再分发需法务确认）。Ubuntu 8.04 基底。内存约 256MB（推荐 512MB），Linux 侧最轻靶机。无官方 Vagrant box（社区第三方 box 未经认证，待核实）。

### Vulnlab — 已退役（重要更新）
- 官网实查："Vulnlab is retired as of March 2026. New signups are no longer possible. All content is available on Hack The Box."曾是付费订阅平台。从组合中排除。

### 其他活跃 AD 实验环境
| 项目 | 许可证 | 状态 | 说明 |
|---|---|---|---|
| safebuffer/vulnerable-AD | MIT | 2347 stars，2024-04 后放缓 | 在既有 DC 上一键注入 14 类常见 AD 错配——降配方案核心组件 |
| davidprowe/BadBlood | GPL-3.0 | 2023-06 停更 | 给 DC 灌注海量域对象制造真实规模 |
| clong/DetectionLab | MIT | 2023-03 实质停更 | Packer+Vagrant AD+Splunk/Fleet/Velociraptor；可抄配方不建议依赖维护 |
| badsectorlabs/ludus | AGPL-3.0 | 非常活跃 2026-11-19 | 靶场自动化编排器（Proxmox 底座），GOAD 官方 provider；商用条款待核实 |
| mvelazc0/PurpleSharp | BSD-3-Clause | 主流 AD 攻击模拟器 | C#，AD 内生成攻击遥测——AD 环节攻击执行引擎优选 |
| mitre/caldera | Apache-2.0 | 活跃度待核实 | 平台化攻击编排可选；单机轻量场景 ART+PurpleSharp 已够 |

内存直接回答：16GB 跑不通 GOAD 正式版/Light；可跑 MINILAB/单 DC（6–8GB 估算）+Web 容器+Msf2+离线检测链。32GB：GOAD-Light+Web 容器+Msf2+Velociraptor ≈24–27GB，可行但接近上限。

## C. 防守侧检测栈（AEV 关键）

| 组件 | 许可证 | 最近提交 | 资源 | 角色 |
|---|---|---|---|---|
| Sysmon（微软） | 免费专有二进制（EULA 限制再分发——让用户自取） | 随微软更新 | 极低 | 受害端遥测采集 |
| SwiftOnSecurity/sysmon-config | CC BY 4.0 | 2021-10 后停更 | — | 不推荐（有替代） |
| olafhartong/sysmon-modular | MIT | 活跃 2026-10-14，3.2k stars | 极低 | 推荐采用：模块化 Sysmon 配置 |
| Velociraptor | AGPL-3.0（Rapid7 托管） | 非常活跃 2026-11-20，v0.77.3 | server 容器 0.5–1GB（估算），客户端 Sigma 匹配 200–300MB（官方） | 推荐核心：采集+内置 Sigma 引擎+命中判定 |
| SigmaHQ/sigma | 规则 DRL-1.1；规范公有领域 | 非常活跃 2026-11-18 | — | 检测规则源（官方 README：3000+ 条） |
| SigmaHQ/pySigma | LGPL-2.1 | 活跃 2026-11-09 | 极低 | Sigma 编译/转换库 |
| WithSecureLabs/chainsaw | GPL-3.0 | 活跃（3.7k stars） | 极低（CLI） | 离线 EVTX+Sigma 命中扫描 |
| Yamato-Security/hayabusa | AGPL-3.0 | 活跃 2026-11-10 | 端点扫描约 1–2GB（官方对比数据） | 离线扫描备选（规则更全但更耗内存） |
| atomic-red-team | MIT | 活跃 2026-11-06 | 极低 | 攻击执行：ATT&CK 映射原子测试库 |
| Wazuh | 主体 GPLv2（引擎部分 AGPL-3.0，部分双许可） | 非常活跃 | 官方 quickstart 全装 4vCPU/8GiB/50GB | 可选 SIEM；与 AD 靶场同机偏重 |
| SecurityOnion | Elastic License 2.0（非 OSI） | 活跃 2026-11-02 | standalone 最低 16GB/4核/200GB，推荐 24GB | 排除：太重且 ELv2 再分发受限 |
| Elastic Stack + detection-rules | ES：AGPLv3/SSPL/ELv2 三选一；detection-rules：ELv2 | 非常活跃 | 4–8GB 起（估算） | 不推荐进桌面靶场 |
| falcosecurity/falco | Apache-2.0 | 活跃 2026-11-06 | 低，原生 compose | Linux 容器侧运行时检测（可选补强） |
| sbousseaden/EVTX-ATTACK-SAMPLES | GPL-3.0 | 2023-01（静态样本库） | 零 | 离线预验证：约 200 个按 ATT&CK 归类的 EVTX 样本+回放工具，不启动靶场即可回归检测规则 |

### 最轻量且许可证兼容的组合（推荐）
```
Windows 受害 VM：Sysmon（微软自取）+ sysmon-modular（MIT）
        ↓ EVTX
判定路径一（在线，推荐）：Velociraptor（AGPL-3.0，官方 GHCR 镜像）
  · Server.Import.CuratedSigma 导入 SigmaHQ/Hayabusa 精选规则
  · 内置 sigma() VQL 引擎 + Windows.Sigma.EventLogs 工件：
    规则同步到端点 → 端点解析 EVTX → 仅命中事件回传 server（按 Critical/High/Medium 分级）
  · Client Monitoring 事件查询 = 实时命中告警（官方示例：实时抓到 PSExec）
判定路径二（离线兜底，零常驻内存）：导出 EVTX → chainsaw（GPL-3.0）或 hayabusa（AGPL-3.0）
  按 Sigma 规则扫描 → JSON 命中列表
```

### "攻击证据 → 检测命中判定"的成熟做法（现成联动）
1. Join key = ATT&CK 技术编号。ART 每个测试带 ATT&CK 映射（MIT）；SigmaHQ 规则带 attack.tXXXX tag；两边按技术编号对齐即可生成"测试↔规则↔命中"证据链。社区公认模式（atomicredteam.io/built-on-atomic 页面专门列出基于 ATT&CK+SigmaHQ+pySigma+ART 构建的检测工程平台）。
2. Velociraptor 内置 Sigma 是现成判定引擎（sigma.velocidex.com 官方文档）：sigma_log_sources() 做 logsource→EVTX 映射、sigma() 插件匹配、Server.Import.CuratedSigma 一键导入；官方数据：Velociraptor 引擎比 Hayabusa 快约 5 倍、内存 200–300MB vs 1–2GB。
3. 离线静态预检：EVTX-ATTACK-SAMPLES 让部署靶场前就能批量回归检测规则。
4. ATT&CK Navigator 覆盖层自动生成工具：存在此类生态工具但未核实到维护中的仓库——待核实。
5. AD 专属攻击执行：PurpleSharp（BSD-3）比 ART 覆盖更深的 AD 横向技术；进阶可用 Caldera 编排。

### 许可证兼容性提示（宿主 Apache-2.0 视角）
- 可直接集成/分发：MIT/Apache/BSD 系（ART、sysmon-modular、VAmPI、juice-shop、Vulhub、crAPI、Falco、PurpleSharp、Caldera）。
- 可容器化独立运行，但不宜与宿主代码链接：GPL/AGPL 系（DVWA、WebGoat、Mutillidae、GOAD、BadBlood、chainsaw、hayabusa、Velociraptor、Wazuh、Ludus）。独立容器/VM 由用户拉起一般不构成衍生作品，但"产品整体打包分发镜像"需法务确认。
- 条件可用：SigmaHQ 规则 DRL-1.1（MIT 基底：允许商用与修改，但必须署名规则作者，且展示命中结果时必须显示作者——证据报告里带规则作者字段，反而符合证据链需求）。
- 避开或隔离：SecurityOnion 与 elastic/detection-rules（ELv2）；Sysmon 二进制与 Windows 评估版 ISO（专有，用户自取，不可捆绑分发）。

## 1. 一链组合（32GB 档）

| 环节 | 组件 | 内存 |
|---|---|---|
| Web 入口 | DVWA + juice-shop | 约 0.5–1GB（估算） |
| API 入口 | VAmPI（可换 crAPI +1.5GB） | 约 0.1GB（估算） |
| Linux 目标 | Metasploitable 2 | 0.5GB（官方口径） |
| AD 域 | GOAD-Light（3VM：2 DC + 1 域内机器） | 官方宿主总要求 ≥20GB |
| 检测栈 | Velociraptor server 容器 + 受害 VM 内 Sysmon/agent | 约 0.5–1GB（估算）+ 端点 200–300MB/台（官方） |
| 底座 | Docker Desktop/WSL2 + 虚拟化开销 | 约 2–3GB（估算） |
| 合计 | | 约 24–27GB，32GB 可跑需留神峰值 |

配套攻击侧：ART（MIT）跑 Windows 技术 + PurpleSharp（BSD-3）跑 AD 横向；证据链 = ART/PurpleSharp 测试编号 ↔ Sigma tag ↔ Velociraptor 命中记录。

"一条命令"的现实边界（如实说明）：Web/API/Linux 检测容器可纯 docker compose 一条命令；AD 环节必须落 VM 层（vagrant + VirtualBox/VMware，或 Proxmox+Ludus），GOAD 首次部署需人工下载 Windows 评估版 ISO（许可不允许预分发）——这是开源组合无法消除的硬约束。

## 2. 降配备选（16GB 档）

- 砍：GOAD-Light、Wazuh/Elastic/SecurityOnion、crAPI、Mutillidae、SCCM/第二域。
- 留：AD 用 GOAD MINILAB（2VM，估算 6–8GB 待核实）+ vulnerable-AD（MIT）注入错配，规模感可用 BadBlood 灌注；Web 用 VAmPI+DVWA（约 0.5GB）；Linux 用 Metasploitable 2（0.5GB）；检测走离线链零常驻（Sysmon→EVTX→chainsaw/hayabusa 按需扫）或 Velociraptor 单容器（约 1GB）。合计估算 8–10GB + 宿主，16GB 机型可跑。
- Samba AD DC 可替代部分域控功能，但不产生 Windows EVTX 遥测，AEV 的"检测命中"环节对 AD 技术将不可用——不推荐作为默认。

## 3. 待核实清单

1. GOAD MINILAB 官方内存数字（文档未标，6–8GB 为估算）。
2. 各 Web 靶场容器实测内存（均为估算，无官方数字）。
3. Metasploitable 2 再分发许可细节（"free for training/testing"，非标准 OSI）。
4. Velociraptor server 在 3–5 客户端小规模下的官方最低资源。
5. Sigma 规则 → ATT&CK Navigator 覆盖层生成工具的活跃仓库。
6. Ludus 开源核心与商业授权的边界。
7. Caldera 最近提交日期。
8. WSL2 内跑 GOAD（libvirt）在 Intel 机器上的最新可行性反馈（社区结论截至 2025：Intel 可、AMD 不可）。

主要来源：GitHub API / 各仓库 LICENSE 原文；GOAD 官方文档站 installation/windows 与 labs 页；Metasploitable 3 README 与 LICENSE；Rapid7 Metasploitable 2 官方文档；vulnlab.com 官网（退役声明）；Wazuh quickstart 硬件表；SecurityOnion 官方 hardware 文档；sigma.velocidex.com/docs/sigma_in_velociraptor；docs.velociraptor.app（0.77.3、Docker 部署）；SigmaHQ README 与 DRL-1.1 许可文件；atomicredteam.io/built-on-atomic；GOAD issue #38 及社区讨论（WSL2 嵌套虚拟化）。
