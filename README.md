# KaliTUI — AI 驾驭 Kali 的终端渗透 Agent

[![tests](https://img.shields.io/badge/tests-116%20passed-brightgreen)](https://github.com/Kunspring/DeepKali)
[![tools](https://img.shields.io/badge/tools-48%20%E4%B8%93%E7%94%A8-8A2BE2)](https://github.com/Kunspring/DeepKali)
[![Python](https://img.shields.io/badge/Python-3.13-blue)]()
[![Kali](https://img.shields.io/badge/Kali-2026.1-blue)]()
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> 在终端里和 AI 对话，AI 直接调用你的 Kali 工具——从 nmap 扫描到 impacket 横向，
> 45 个 Kali 常用工具**逐个深度定制**，一个界面完成整个渗透测试工作流。

```
┌ KaliTUI — AI 驾驭 Kali ───────────────────────────────┐
│ 💬 对话                    │ 🛠 工具执行               │
│ 你 扫描一下 127.0.0.1      │ ▶ run_command {nmap -F …}│
│ 🤔 agent 思考中…           │ ✔ run_command 完成        │
│ 🛠 调用 run_command         │ Starting Nmap 7.95 …     │
│ KaliTUI 目标 22/tcp open…  │ 22/tcp  open  ssh         │
│ ⚠ 危险操作确认             │                          │
│  爆破/口令攻击工具          │                          │
│  [hydra -l admin …]        │                          │
│   ✖ 拒绝        ✔ 允许     │                          │
└────────────────────────────────────────────────────────┘
```

## 📌 项目亮点

- **真·工具调用循环**：AI 自主决定调用工具，观察结果后继续，直到完成任务
- **Kali 工具逐个深度定制**（`kalitui/profiles/`）：每个常用工具一个专属档案——
  参数化专用工具（输入校验、防注入、自动摘要输出）+ 深度使用 lore 按需注入提示词
- **工具联动流水线**：`recon_pipeline` 一条命令完成"存活探测 → 版本扫描 → 工具链建议"
- **三层安全模型**：命令静态分级 + 确认弹窗 + 参数白名单防注入
- **兼容任意 OpenAI 风格 API**：DeepSeek / OpenAI / Ollama / 各类网关
- **无 API 也能玩**：Demo 模式用脚本大脑驱动真实工具执行
- **116 个自动化测试**：每个档案都有独立测试，全量 8 秒跑完

---

## 🧰 工具档案总览（45 档案 / 48 工具）

### 侦察与信息收集

| 工具 | 档案 | 说明 |
|---|---|---|
| `recon_pipeline` | playbook | **联动流水线**：存活探测→版本扫描→按端口自动生成工具链建议 |
| `nmap_scan` | nmap | 6 种模式：主机发现 / 快速 / 版本 / 全面 / UDP / 全端口 |
| `net_discover` | netdiscover | ARP 主机发现，主动 / 被动（隐蔽）模式 |
| `hping_probe` | hping3 | SYN/ACK/FIN/ICMP 主动探测（无洪水能力） |
| `osint_gather` | theHarvester | 12 个数据源子域/邮箱收集（crtsh 默认最快） |
| `dns_recon` | dnsrecon | 标准查询 / 子域爆破 / 区域传送 |

### 服务枚举

| 工具 | 档案 | 说明 |
|---|---|---|
| `smb_enum` | enum4linux | SMB 信息枚举：用户/共享/组/密码策略 |
| `smb_map` | smbmap | 共享枚举与递归文件浏览（支持 C$/ADMIN$） |
| `smb_ls` | smbclient | 共享目录浏览，域凭据安全引用 |
| `ldap_enum` | ldapsearch | 域目录枚举（过滤器/属性/绑定校验） |
| `smtp_enum` | smtp-user-enum | SMTP 用户枚举 VRFY/EXPN/RCPT |
| `ftp_check` | ftp | FTP 匿名/凭据检查 |
| `redis_check` | redis-cli | Redis 未授权访问检查 |

### Web 应用

| 工具 | 档案 | 说明 |
|---|---|---|
| `http_req` | curl | HTTP 请求：6 种方法/多头/cookie/响应摘要 |
| `nikto_scan` | nikto | Web 服务器漏洞扫描 |
| `dir_brute` | gobuster | 目录枚举，状态码过滤 |
| `ffuf_dir` | ffuf | 高速模糊测试，扩展名矩阵 |
| `wfuzz_fuzz` | wfuzz | 字典模糊测试（Python 侧状态码过滤） |
| `wpscan_scan` | wpscan | WordPress 漏洞扫描 |
| `sqlmap_check` | sqlmap | SQL 注入自动检测（level/risk/cookie） |
| `nuclei_scan` | nuclei | 模板化漏洞扫描 |
| `waf_detect` | wafw00f | WAF 识别 |
| `ssl_scan` | sslscan | TLS 协议/套件/证书弱点 |
| `tls_deep` | testssl.sh | 深度 TLS 检测（Heartbleed/POODLE 等攻击向量） |
| `cewl_words` | cewl | 网站词表生成（配合 hydra） |

### 利用与口令

| 工具 | 档案 | 说明 |
|---|---|---|
| `msf_search` / `msf_run` | msfconsole | Metasploit 非交互搜索与执行（后台防挂起） |
| `payload_gen` | msfvenom | payload 生成（白名单+路径限制） |
| `sploit_search` / `sploit_show` | searchsploit | 本地 ExploitDB |
| `hydra_brute` | hydra | 在线口令爆破（服务表单定制，命中即停） |
| `crack_hash` | john/hashcat | 离线破解，hash 临时文件化防注入 |
| `hash_id` | hashid | hash 类型识别（输出 hashcat 模式号） |
| `wifi_crack` | aircrack-ng | WPA 握手包离线破解 |

### 横向移动与域渗透

| 工具 | 档案 | 说明 |
|---|---|---|
| `imp_exec` | impacket | smbexec/wmiexec/atexec 三合一远程执行（支持 PTH） |
| `winrm_exec` | evil-winrm | WinRM 远程执行（支持 PTH） |
| `secrets_dump` | impacket | SAM/LSA/NTDS 凭据提取 |
| `kerberoast` | GetUserSPNs | Kerberoasting（需域凭据） |
| `asrep_roast` | GetNPUsers | AS-REP Roasting（无需凭据可试） |
| `responder_analyze` | responder | LLMNR/NBT-NS 流量分析模式 |
| `chisel_tunnel` | chisel | HTTP 隧道（reverse/forward/SOCKS5） |

### 网络与无线

| 工具 | 档案 | 说明 |
|---|---|---|
| `nc_listen` / `nc_connect` | netcat | 监听/连接，数据防注入，-q 自动退出 |
| `socat_tunnel` | socat | 端口转发/数据桥接 |
| `tcpdump_capture` | tcpdump | 限时/限数量抓包，BPF 过滤校验 |
| `tshark_capture` | tshark | 协议级抓包（HTTP/SMB 一目了然） |
| `wifi_monitor` | airmon-ng | 无线监控模式管理 |
| `mac_change` | macchanger | MAC 查看/修改/随机 |

---

## 🗺 渗透测试工作流（Mermaid 流程图）

一条 `recon_pipeline` 起手，按开放端口自动分流到对应工具链：

```mermaid
graph TD
    A["🎯 目标 / recon_pipeline"] --> B["nmap 存活+版本扫描"]
    B --> C{"开放端口?"}
    C -->|"21/22/25/3306"| D["hydra_brute 口令爆破"]
    C -->|"80/443/8080"| E["http_req 指纹"]
    E --> F["nikto_scan / dir_brute / ffuf_dir"]
    F --> G{"WAF?"}
    G -->|"是"| H["waf_detect 识别后绕过"]
    G -->|"否"| I["sqlmap_check 注入检测"]
    C -->|"139/445"| J["smb_enum / smb_map"]
    J --> K["smb_ls 浏览共享"]
    K --> L["hydra_brute SMB 弱口令"]
    C -->|"389/636/88"| M["ldap_enum 域枚举"]
    M --> N["kerberoast / asrep_roast 域提权"]
    C -->|"5985/5986"| O["winrm_exec 远程执行"]
    C -->|"6379"| P["redis_check 未授权"]
    I --> Q["💥 拿权限 / secrets_dump / imp_exec 横向"]
    N --> Q
    O --> Q
```

## 🎬 典型攻击链（一句话 → 一串工具）

| 场景 | 工具链 |
|---|---|
| 内网横向 | `net_discover` 找主机 → `nmap_scan` 扫端口 → `smb_enum` 枚举 → `hydra_brute` 爆破 → `imp_exec` 远程执行 |
| Web 打点 | `osint_gather` 找资产 → `http_req` 指纹 → `ffuf_dir` 挖路径 → `sqlmap_check` 注入 → `payload_gen` 生成马 → `nc_listen` 收 shell |
| 域渗透 | `ldap_enum` 枚举 → `asrep_roast`/`kerberoast` 拿 hash → `crack_hash` 离线破解 → `secrets_dump` 提权 → `chisel_tunnel` 内网穿透 |
| 口令闭环 | `cewl_words` 生成词表 → `hash_id` 识别类型 → `crack_hash` 破解 → `hydra_brute` 撞其他服务 |
| 无线评估 | `wifi_monitor` 开监控模式 → `mac_change` 伪装 → `airodump` 抓握手（run_command）→ `wifi_crack` 破解 |

> 💡 所有链条中的危险步骤（hydra/sqlmap/impacket 等）都会触发安全确认弹窗——**流程自动，授权人工**。

---

## 🛡 安全模型（三层）

### 第一层：命令静态分级（`kalitui/safety.py`，30+ 规则）

| 级别 | 行为 | 典型规则 |
|---|---|---|
| `safe` | 自动执行 | 常规命令、文件操作 |
| `confirm` | 弹窗确认 | `hydra` / `sqlmap` / `msfvenom` / `impacket-*` / `nc` / `socat` / `wfuzz` / `airmon-ng` / `macchanger` / `redis-cli` / `ftp` / `smtp-user-enum` / `chisel` / `responder` 等 |
| `blocked` | 默认拒绝 | 删除/覆盖/格式化等破坏性命令，可「强制」放行 |

弹窗里可以**编辑命令**后再放行；策略可切换 `ask / always_allow / always_block`。

### 第二层：参数白名单校验（每个档案的 `_build_cmd`）

- 目标/URL/端口/字典路径全部正则校验，非法立即拒绝
- 危险字符（`; | & \` $ () {}` 等）注入黑名单

### 第三层：Shell 引用防拆分

实战中抓到的注入点全部 `shlex.quote` 修复：

- wfuzz cookie（`-b x;rm` → bash 拆词执行）
- tshark BPF 过滤（空格拆分参数）
- hashid 的 `$6$`（bash 变量展开吞掉 hash！）
- sqlmap cookie（`PHPSESSID=...; security=low` 被拆成两条命令）
- URL query 的 `&`（sanitize_url 增加 `allow_query` 模式 + 强制引用）
- hydra 表单串 / smbclient 域凭据

---

## 🚀 安装

```bash
git clone https://github.com/Kunspring/DeepKali.git
cd kalitui
./install.sh        # 创建 venv、装依赖、生成 ~/.local/bin/kalitui
export KALITUI_API_KEY=sk-你的key
kalitui
```

也可以手动：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m kalitui
```

## ⚙️ 配置

优先级：环境变量 > 配置文件 > 默认值。

| 环境变量 | 说明 | 默认 |
|---|---|---|
| `KALITUI_API_KEY` | API key（必填，否则进 demo 模式） | — |
| `KALITUI_BASE_URL` | OpenAI 兼容 API 地址 | `https://api.deepseek.com/v1` |
| `KALITUI_MODEL` | 模型名 | `deepseek-chat` |
| `KALITUI_DEMO` | `1` 强制 demo 模式 | 自动 |
| `KALITUI_WORKDIR` | agent 工作目录 | 当前目录 |

首次运行后生成 `~/.config/kalitui/config.json` 持久配置，可直接编辑。
命令行参数：`kalitui --model deepseek-reasoner --danger always_allow --demo`。

## 💬 使用

- 输入消息回车，AI 自主调用工具完成任务
- `/help` 命令列表 · `/clear` 清屏 · `/new` 重置会话 · `/danger` 查看/设置策略 ·
  `/model` 显示模型 · `/quit` 退出
- `Ctrl+C` 中断当前任务 · `q` 退出 · `Ctrl+L` 清空工具输出面板

**示例对话**（需配置 API key）：

```
> 扫描本机，告诉我开了哪些端口
> 对 10.0.0.5 跑一遍完整侦察流程
> 看看 /etc/ssh/sshd_config 有什么可疑配置
> 爆破测试（体验危险命令确认弹窗）
```

## 🎯 真实靶场验证（DVWA）

本项目的工具链在真实靶场 DVWA v1.10（Docker）上全流程验证过：

| 阶段 | 工具 | 战果 |
|---|---|---|
| 侦察 | `recon_pipeline` | 识别 Apache 2.4.25 (Debian) + 工具链建议 |
| 指纹 | `http_req` | 带 cookie/query 访问注入页成功 |
| 枚举 | `dir_brute` / `ffuf_dir` | 发现 phpinfo.php、php.ini 暴露 |
| 注入 | 手工 `http_req` | `id=1'` 报错 → UNION 拖出 admin MD5 |
| 注入 | `sqlmap_check` | 布尔/报错(EXTRACTVALUE)/时间盲注(SLEEP) 全部确认 |
| 爆破 | `hydra_brute` | MySQL 命中 `app:vulnerables` |

靶场实战抓出并修复 4 个真实 bug（见安全模型第三层）。

---

## 🏗 架构

```
kalitui/
├── kalitui/
│   ├── app.py        # Textual TUI：双面板、确认弹窗、斜杠命令、状态栏
│   ├── llm.py        # Agent：OpenAI 兼容客户端 + 工具调用循环 + 档案动态注入
│   ├── tools.py      # 工具执行器：bash 子进程、进程组管理、审批回调、扩展挂载
│   ├── safety.py     # 命令安全分级（正则规则库）
│   ├── prompts.py    # Kali 系统提示词
│   ├── demo.py       # 无 API 的脚本大脑（演示/测试）
│   ├── config.py     # 配置加载与持久化
│   └── profiles/     # 深度定制工具档案（每个工具一个文件）
│       ├── base.py       # 档案基类 + 参数校验/防注入工具
│       ├── __init__.py   # 注册表：schema 合并、执行器挂载、按需 lore
│       ├── nmap.py       # nmap_scan
│       ├── msf.py        # msf_search / msf_run
│       ├── nikto.py      # nikto_scan
│       ├── gobuster.py   # dir_brute
│       ├── searchsploit.py # sploit_search / sploit_show
│       ├── hydra.py      # hydra_brute
│       ├── sqlmap.py     # sqlmap_check
│       ├── crack.py      # crack_hash（john/hashcat）
│       ├── wpscan.py     # wpscan_scan
│       ├── enum4linux.py # smb_enum
│       ├── smbmap.py     # smb_map
│       ├── dnsrecon.py   # dns_recon
│       ├── ffuf.py       # ffuf_dir
│       ├── aircrack.py   # wifi_crack
│       ├── msfvenom.py   # payload_gen
│       ├── tcpdump.py    # tcpdump_capture
│       ├── nuclei.py     # nuclei_scan
│       ├── responder.py  # responder_analyze
│       ├── evilwinrm.py  # winrm_exec
│       ├── netcat.py     # nc_listen / nc_connect
│       ├── smbclient.py  # smb_ls
│       ├── ldapsearch.py # ldap_enum
│       ├── secretsdump.py# secrets_dump
│       ├── chisel.py     # chisel_tunnel
│       ├── getnpusers.py  # asrep_roast
│       ├── getuserspns.py # kerberoast
│       ├── socat.py       # socat_tunnel
│       ├── tshark.py      # tshark_capture
│       ├── hping3.py      # hping_probe
│       ├── impexec.py     # imp_exec
│       ├── wfuzz.py       # wfuzz_fuzz
│       ├── netdiscover.py # net_discover
│       ├── airmon.py      # wifi_monitor
│       ├── macchanger.py  # mac_change
│       ├── curl.py        # http_req
│       ├── sslscan.py     # ssl_scan
│       ├── wafw00f.py     # waf_detect
│       ├── redis.py       # redis_check
│       ├── ftp.py         # ftp_check
│       ├── theharvester.py# osint_gather
│       ├── testssl.py     # tls_deep
│       ├── smtpenum.py    # smtp_enum
│       ├── hashid.py      # hash_id
│       ├── cewl.py        # cewl_words
│       └── playbook.py    # recon_pipeline 联动编排
└── tests/            # 116 个测试：安全分级、工具、agent 循环、档案、headless TUI
```

### 新增一个工具档案

在 `kalitui/profiles/` 下新建 `xxx.py`，继承 `ToolProfile`，三步完成：

```python
from .base import ToolProfile, check_installed, sanitize_int

class XxxProfile(ToolProfile):
    name = "xxx"
    aliases = ["xxx", "别名1", "别名2"]        # lore 按需注入的匹配词
    summary = "一句话说明"
    lore = """### xxx 深度使用要点
- 工具定位与使用场景
- 输出解读与下一步建议"""
    extra_schemas = [ { "type": "function", "function": { "name": "xxx_run", ... } } ]

    async def exec_xxx_run(self, ex, args):
        if not check_installed("xxx"): return "xxx 未安装"
        cmd, timeout = _build_cmd(args)       # 参数校验 + 命令构造
        raw = await self._run(ex, cmd, timeout=timeout)   # 复用安全审批/超时/进程组
        return _summarize(raw)                # 关键结果摘要
```

在 `profiles/__init__.py` 的 `REGISTRY` 加一行，Agent/TUI 自动生效。

## 🧪 开发与测试

```bash
.venv/bin/python -m pytest tests/ -q        # 116 passed in ~8s
```

测试覆盖：安全分级规则、工具命令构造与注入防护、agent 工具循环、档案注册表与 lore
匹配、headless TUI 渲染。每个工具档案都有独立测试文件（`tests/test_profiles1-10.py`）。

## ⚠️ 安全与免责声明

- 危险命令在**执行前**静态分级；弹窗确认后才执行，且可在弹窗中改写命令
- 安全层只做静态匹配，无法防住所有情况——**请只在自己的机器/授权目标上使用**
- 对**外部目标**的扫描/攻击，提示词要求 AI 先向用户确认授权范围
- 本项目仅供安全研究、教学与授权测试使用，使用者须遵守当地法律法规

## 📄 License

MIT
