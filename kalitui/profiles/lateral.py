"""内网横向移动知识库（lore-only 档案，白帽内网/域渗透场景）。

不注册工具——对话命中"横向/内网/pivot"等场景时，注入横向移动
技术路线深度知识。
"""

from __future__ import annotations

from typing import Any

from .base import ToolProfile

LATERAL_LORE = """### 内网横向移动路线（拿到第一台机器后的推进顺序）

#### 0. 纪律
- 每步操作都在授权范围内（scope 守卫会确认目标）；最小证明、不破坏。
- 横向移动的关键是**凭证与可达性**，不是盲扫——先梳理已有什么再决定怎么走。

#### 1. 信息收集（先看清内网）
- 本机网络：`ip a` / `ip route` / `cat /etc/hosts` / `arp -a`——画内网拓扑
- 域环境：`net user /domain`、`net group "domain admins" /domain`、`dsquery`
  （Kali 侧用 ldap_enum / enum4linux 从外网视角枚举）
- 已拿到的机器上：`history`、`.ssh/`、配置文件、浏览器凭证——**凭证优先**

#### 2. 凭证收集（横向移动的燃料）
- 本机 hash：impacket `secretsdump`（SAM/LSA）、mimikatz（有则用，注意杀软）
- 共享/缓存：`reg query HKLM\\SECURITY`、`cmdkey /list`、`vaultcmd`
- 域凭证：Kerberoasting（kerberoast 工具）、AS-REP Roasting（asrep_roast）、
  密码喷洒（hydra 慢速，注意锁定策略）
- 拿到 hash 后：PTH（pass-the-hash）——impacket smbexec/wmiexec/atexec 都支持 -hashes

#### 3. 横向执行（按协议挑）
- SMB：smbexec / wmiexec / psexec（445 通优先）——已定制 imp_exec
- WinRM：evil-winrm（5985/5986，支持 PTH）——已定制 winrm_exec
- RDP：xfreerdp / rdesktop（有图形时）
- SSH 密钥复用：拿到的 id_rsa 直接试其他主机
- 服务滥用：Redis 未授权写计划任务、docker API 未授权、NFS 可写挂载

#### 4. 隧道与 Pivot（网络不可达时）
- chisel（已定制）：reverse/forward/SOCKS5，HTTP 隧道过防火墙
- socat（已定制）：端口转发/桥接
- SSH 动态转发：`ssh -D 1080 root@跳板机`（本地代理进内网）
- 内网扫描统一走隧道：nmap -Pn -sT（无 ICMP 时）——小心速度，慢速优先

#### 5. 域控之路（最终目标）
- 收集域管会话：`findstr /si password *.txt` 之类 + 凭证复用
- 域管 hash → PTH 到域控 → secretsdump NTDS.dit 全量凭证
- 拿域控后：立即停止横向扩展，向用户汇报并生成报告（不要大范围破坏）"""


class LateralProfile(ToolProfile):
    name = "lateral"
    aliases = [
        "横向", "横向移动", "内网", "内网渗透", "lateral", "lateral movement",
        "pivot", "隧道", "跳板", "域渗透", "pass the hash", "pth", "pth 攻击",
        "域控", "ntds", "mimikatz", "内网代理",
    ]
    summary = "横向移动知识库（内网/域渗透场景按需注入）"
    lore = LATERAL_LORE
    extra_schemas: list[dict[str, Any]] = []

    # 纯 lore 档案：没有可注册的工具
    def register(self, executor: Any) -> None:
        return
