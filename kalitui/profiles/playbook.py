"""playbook 深度定制：多工具联动侦察流水线（收官编排）。

把已定制的工具串成自动化流程：
1. ping 探测存活
2. nmap 版本扫描（top 端口）
3. 按开放端口/服务自动生成"工具链建议清单"
4. 汇总输出（危险工具只建议、不自动执行，由用户/agent 确认后逐步调用）
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_ports, sanitize_target
from .nmap import _build_cmd as nmap_build_cmd, re_search_port

# 服务关键词 → 建议工具链（按渗透流程排序）
_SERVICE_PLAYBOOK: dict[str, list[str]] = {
    "ssh": ["hydra_brute（ssh 弱口令）"],
    "ftp": ["ftp_check（匿名/凭据）", "hydra_brute（ftp 弱口令）"],
    "smtp": ["smtp_enum（用户枚举）", "hydra_brute（smtp 弱口令）"],
    "pop3": ["hydra_brute（pop3 弱口令）"],
    "imap": ["hydra_brute（imap 弱口令）"],
    "telnet": ["hydra_brute（telnet 弱口令）"],
    "http": ["http_req（看内容/指纹）", "nikto_scan（漏洞）", "dir_brute（目录）", "ffuf_dir（深挖）", "waf_detect（WAF）", "nuclei_scan（模板）"],
    "https": ["http_req -k（看内容）", "ssl_scan（TLS 配置）", "tls_deep（深度 TLS）", "nikto_scan", "dir_brute", "waf_detect", "nuclei_scan"],
    "ssl/http": ["http_req -k", "ssl_scan", "nikto_scan", "dir_brute", "waf_detect"],
    "ssl/ldap": ["ldap_enum（LDAPS）"],
    "ldap": ["ldap_enum（目录枚举）"],
    "netbios-ssn": ["smb_enum（SMB 枚举）"],
    "microsoft-ds": ["smb_enum（用户/共享）", "smb_map（共享内容）", "smb_ls（目录浏览）", "hydra_brute（smb 弱口令）"],
    "mysql": ["hydra_brute（mysql 弱口令）"],
    "mssql": ["hydra_brute（mssql 弱口令）"],
    "postgresql": ["hydra_brute（postgres 弱口令）"],
    "redis": ["redis_check（未授权检查）"],
    "ms-wbt-server": ["提示：RDP 3389，弱口令用 hydra（rdp），或检查 NLA"],
    "winrm": ["winrm_exec（凭据后远程执行）"],
    "domain": ["dns_recon（区域传送/记录）", "ldap_enum（域枚举）"],
    "kerberos-sec": ["kerberoast / asrep_roast（域提权）"],
    "snmp": ["提示：snmpwalk 未定制，用 run_command 直接跑（public 团体串）"],
    "mongodb": ["hydra_brute（mongodb 弱口令）"],
}

# 端口 → 服务关键词回退
_PORT_FALLBACK: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtp",
    636: "ssl/ldap", 1433: "mssql", 1521: "mssql", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5985: "winrm", 5986: "winrm",
    6379: "redis", 8080: "http", 8443: "https", 27017: "mongodb", 161: "snmp",
}

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "recon_pipeline",
            "description": (
                "多工具联动侦察流水线：ping 探测存活 → nmap 版本扫描（top 端口）→ "
                "自动按开放端口/服务生成工具链建议清单。"
                "一条命令完成侦察阶段的收尾工作；危险工具（hydra/sqlmap 等）只给建议不自动执行。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标 IP/域名/CIDR"},
                    "ports": {
                        "type": "string",
                        "description": "指定端口（可选），如 '22,80,443' 或 '1-1000'",
                    },
                },
                "required": ["target"],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    """流水线由多个 nmap 命令组成，此函数校验参数并返回主扫描命令。"""
    target = sanitize_target(str(args["target"]))
    ports = sanitize_ports(args.get("ports"))  # 校验 ports 格式（异常即拒绝）
    if ports:
        return f"nmap -sV -T4 -p{ports} {target}", 300
    return f"nmap -sV -T4 --top-ports 200 {target}", 300


def _parse_ports(raw: str) -> list[tuple[int, str, str]]:
    """解析 nmap -sV 输出 → [(端口, 服务, 版本)]"""
    out: list[tuple[int, str, str]] = []
    for line in raw.splitlines():
        if not re_search_port(line):
            continue
        parts = line.split()
        try:
            port = int(parts[0].split("/")[0])
        except (ValueError, IndexError):
            continue
        service = parts[2] if len(parts) > 2 else "unknown"
        version = " ".join(parts[3:]) if len(parts) > 3 else ""
        out.append((port, service, version))
    return out


def _suggest(port: int, service: str) -> list[str]:
    key = service.lower()
    if key in _SERVICE_PLAYBOOK:
        return _SERVICE_PLAYBOOK[key]
    for k, v in _SERVICE_PLAYBOOK.items():
        if k in key:
            return v
    fallback = _PORT_FALLBACK.get(port)
    if fallback:
        return _SERVICE_PLAYBOOK.get(fallback, [f"提示：{port} 端口服务未知，用 nmap -sV 或 http_req 进一步确认"])
    return [f"提示：{service} 暂无专用档案，用 run_command 深入或搜索 exploit（sploit_search）"]


def _summarize(raw: str, ports_raw: str = "") -> str:
    ports = _parse_ports(raw)
    hosts = len({l.split(" for ")[-1].strip() for l in raw.splitlines() if l.startswith("Nmap scan report")})
    head: list[str] = []
    if hosts:
        head.append(f"存活主机: {hosts} 台")
    if ports:
        head.append(f"开放端口 ({len(ports)}):")
        for p, svc, ver in ports:
            head.append(f"  {p}/tcp {svc}" + (f" {ver}" if ver else ""))
        head.append("📋 工具链建议（按优先级，危险工具需确认后执行）:")
        for p, svc, _ver in ports:
            head.append(f"- {p} ({svc}): " + " → ".join(_suggest(p, svc)))
    else:
        head.append("未发现开放端口（或全部过滤/关闭）")
    head.append("提示：本流水线只做侦察；利用/口令类工具由 agent 按建议逐个执行（会触发安全确认）。")
    return ToolProfile._summary(raw, head, tail=60)


class PlaybookProfile(ToolProfile):
    name = "playbook"
    aliases = ["流水线", "联动", "侦察流程", "recon", "一键侦察", "组合扫描"]
    summary = "多工具联动侦察流水线"
    lore = """### 侦察流水线使用要点
- 定位：一条命令完成"存活探测+端口扫描+服务识别+工具建议"，是侦察阶段的收尾编排。
- 输出建议清单按优先级排列：Web 先看内容再扫漏洞；SMB 先枚举再口令；域环境先 LDAP/Kerberos。
- 危险工具（hydra/sqlmap/impacket）只出现在建议里，agent 执行时会触发安全确认——这是特性。
- 流程跑完后：按建议逐个调用对应工具（如 445 → smb_enum → smb_map → hydra_brute）。
- 自定义端口用 ports 参数（如 22,80,443）；大批量目标建议 CIDR 分段扫描。"""
    extra_schemas = SCHEMAS

    async def exec_recon_pipeline(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("nmap"):
            return "nmap 未安装（apt install nmap）。"
        target = sanitize_target(str(args["target"]))
        ports = str(args.get("ports") or "").strip()

        # 1) ping 探测
        ping_cmd, t1 = nmap_build_cmd({"target": target, "scan_type": "ping"})
        ping_raw = await self._run(ex, ping_cmd, timeout=t1)

        # 2) 版本扫描（top 200 端口，更快更聚焦）
        ver_cmd, t2 = _build_cmd(args)
        ver_raw = await self._run(ex, ver_cmd, timeout=t2)

        raw = ping_raw + "\n" + ver_raw
        return _summarize(raw)
