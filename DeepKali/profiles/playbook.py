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

# IP / CIDR 判断（域名目标才做子域发现）
_IP_ONLY_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _looks_like_domain(target: str) -> bool:
    """目标是否像域名（非 IP / 非 CIDR）。"""
    t = target.strip()
    if "/" in t:  # CIDR
        return False
    if _IP_ONLY_RE.match(t):
        return False
    return "." in t and not t.startswith(("http://", "https://"))

# 服务关键词 → 建议工具链（按渗透流程排序）
_SERVICE_PLAYBOOK: dict[str, list[str]] = {
    "ssh": ["hydra_brute（ssh 弱口令）"],
    "ftp": ["ftp_check（匿名/凭据）", "hydra_brute（ftp 弱口令）"],
    "smtp": ["smtp_enum（用户枚举）", "hydra_brute（smtp 弱口令）"],
    "pop3": ["hydra_brute（pop3 弱口令）"],
    "imap": ["hydra_brute（imap 弱口令）"],
    "telnet": ["hydra_brute（telnet 弱口令）"],
    "http": ["http_req（看内容）", "whatweb（技术栈指纹）", "wpscan/joomla_scan/drupwn（按指纹选 CMS 专项）", "nikto_scan（漏洞）", "dir_brute（目录）", "ffuf_dir（深挖）", "katana（JS 端点提取）", "gau（历史 URL）", "waf_detect（WAF）", "nuclei_scan（模板）", "git_leak（.git 源码泄露）"],
    "https": ["http_req -k（看内容）", "whatweb（技术栈指纹）", "ssl_scan（TLS 配置）", "tls_deep（深度 TLS）", "nikto_scan", "dir_brute", "waf_detect", "nuclei_scan", "git_leak（.git 泄露）"],
    "ssl/http": ["http_req -k", "ssl_scan", "nikto_scan", "dir_brute", "waf_detect"],
    "ssl/ldap": ["ldap_enum（LDAPS）"],
    "ldap": ["ldap_enum（目录枚举）"],
    "netbios-ssn": ["smb_enum（SMB 枚举）"],
    "nfs": ["nfs_enum（导出共享）"],
    "microsoft-ds": ["smb_enum（用户/共享）", "smb_map（共享内容）", "smb_ls（目录浏览）", "hydra_brute（smb 弱口令）", "bloodhound_py（有凭据后采域关系）"],
    "mysql": ["hydra_brute（mysql 弱口令）"],
    "mssql": ["hydra_brute（mssql 弱口令）"],
    "postgresql": ["hydra_brute（postgres 弱口令）"],
    "redis": ["redis_check（未授权检查）"],
    "rsync": ["rsync_enum（模块枚举）"],
    "ms-wbt-server": ["提示：RDP 3389，弱口令用 hydra（rdp），或检查 NLA"],
    "winrm": ["winrm_exec（凭据后远程执行）"],
    "domain": ["dns_recon（区域传送/记录）", "subfinder（子域被动枚举）", "gau（历史 URL）", "dnsx（批量解析验证）", "ldap_enum（域枚举）"],
    "elasticsearch": ["http_req（REST 接口指纹）", "run_command（_cat/indices 未授权检查）"],
    "memcached": ["run_command（stats 未授权检查，nc 11211）"],
    "docker": ["run_command（/version /containers/json 未授权检查）"],
    "webmin": ["http_req（Webmin 登录面）", "hydra_brute（webmin 弱口令）"],
    "weblogic": ["http_req（管理台指纹）", "run_command（CVE 检测脚本/手工验证）"],
    "kibana": ["http_req（Kibana 面板指纹）", "run_command（_search 未授权检查）"],
    "grafana": ["http_req（Grafana 面板指纹）", "run_command（API 未授权/CVE-2021-43798 路径遍历）"],
    "spring": ["http_req（Spring Boot 指纹）", "run_command（/actuator /env /heapdump 未授权检查）"],
    "consul": ["run_command（/v1/agent/services 未授权 API）"],
    "vault": ["run_command（/v1/sys/health 未授权探测）"],
    "jenkins": ["http_req（Jenkins 登录面）", "hydra_brute（jenkins 弱口令）"],
    "kafka": ["run_command（Kafka 未授权连接检查）"],
    "rabbitmq": ["http_req（15672 管理台）", "hydra_brute（rabbitmq 弱口令）"],
    "prometheus": ["run_command（/api/v1/targets 未授权）"],
    "sonarqube": ["http_req（SonarQube 登录面）", "hydra_brute（弱口令）"],
    "minio": ["http_req（MinIO 控制台）", "run_command（/minio/health/live 未授权检查）"],
    "etcd": ["run_command（/v3/kv/range 未授权读）"],
    "kubernetes": ["run_command（/api/v1/namespaces 未授权 K8s API）"],
    "ajp": ["run_command（Ghostcat CVE-2020-1938 检测：AJP 文件读取/回显）"],
    "glassfish": ["http_req（GlassFish 管理台）", "hydra_brute（弱口令）"],
    "elasticsearch-transport": ["run_command（ES transport 9300 未授权连接检查）"],
    "redis-sentinel": ["run_command（Sentinel 26379 未授权检查）"],
    "kerberos-sec": ["kerberoast / asrep_roast（域提权）", "bloodhound_py（凭据就绪后采域关系→最短路径）"],
    "oracle": ["hydra_brute（oracle 弱口令，可用 oracletns 模块）"],
    "vnc": ["提示：VNC 弱口令用 hydra（vnc）"],
    "tftp": ["提示：TFTP 无认证，用 run_command 直接 tftp 下载文件尝试"],
    "snmp": ["提示：snmpwalk 未定制，用 run_command 直接跑（public 团体串）"],
    "mongodb": ["hydra_brute（mongodb 弱口令）"],
}

# 端口 → 服务关键词回退
_PORT_FALLBACK: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtp",
    636: "ssl/ldap", 1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 5985: "winrm",
    5986: "winrm", 6379: "redis", 2049: "nfs", 69: "tftp", 873: "rsync",
    8080: "spring", 8443: "https", 27017: "mongodb", 161: "snmp",
    8000: "http", 8888: "http", 9200: "elasticsearch", 5601: "kibana",
    11211: "memcached", 2375: "docker", 10000: "webmin", 7001: "weblogic",
    3000: "grafana", 8081: "spring", 9090: "prometheus", 9000: "sonarqube",
    8500: "consul", 8200: "vault", 9092: "kafka",
    15672: "rabbitmq", 9001: "minio", 2379: "etcd", 6443: "kubernetes",
    8009: "ajp", 4848: "glassfish", 9300: "elasticsearch-transport",
    26379: "redis-sentinel",
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
    {
        "type": "function",
        "function": {
            "name": "bounty_recon",
            "description": (
                "一键白帽侦察执行链（支持多目标）：可选子域发现（crt.sh 证书日志 + httpx "
                "存活探测）→ 对每个目标跑 nmap 版本扫描（top 200）→ 解析开放端口/服务 → "
                "对 Web 服务自动跑 WAF 识别（wafw00f）+ 目录枚举（gobuster）+ 可选 nuclei "
                "漏洞扫描 → 输出按目标分组的攻击面摘要。适合新目标开局或证据不足时快速建立攻击面。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "目标 IP/域名/CIDR，逗号分隔多目标（最多 10 个）",
                    },
                    "ports": {
                        "type": "string",
                        "description": "指定端口（可选），如 '22,80,443' 或 '1-1000'",
                    },
                    "web_check": {
                        "type": "boolean",
                        "description": "是否对 Web 服务自动跑 WAF/目录（默认 true）",
                    },
                    "vuln_scan": {
                        "type": "boolean",
                        "description": "是否跑 nuclei 已知漏洞扫描（较慢，默认 false）",
                    },
                    "sub_enum": {
                        "type": "boolean",
                        "description": "是否先做子域发现（crt.sh 证书日志，仅对域名目标，较慢，默认 false）",
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


def _parse_dir_results(raw: str) -> list[str]:
    """解析 gobuster 输出 → 非 404 的目录/文件列表，如 ['/admin(200)', '/api(301)']。"""
    out: list[str] = []
    for line in raw.splitlines():
        m = re.search(r"(\S+)\s+\(Status:\s*(\d{3})\)", line)
        if m and m.group(2) != "404":
            out.append(f"{m.group(1)}({m.group(2)})")
    return out


def _parse_nuclei(raw: str) -> list[str]:
    """解析 nuclei 输出 → 有意义的命中行（CVE/严重级别），去重取前几条。"""
    hits: list[str] = []
    for line in raw.splitlines():
        low = line.lower().strip()
        if not low:
            continue
        if any(k in low for k in ("cve-", "[critical]", "[high]", "[medium]", "[low]")):
            hit = line.strip()[:120]
            if hit not in hits:
                hits.append(hit)
    return hits


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
- 自定义端口用 ports 参数（如 22,80,443）；大批量目标建议 CIDR 分段扫描。
- bounty_recon 是深度链：nmap 版本扫描后自动对 Web 服务跑 WAF 识别 + 目录枚举，
  一步产出"端口+WAF+目录"三合一攻击面摘要；web_check=false 可跳过 Web 深化。"""
    extra_schemas = SCHEMAS

    async def exec_recon_pipeline(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("nmap"):
            return "nmap 未安装（apt install nmap）。"
        target = sanitize_target(str(args["target"]))

        # 1) ping 探测
        ping_cmd, t1 = nmap_build_cmd({"target": target, "scan_type": "ping"})
        ping_raw = await self._run(ex, ping_cmd, timeout=t1)

        # 2) 版本扫描（top 200 端口，更快更聚焦）
        ver_cmd, t2 = _build_cmd(args)
        ver_raw = await self._run(ex, ver_cmd, timeout=t2)

        raw = ping_raw + "\n" + ver_raw
        return _summarize(raw)

    # ---------------- bounty_recon：一键白帽侦察执行链 ----------------
    async def exec_bounty_recon(self, ex: Any, args: dict[str, Any]) -> str:
        """支持逗号分隔多目标（最多 10 个）。每个目标：
        nmap 版本扫描 → 解析端口 → Web 服务自动 WAF 识别 + 目录枚举 + （可选）nuclei。

        每步独立容错（一步失败不影响后续）；每个子命令仍走 run_command，
        scope 守卫照常校验目标授权。
        """
        from .gobuster import _build_cmd as gobuster_build_cmd
        from .wafw00f import _build_cmd as waf_build_cmd

        if not check_installed("nmap"):
            return "nmap 未安装（apt install nmap）。"
        waf_ok = check_installed("wafw00f")
        gobuster_ok = check_installed("gobuster")
        nuclei_ok = check_installed("nuclei")
        crtsh_ok = check_installed("curl")
        httpx_ok = check_installed("httpx")
        raw_targets = [t.strip() for t in str(args["target"]).split(",") if t.strip()]
        if not raw_targets:
            raise ValueError("target 不能为空")
        if len(raw_targets) > 10:
            raise ValueError("一次最多 10 个目标（大批量建议分批执行）")
        ports = sanitize_ports(args.get("ports"))
        web_check = bool(args.get("web_check", True))
        vuln_scan = bool(args.get("vuln_scan", False))
        sub_enum = bool(args.get("sub_enum", False))

        sections: list[str] = []

        # 0) 子域发现（仅对域名目标；crt.sh 证书日志 + httpx 存活探测）
        if sub_enum:
            from .crtsh import _build_cmd as crtsh_build_cmd
            from .crtsh import _parse as crtsh_parse
            from .httpx import _build_cmd as httpx_build_cmd
            from .httpx import _parse as httpx_parse

            domain_targets = [t for t in raw_targets if _looks_like_domain(t)]
            if not domain_targets:
                sections.append("sub_enum: 目标均为 IP/CIDR，跳过子域发现")
            elif not crtsh_ok:
                sections.append("sub_enum: 跳过（curl 未安装）")
            else:
                found_all: list[str] = []
                for dt in domain_targets:
                    try:
                        raw = await self._run(ex, crtsh_build_cmd(dt), timeout=90)
                        found = crtsh_parse(raw, 40)
                        found_all += [f"{dt} → {d}" for d in found]
                    except Exception:  # noqa: BLE001
                        sections.append(f"sub_enum: {dt} 查询失败（跳过）")
                if found_all:
                    head = [f"📜 子域发现 ({len(found_all)} 个):"]
                    head += [f"  {f}" for f in found_all[:25]]
                    if len(found_all) > 25:
                        head.append(f"  … 共 {len(found_all)} 个")
                    sections.append("\n".join(head))
                    # httpx 批量存活探测（子域太多时只探前 20 个）
                    if httpx_ok:
                        probe_targets = [f.split(" → ")[-1] for f in found_all[:20]]
                        try:
                            px_raw = await self._run(ex, httpx_build_cmd(probe_targets), timeout=120)
                            rows = httpx_parse(px_raw)
                            if rows:
                                alive = [f"{r['url']} [{r['status']}]" for r in rows[:20]]
                                sections.append(
                                    "🌐 存活子域: " + (", ".join(alive) if alive else "（均无 HTTP 响应）")
                                )
                        except Exception:  # noqa: BLE001
                            sections.append("sub_enum: httpx 存活探测失败（跳过）")
                else:
                    sections.append("sub_enum: 证书日志未发现子域（可稍后用 dnsrecon brt 兜底）")

        for target in raw_targets:
            target = sanitize_target(target)
            head: list[str] = [f"===== {target} ====="]

            # 1) nmap 版本扫描（top 200，快）
            nmap_cmd, t = _build_cmd({"target": target, "ports": ports})
            raw = await self._run(ex, nmap_cmd, timeout=t)
            port_list = _parse_ports(raw)
            hosts = len({
                l.split(" for ")[-1].strip()
                for l in raw.splitlines() if l.startswith("Nmap scan report")
            })
            head.append(f"存活主机: {hosts or 1} 台")
            head.append(f"开放端口 ({len(port_list)}):")
            for p, svc, ver in port_list:
                head.append(f"  {p}/tcp {svc}" + (f" {ver}" if ver else ""))

            # 2) Web 服务自动深化（容错：失败继续）
            web_ports = [p for p, svc, _v in port_list if "http" in svc.lower()]
            if web_check and web_ports:
                if not (waf_ok or gobuster_ok or (vuln_scan and nuclei_ok)):
                    head.append("[Web 深化] 跳过：wafw00f/gobuster/nuclei 均未安装（apt install 后重试）")
                for p in web_ports[:3]:
                    scheme = "https" if p == 443 else "http"
                    url = f"{scheme}://{target}" if p in (80, 443) else f"{scheme}://{target}:{p}"
                    head.append(f"[Web 深化] {url}")
                    if waf_ok:
                        try:
                            waf_cmd, waf_to = waf_build_cmd({"url": url})
                            waf_raw = await self._run(ex, waf_cmd, timeout=waf_to)
                            if "is behind" in waf_raw.lower():
                                head.append("  WAF: 检测到防护（后续请求考虑 waf_bypass 思路）")
                            else:
                                head.append("  WAF: 未检测到（或工具不可达）")
                        except Exception:  # noqa: BLE001
                            head.append("  WAF: 检测失败（跳过）")
                    else:
                        head.append("  WAF: 跳过（wafw00f 未安装）")
                    if gobuster_ok:
                        try:
                            dir_cmd, dir_to = gobuster_build_cmd({"url": url, "threads": 20})
                            dir_raw = await self._run(ex, dir_cmd, timeout=dir_to)
                            found = _parse_dir_results(dir_raw)
                            head.append(
                                "  目录发现: " + (", ".join(found[:10]) if found else "无（均 404/超时）")
                            )
                        except Exception:  # noqa: BLE001
                            head.append("  目录枚举失败（跳过）")
                    else:
                        head.append("  目录枚举: 跳过（gobuster 未安装）")
                    if vuln_scan:
                        if nuclei_ok:
                            try:
                                nuclei_raw = await self._run(
                                    ex, f"nuclei -u {url} -silent -nc", timeout=300
                                )
                                hits = _parse_nuclei(nuclei_raw)
                                head.append(
                                    "  nuclei: " + (", ".join(hits[:8]) if hits else "未发现模板命中（可能安全或模板不全）")
                                )
                            except Exception:  # noqa: BLE001
                                head.append("  nuclei: 扫描失败（跳过）")
                        else:
                            head.append("  nuclei: 跳过（未安装，apt install nuclei）")

            # 3) 收尾建议
            if not port_list:
                head.append("未发现开放端口——换端口范围重扫或确认目标可达。")
            elif web_ports:
                head.append("建议: Web 目标用 http_req 看内容与响应头，命中线索再验证（见 vuln_proof lore）。")
            else:
                head.append("建议: 非 Web 服务按漏洞指纹搜索（sploit_search）逐个深入。")
            sections.append("\n".join(head))

        return f"bounty_recon 完成（{len(raw_targets)} 个目标）\n\n" + "\n\n".join(sections)
