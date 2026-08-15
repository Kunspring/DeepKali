"""目标授权范围守卫（ScopeGuard）——白帽挖漏洞合规第一道闸。

白帽/赏金场景的第一铁律：只测授权范围内的目标。ScopeGuard 在命令执行前
提取其中的外部目标（公网 IP / 域名 / URL 主机 / user@host），未授权目标
必须先经用户确认，确认一次后本会话内放行。

默认豁免（本地靶场 / CTF / 教学场景，无需确认）：
  - loopback: 127.0.0.0/8, ::1, localhost
  - RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  - 链路本地: 169.254.0.0/16, fe80::/10

策略（scope_policy）：
  - ask    （默认）外部目标未授权 → 弹窗确认
  - off    完全关闭本守卫（不推荐，仅自测本机内网时用）
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path

# 授权目标持久化文件（白帽跨会话复用）
SCOPE_FILE = Path(os.environ.get(
    "KALITUI_SCOPE_FILE",
    str(Path.home() / ".config" / "kalitui" / "scope.json"),
)).expanduser()

# ---- 目标提取正则 ----
_URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9._-]+)", re.IGNORECASE)
_AT_HOST_RE = re.compile(r"@([A-Za-z0-9._-]+)")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?\b")
_IPV6_RE = re.compile(r"\b([0-9a-fA-F:]{3,39})\b")
_CIDR_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/(?:3[0-2]|[12]?\d))\b")


def _is_valid_cidr(token: str) -> bool:
    """CIDR 文本是否合法（网段或主机位均可，如 203.0.113.0/24、203.0.113.5/32）。"""
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False
_DOMAIN_RE = re.compile(
    r"""(?<![\w@./-])([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.
        (?:[a-zA-Z0-9-]{1,61}\.)*[a-zA-Z]{2,24})(?![\w@./-])""",
    re.VERBOSE,
)

# 已知会对外部目标发起活动的网络工具（出现这些工具名才提取裸域名，
# 避免把本地文件路径 / 参数误判为目标）
_NET_TOOLS = (
    "nmap", "masscan", "ping", "fping", "curl", "wget", "hydra", "medusa",
    "sqlmap", "nikto", "gobuster", "ffuf", "wfuzz", "wpscan", "nuclei",
    "dnsrecon", "dnsenum", "theharvester", "dig", "nslookup", "host",
    "openssl", "sslscan", "testssl", "nc", "ncat", "socat", "msfconsole",
    "msfvenom", "crackmapexec", "netexec", "smbclient", "smbmap",
    "enum4linux", "ldapsearch", "evil-winrm", "evilwinrm", "smbexec",
    "wmiexec", "atexec", "secretsdump", "ntlmrelayx", "responder",
    "redis-cli", "ftp", "telnet", "ssh", "scp", "hping3", "hping",
    "arp-scan", "netdiscover", "tcpdump", "tshark", "wafw00f", "cewl",
    "whatweb", "dmitry", "recon-ng", "amass", "subfinder", "httpx",
    "feroxbuster", "dirsearch", "xray", "acunetix", "zap-cli",
    "mimikatz", "kerberoast", "rpcclient", "showmount", "nbtscan",
    "onesixtyone", "snmpwalk", "snmp-check", "ike-scan", "fierce",
)

# 本地文件/参数误报拦截：这些扩展名结尾的"域名"其实是文件路径
_LOCAL_EXT = (
    ".txt", ".py", ".sh", ".conf", ".cfg", ".ini", ".json", ".yaml",
    ".yml", ".log", ".md", ".html", ".js", ".css", ".xml", ".csv",
    ".gz", ".zip", ".tar", ".lst", ".dic", ".php", ".c", ".h",
    ".so", ".a", ".o", ".pdf", ".png", ".jpg", ".key", ".pem",
    ".crt", ".cer", ".p12", ".jar", ".war", ".class",
)

# 这些 token 不是目标（常见命令参数/本地路径段）
_NON_TARGET_TOKENS = {
    "localhost", "localdomain", "example.com", "example.org", "example.net",
    "github.com", "raw.githubusercontent.com", "pypi.org", "files.pythonhosted.org",
    "deb.debian.org", "http.kali.org", "kali.download", "archive.ubuntu.com",
    "security.ubuntu.com", "docker.io", "registry-1.docker.io", "registry.hub.docker.com",
    "mirrors.tuna.tsinghua.edu.cn", "mirrors.aliyun.com", "mirrors.ustc.edu.cn",
    "nodejs.org", "npmjs.org", "registry.npmjs.org", "rubygems.org",
    "pypi.python.org", "downloads.mysql.com", "repo.mysql.com",
    "packages.microsoft.com", "microsoft.com", "msftconnecttest.com",
    "connectivitycheck.gstatic.com", "www.google.com", "baidu.com", "qq.com",
    "cloudflare.com", "1.1.1.1", "8.8.8.8", "8.8.4.4", "223.5.5.5", "114.114.114.114",
}


def _is_private(host: str) -> bool:
    """判断主机是否属于默认豁免范围（本机/内网）。

    注意：不用 ipaddress 的 is_private（Python 3.13 起把 TEST-NET/文档网段
    也算 private，导致 203.0.113.x 这类示例目标被误豁免），改为手工精确匹配。
    """
    host = host.strip().strip("[]").lower()
    if host in ("localhost", "localhost.localdomain"):
        return True
    if "/" in host:  # CIDR 网段
        try:
            net = ipaddress.ip_network(host, strict=False)
        except ValueError:
            return False
        if net.version == 4:
            return any(net.subnet_of(p) for p in _PRIVATE_V4)
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if addr.version == 4:
        return any(addr in net for net in _PRIVATE_V4)
    # IPv6：仅豁免 loopback / ULA(fc00::/7) / link-local / unspecified
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or (int(addr) >> 120) in (0xFC, 0xFD)
    )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# 精确豁免网段（本机/内网/链路本地/CGNAT）
_PRIVATE_V4 = [
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8",      # loopback
        "10.0.0.0/8",       # RFC1918
        "172.16.0.0/12",    # RFC1918
        "192.168.0.0/16",   # RFC1918
        "169.254.0.0/16",   # 链路本地
        "100.64.0.0/10",    # CGNAT
    )
]


def _looks_like_file_path(token: str) -> bool:
    low = token.lower()
    if any(low.endswith(ext) for ext in _LOCAL_EXT):
        return True
    # 含路径分隔符且不全是点分数字的，多半是路径（CIDR 的 /24 不是路径）
    if "/" in token and not _CIDR_RE.fullmatch(token):
        return True
    return False


def _is_non_target(token: str) -> bool:
    low = token.lower()
    if low in _NON_TARGET_TOKENS:
        return True
    if low.endswith(".local") or low.endswith(".lan") or low.endswith(".home"):
        return True
    return False


def extract_targets(command: str) -> list[str]:
    """从一条 shell 命令中提取可能的外部目标（去重、保序）。

    提取来源：
      1. URL 主机（http://host/...）——任何命令都提取
      2. user@host（ssh/scp 等）——任何命令都提取
      3. 裸 IP（v4）——任何命令都提取
      4. 裸域名——仅当命令中出现已知网络工具时提取（防本地路径误报）
    """
    text = command or ""
    found: list[str] = []

    # CIDR 网段优先于裸 IP 匹配（保留 /24 前缀，授权语义才准确）
    for m in _CIDR_RE.finditer(text):
        cidr = m.group(1)
        if _is_valid_cidr(cidr) and not _is_private(cidr):
            found.append(cidr)
    for m in _URL_HOST_RE.finditer(text):
        found.append(m.group(1))
    for m in _AT_HOST_RE.finditer(text):
        found.append(m.group(1))
    for m in _IP_RE.finditer(text):
        if "/" in m.group(0):
            continue  # CIDR 已由 _CIDR_RE 处理（含非法前缀也不降级为裸 IP）
        found.append(m.group(1))
    for m in _IPV6_RE.finditer(text):
        token = m.group(1)
        if token.count(":") >= 2 and _is_ip(token):
            found.append(token)

    first_word = text.split()[0].split("/")[-1] if text.split() else ""
    uses_net_tool = first_word in _NET_TOOLS or any(
        t in _NET_TOOLS for t in re.split(r"[;\s|]+", text)[:8]
    )
    if uses_net_tool:
        for m in _DOMAIN_RE.finditer(text):
            found.append(m.group(1))

    targets: list[str] = []
    for t in found:
        t = t.strip().rstrip(".,;:)]}>")
        if not t:  # pragma: no cover 防御：正则产物 strip 后非空
            continue
        if _is_private(t) or _is_non_target(t) or _looks_like_file_path(t):
            continue
        if t not in targets:
            targets.append(t)
    return targets


class ScopeGuard:
    """会话级目标授权守卫（支持持久化，白帽跨会话复用授权）。"""

    def __init__(self, policy: str = "ask") -> None:
        self.policy = policy
        self.authorized: list[str] = []   # 用户确认过的目标（持久化）
        self.declined: list[str] = []     # 用户拒绝过的目标（会话内不再重复问）

    # ---------------- 查询 ----------------
    def _covered(self, target: str, authorized: list[str]) -> bool:
        """target 是否被授权列表覆盖（字符串相等，或 IP 落在授权 CIDR 内）。"""
        if target in authorized:
            return True
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return False
        for item in authorized:
            if "/" in item and _is_valid_cidr(item):
                try:
                    if addr in ipaddress.ip_network(item, strict=False):
                        return True
                except ValueError:  # pragma: no cover 防御：_is_valid_cidr 已保证合法
                    continue
        return False

    def unauthorized(self, command: str) -> list[str]:
        """返回命令中未授权的外部目标；无外部目标/全部已授权 → 空列表。"""
        if self.policy == "off":
            return []
        targets = extract_targets(command)
        return [t for t in targets
                if not self._covered(t, self.authorized) and t not in self.declined]

    def authorize(self, target: str) -> None:
        if target not in self.authorized:
            self.authorized.append(target)
            self.save_persisted()

    def authorize_all(self, targets: list[str]) -> None:
        changed = False
        for t in targets:
            if t not in self.authorized:
                self.authorized.append(t)
                changed = True
        if changed:
            self.save_persisted()

    def decline(self, target: str) -> None:
        if target not in self.declined:
            self.declined.append(target)

    def decline_all(self, targets: list[str]) -> None:
        for t in targets:
            self.decline(t)

    # ---------------- 持久化 ----------------
    def load_persisted(self) -> None:
        """从配置文件加载历史授权目标（白帽跨会话复用，坏文件静默忽略）。"""
        try:
            if SCOPE_FILE.exists():
                data = json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
                loaded = [t for t in data.get("authorized", []) if isinstance(t, str) and t]
                for t in loaded:
                    if t not in self.authorized:
                        self.authorized.append(t)
        except (OSError, ValueError):
            pass

    def save_persisted(self) -> None:
        """保存授权目标到配置文件（失败静默——授权仍在会话内生效）。"""
        try:
            SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
            SCOPE_FILE.write_text(
                json.dumps(
                    {"authorized": self.authorized, "policy": self.policy},
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError:
            pass

    def summary(self) -> str:
        lines = [f"策略: {self.policy}"]
        if self.authorized:
            lines.append("已授权目标: " + ", ".join(self.authorized))
        else:
            lines.append("已授权目标: （无）")
        if self.declined:
            lines.append("已拒绝目标: " + ", ".join(self.declined))
        return "\n".join(lines)
