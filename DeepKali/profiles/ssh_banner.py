"""SSH Banner 审计：抓取目标 SSH banner，提取版本并对照弱版本风险表。

白帽定位：SSH 服务侦察——banner 泄露精确版本（OpenSSH_7.2/8.9p1），
对照已知弱版本（用户枚举/预认证 RCE 系）给出风险提示，接 cve_lookup 细化。
纯 nc 抓 banner，零扫描特征（单连接）。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_TARGET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,251}$", re.IGNORECASE)
_BANNER_RE = re.compile(r"SSH-2\.0-([A-Za-z0-9._\-]+)")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")

# (产品, 最低安全版本, 说明) —— 低于最低即提示
_WEAK: list[tuple[str, tuple[int, int, int], str]] = [
    ("OpenSSH", (7, 4, 0), "低于 7.4：CVE-2016-6210 用户枚举/时序侧信道"),
    ("OpenSSH", (8, 5, 0), "低于 8.5：CVE-2021-41617 权限提升（需本地用户）"),
    ("OpenSSH", (9, 3, 0), "低于 9.3：CVE-2023-38408 ssh-agent 预认证 RCE（需转发 agent）"),
    ("Dropbear", (2022, 83, 0), "旧版 Dropbear 弱随机/已知 CVE 系"),
]
_MAX_VERSION = (99, 99, 99)

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "ssh_banner",
            "description": (
                "SSH Banner 审计：抓取目标 SSH banner 提取版本，对照弱版本风险表"
                "（CVE-2016-6210 用户枚举/2023-38408 agent RCE 系），建议接 cve_lookup。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "目标 IP 或域名，如 10.0.0.9",
                    },
                    "port": {
                        "type": "integer",
                        "description": "SSH 端口（默认 22）",
                    },
                },
                "required": ["target"],
            },
        },
    },
]


def _build_cmd(target: str, port: int) -> str:
    return f"timeout 6 bash -c \"echo | nc -w 4 {target} {port} | head -1\""


def _parse_banner(raw: str) -> str:
    m = _BANNER_RE.search(raw)
    return m.group(1) if m else ""


def _parse_version(product: str) -> tuple[int, int, int]:
    m = _VERSION_RE.search(product)
    if not m:
        return _MAX_VERSION
    parts = [int(m.group(1)), int(m.group(2))]
    parts.append(int(m.group(3)) if m.group(3) else 0)
    return tuple(parts)  # type: ignore[return-value]


def _check_weak(product: str) -> str | None:
    """对照弱版本表 → 风险说明；安全版本返回 None。"""
    ver = _parse_version(product)
    if ver == _MAX_VERSION:
        return None
    for prod, min_ver, note in _WEAK:
        if product.startswith(prod) and ver < min_ver:
            return note
    return None


def _summarize(raw: str, target: str, port: int) -> str:
    product = _parse_banner(raw)
    head: list[str] = []
    if not product:
        head.append(f"⚠️ 未获取到 SSH banner（{target}:{port}）——端口关闭/非 SSH/防火墙过滤。")
        head.append("提示：确认端口开放（nmap），或目标用非标准端口/SSH over TLS。")
    else:
        head.append(f"🔑 {target}:{port} SSH 指纹: {product}")
        note = _check_weak(product)
        if note:
            head.append(f"  🚨 弱版本风险: {note}")
            head.append("  下一步：cve_lookup 查该版本 CVE 详情；确认补丁状态（版本号可伪造，"
                        "需实测行为验证）。")
        else:
            head.append("  ✅ 版本高于已知弱版本阈值（仍需 cve_lookup 确认最新 CVE）。")
        head.append("  提示：配合 hydra 弱口令测试（仅限授权）；检查认证方式"
                    "（PermitRootLogin/密钥 vs 密码）。")
    return ToolProfile._summary(raw, head, tail=20)


class SshBannerProfile(ToolProfile):
    name = "ssh_banner"
    aliases = ["ssh 指纹", "ssh banner", "ssh 版本", "ssh 审计", "banner 抓取", "ssh 弱版本"]
    summary = "SSH Banner 版本审计"
    lore = """### SSH Banner 审计使用要点
- 定位：SSH 服务侦察——banner 泄露精确版本，对照弱版本表给风险提示。
- 弱版本表：OpenSSH <7.4（CVE-2016-6210 用户枚举）、<8.5（CVE-2021-41617
  提权）、<9.3（CVE-2023-38408 agent RCE——注意需开启 agent 转发）、旧 Dropbear。
- 结合流程：ssh_banner 命中弱版本 → cve_lookup 查详情 → searchsploit 找 PoC
  → 授权内验证；版本安全也做 hydra 弱口令（密码认证开启时）。
- 注意：版本号可伪造（蜜罐/加固）；行为验证优先（实际交互差异）；
  单连接 banner 抓取无扫描特征，但批量扫端口需授权。
- 本机加固对照：PermitRootLogin no、PasswordAuthentication 按需、
  协议版本 2、Fail2ban 等是 SSH 加固基线。"""
    extra_schemas = SCHEMAS

    async def exec_ssh_banner(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("nc"):
            return "nc 未安装（apt install netcat-openbsd）。"
        target = str(args.get("target") or "").strip().lower()
        if not _TARGET_RE.match(target):
            return f"target 格式非法: {target!r}"
        port = int(args.get("port") if args.get("port") is not None else 22)
        if not 1 <= port <= 65535:
            return f"port 非法: {port}"
        raw = await self._run(ex, _build_cmd(target, port), timeout=15)
        return _summarize(raw, target, port)
