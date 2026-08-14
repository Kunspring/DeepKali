"""工具档案注册表：汇总所有深度定制工具。

- all_schemas()：全部专属 function schema（追加到 Agent 的 tools 列表）
- register_extensions(executor)：把每个档案的执行器挂到 Executor.extensions
- lore_for(history)：根据对话内容按需注入相关档案的深度知识（省 token）
- inventory()：已定制工具清单（用于系统提示词/状态展示）
"""

from __future__ import annotations

from typing import Any

from .base import ToolProfile
from .aircrack import AircrackProfile
from .airmon import AirmonProfile
from .cewl import CewlProfile
from .chisel import ChiselProfile
from .crack import CrackProfile
from .curl import CurlProfile
from .dnsrecon import DnsreconProfile
from .enum4linux import Enum4linuxProfile
from .evilwinrm import EvilWinrmProfile
from .ffuf import FfufProfile
from .ftp import FtpProfile
from .getnpusers import GetNPUsersProfile
from .getuserspns import GetUserSPNsProfile
from .gobuster import GobusterProfile
from .hashid import HashidProfile
from .hping3 import Hping3Profile
from .hydra import HydraProfile
from .impexec import ImpExecProfile
from .ldapsearch import LdapsearchProfile
from .macchanger import MacchangerProfile
from .msf import MsfProfile
from .msfvenom import MsfvenomProfile
from .netcat import NcProfile
from .netdiscover import NetdiscoverProfile
from .nikto import NiktoProfile
from .nmap import NmapProfile
from .nuclei import NucleiProfile
from .playbook import PlaybookProfile
from .redis import RedisProfile
from .responder import ResponderProfile
from .searchsploit import SploitProfile
from .secretsdump import SecretsdumpProfile
from .smbclient import SmbclientProfile
from .smbmap import SmbmapProfile
from .smtpenum import SmtpEnumProfile
from .socat import SocatProfile
from .sqlmap import SqlmapProfile
from .sslscan import SslscanProfile
from .tcpdump import TcpdumpProfile
from .testssl import TestsslProfile
from .theharvester import TheHarvesterProfile
from .tshark import TsharkProfile
from .wafw00f import Wafw00fProfile
from .wfuzz import WfuzzProfile
from .wpscan import WpscanProfile

REGISTRY: list[ToolProfile] = [
    NmapProfile(),
    MsfProfile(),
    NiktoProfile(),
    GobusterProfile(),
    SploitProfile(),
    HydraProfile(),
    SqlmapProfile(),
    CrackProfile(),
    WpscanProfile(),
    Enum4linuxProfile(),
    SmbmapProfile(),
    DnsreconProfile(),
    FfufProfile(),
    AircrackProfile(),
    MsfvenomProfile(),
    TcpdumpProfile(),
    NucleiProfile(),
    ResponderProfile(),
    EvilWinrmProfile(),
    NcProfile(),
    SmbclientProfile(),
    LdapsearchProfile(),
    SecretsdumpProfile(),
    ChiselProfile(),
    GetNPUsersProfile(),
    GetUserSPNsProfile(),
    SocatProfile(),
    TsharkProfile(),
    Hping3Profile(),
    ImpExecProfile(),
    WfuzzProfile(),
    NetdiscoverProfile(),
    AirmonProfile(),
    MacchangerProfile(),
    CurlProfile(),
    SslscanProfile(),
    Wafw00fProfile(),
    RedisProfile(),
    FtpProfile(),
    TheHarvesterProfile(),
    TestsslProfile(),
    SmtpEnumProfile(),
    HashidProfile(),
    CewlProfile(),
    PlaybookProfile(),
]

# name -> profile
_BY_NAME: dict[str, ToolProfile] = {p.name: p for p in REGISTRY}


def all_schemas() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in REGISTRY:
        out.extend(p.extra_schemas)
    return out


def register_extensions(executor: Any) -> None:
    for p in REGISTRY:
        p.register(executor)


def inventory() -> str:
    if not REGISTRY:
        return ""
    lines = [f"- {p.name}：{p.summary}（专属工具: {', '.join(p.tool_names())}）" for p in REGISTRY]
    return "已深度定制的 Kali 工具档案:\n" + "\n".join(lines)


def lore_for(history: list[dict[str, Any]]) -> str:
    """扫描对话历史（用户消息 + 已调用的工具名），命中档案则注入其 lore。"""
    text = " ".join(
        str(m.get("content") or "")
        for m in history
        if m.get("role") in ("user", "tool")
    )
    text += " " + " ".join(
        str(call.get("function", {}).get("name", ""))
        for m in history
        for call in (m.get("tool_calls") or [])
    )
    if not text.strip():
        return ""
    hits = [
        p
        for p in REGISTRY
        if p.matches(text) or any(tn in text for tn in p.tool_names())
    ]
    if not hits:
        return ""
    parts = ["# 深度定制工具档案（按当前任务加载，遵循其中的用法要点）"]
    for p in hits:
        parts.append(f"## {p.name}\n{p.lore}")
    return "\n\n".join(parts)
