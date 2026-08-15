"""工具档案注册表：汇总所有深度定制工具。

- all_schemas()：全部专属 function schema（追加到 Agent 的 tools 列表）
- register_extensions(executor)：把每个档案的执行器挂到 Executor.extensions
- lore_for(history)：根据对话内容按需注入相关档案的深度知识（省 token）
- inventory()：已定制工具清单（用于系统提示词/状态展示）
"""

from __future__ import annotations

from typing import Any

from .base import ToolProfile
from .bloodhound import BloodHoundPyProfile
from .masscan import MasscanProfile
from .kerbrute import KerbruteProfile
from .whatweb import WhatWebProfile
from .drupwn import DrupwnProfile
from .subfinder import SubfinderProfile
from .gau import GauProfile
from .directory_list import DirectoryListProfile
from .dnsx import DnsxProfile
from .katana import KatanaProfile
from .aircrack import AircrackProfile
from .api_enum import ApiEnumProfile
from .airmon import AirmonProfile
from .cewl import CewlProfile
from .cmd_inject import CmdInjectProfile
from .chisel import ChiselProfile
from .crack import CrackProfile
from .csrf_check import CsrfCheckProfile
from .cve_lookup import CveLookupProfile
from .crtsh import CrtshProfile
from .cookie_check import CookieCheckProfile
from .curl import CurlProfile
from .default_page import DefaultPageProfile
from .dnsrecon import DnsreconProfile
from .email_auth import EmailAuthProfile
from .error_leak import ErrorLeakProfile
from .enum4linux import Enum4linuxProfile
from .evilwinrm import EvilWinrmProfile
from .exif_meta import ExifMetaProfile
from .ffuf import FfufProfile
from .ftp import FtpProfile
from .getnpusers import GetNPUsersProfile
from .getuserspns import GetUserSPNsProfile
from .gitleak import GitLeakProfile
from .gobuster import GobusterProfile
from .hashid import HashidProfile
from .joomscan import JoomlaScanProfile
from .js_extract import JsExtractProfile
from .jwt_check import JwtCheckProfile
from .header_check import HeaderCheckProfile
from .hping3 import Hping3Profile
from .httpx import HttpxProbeProfile
from .http_methods import HttpMethodsProfile
from .hydra import HydraProfile
from .impexec import ImpExecProfile
from .ldapsearch import LdapsearchProfile
from .linpeas import LinpeasProfile
from .lateral import LateralProfile
from .macchanger import MacchangerProfile
from .msf import MsfProfile
from .msfvenom import MsfvenomProfile
from .netcat import NcProfile
from .netdiscover import NetdiscoverProfile
from .nfs import NfsEnumProfile
from .nikto import NiktoProfile
from .nmap import NmapProfile
from .nuclei import NucleiProfile
from .open_redirect import OpenRedirectProfile
from .page_scan import PageScanProfile
from .param_discover import ParamDiscoverProfile
from .path_traversal import PathTraversalProfile
from .plain_login import PlainLoginProfile
from .playbook import PlaybookProfile
from .privesc import PrivescProfile
from .redis import RedisProfile
from .report_gen import ReportGenProfile
from .rsync import RsyncEnumProfile
from .responder import ResponderProfile
from .searchsploit import SploitProfile
from .secret_scan import SecretScanProfile
from .secretsdump import SecretsdumpProfile
from .smbclient import SmbclientProfile
from .smbmap import SmbmapProfile
from .snmp import SnmpEnumProfile
from .ssh_banner import SshBannerProfile
from .smtpenum import SmtpEnumProfile
from .socat import SocatProfile
from .ssrf_check import SsrfCheckProfile
from .sqlmap import SqlmapProfile
from .sub_takeover import SubTakeoverProfile
from .sslscan import SslscanProfile
from .tcpdump import TcpdumpProfile
from .testssl import TestsslProfile
from .theharvester import TheHarvesterProfile
from .tshark import TsharkProfile
from .upload_detect import UploadDetectProfile
from .vuln_detect import VulnDetectProfile
from .vuln_proof import VulnProofProfile
from .waf_bypass import WafBypassProfile
from .wafw00f import Wafw00fProfile
from .xxe_check import XxeCheckProfile
from .web_leak import WebLeakProfile
from .wfuzz import WfuzzProfile
from .whois_lookup import WhoisLookupProfile
from .wpscan import WpscanProfile
from .xss_check import XssCheckProfile

REGISTRY: list[ToolProfile] = [
    BloodHoundPyProfile(),
    MasscanProfile(),
    KerbruteProfile(),
    WhatWebProfile(),
    DrupwnProfile(),
    SubfinderProfile(),
    GauProfile(),
    DirectoryListProfile(),
    DnsxProfile(),
    KatanaProfile(),
    NmapProfile(),
    MsfProfile(),
    NiktoProfile(),
    GitLeakProfile(),
    GobusterProfile(),
    SploitProfile(),
    HttpxProbeProfile(),
    HttpMethodsProfile(),
    HydraProfile(),
    SqlmapProfile(),
    SubTakeoverProfile(),
    CrackProfile(),
    CsrfCheckProfile(),
    CveLookupProfile(),
    WhoisLookupProfile(),
    WpscanProfile(),
    XssCheckProfile(),
    EmailAuthProfile(),
    ErrorLeakProfile(),
    Enum4linuxProfile(),
    SmbmapProfile(),
    SnmpEnumProfile(),
    SshBannerProfile(),
    DefaultPageProfile(),
    DnsreconProfile(),
    FfufProfile(),
    AircrackProfile(),
    ApiEnumProfile(),
    MsfvenomProfile(),
    TcpdumpProfile(),
    NucleiProfile(),
    ResponderProfile(),
    EvilWinrmProfile(),
    ExifMetaProfile(),
    NcProfile(),
    SmbclientProfile(),
    LdapsearchProfile(),
    LinpeasProfile(),
    SecretScanProfile(),
    SecretsdumpProfile(),
    ChiselProfile(),
    GetNPUsersProfile(),
    GetUserSPNsProfile(),
    SocatProfile(),
    SsrfCheckProfile(),
    TsharkProfile(),
    UploadDetectProfile(),
    HeaderCheckProfile(),
    Hping3Profile(),
    ImpExecProfile(),
    WebLeakProfile(),
    WfuzzProfile(),
    NetdiscoverProfile(),
    NfsEnumProfile(),
    AirmonProfile(),
    MacchangerProfile(),
    CrtshProfile(),
    CookieCheckProfile(),
    CurlProfile(),
    SslscanProfile(),
    Wafw00fProfile(),
    XxeCheckProfile(),
    RedisProfile(),
    ReportGenProfile(),
    RsyncEnumProfile(),
    FtpProfile(),
    TheHarvesterProfile(),
    TestsslProfile(),
    SmtpEnumProfile(),
    HashidProfile(),
    JoomlaScanProfile(),
    JsExtractProfile(),
    JwtCheckProfile(),
    CewlProfile(),
    CmdInjectProfile(),
    OpenRedirectProfile(),
    PageScanProfile(),
    ParamDiscoverProfile(),
    PathTraversalProfile(),
    PlainLoginProfile(),
    PlaybookProfile(),
    WafBypassProfile(),
    VulnProofProfile(),
    VulnDetectProfile(),
    PrivescProfile(),
    LateralProfile(),
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
