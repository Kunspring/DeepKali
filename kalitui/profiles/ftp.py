"""ftp 深度定制：匿名/凭据 FTP 访问检查（危险操作，触发确认）。"""

from __future__ import annotations

import re
import shlex
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "ftp_check",
            "description": (
                "检查 FTP 服务：匿名登录/凭据登录，列出根目录内容。"
                "⚠ 危险操作：会触发确认弹窗。"
                "内网/公网常见弱配置：匿名可读（甚至可写）；找到敏感文件（备份/配置）是渗透金矿。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "FTP 主机"},
                    "port": {"type": "integer", "description": "端口（默认 21）"},
                    "username": {
                        "type": "string",
                        "description": "用户名（默认 anonymous）",
                    },
                    "password": {
                        "type": "string",
                        "description": "密码（匿名默认留空）",
                    },
                },
                "required": ["host"],
            },
        },
    },
]

_CRED_RE = re.compile(r"^[\w.\-\\$@!]{1,128}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    host = sanitize_target(str(args["host"]))
    port = sanitize_int(args.get("port"), 21, 1, 65535, "port", strict=True)
    username = str(args.get("username") or "anonymous").strip()
    password = str(args.get("password") or "").strip()
    if not _CRED_RE.match(username):
        raise ValueError(f"username 含非法字符: {username!r}")
    if password and not _CRED_RE.match(password):
        raise ValueError(f"password 含非法字符: {password!r}")

    # curl ftp:// 匿名列表；带凭据用 user:pass@
    if username == "anonymous" and not password:
        url = f"ftp://{host}:{port}/"
    else:
        url = f"ftp://{shlex.quote(username)}:{shlex.quote(password)}@{host}:{port}/"
    return f"curl -s --max-time 20 {url}", 40


def _summarize(raw: str) -> str:
    entries = [l.strip() for l in raw.splitlines() if l.strip()]
    head: list[str] = []
    if entries:
        head.append(f"FTP 根目录 ({len(entries)} 项):")
        head += entries[:30]
        if len(entries) > 30:
            head.append(f"… 共 {len(entries)} 项")
        head.append("下一步建议：注意敏感文件（.bak/.conf/备份），可尝试下载分析。")
    else:
        head = ["无法列出目录（登录失败/主机不可达）"]
    return ToolProfile._summary(raw, head, tail=35)


class FtpProfile(ToolProfile):
    name = "ftp"
    aliases = ["ftp 检查", "匿名 ftp", "ftp 登录", "21 端口"]
    summary = "FTP 访问检查"
    lore = """### FTP 检查深度使用要点
- 定位：发现 21 端口后先试匿名（anonymous/空密码）——大量内网设备默认开匿名。
- 注意可写目录（上传权限）：可写 FTP 可传 webshell/恶意文件（仅授权测试）。
- 明文协议：FTP 传输的密码可用 tcpdump/tshark 直接抓取。
- 弱口令用 hydra（ftp 协议）；vsftpd 版本漏洞（如 2.3.4 backdoor）用 searchsploit 查。
- 本封装只列目录；下载文件/上传用 run_command 直接 curl 或提示用户进交互。"""
    extra_schemas = SCHEMAS

    async def exec_ftp_check(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
