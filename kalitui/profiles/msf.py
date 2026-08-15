"""Metasploit 深度定制：msfconsole 非交互封装（搜索模块 / 配置并运行）。"""

from __future__ import annotations

import shlex
from typing import Any

from .base import ToolProfile, check_installed

_ACTIONS = ("run", "exploit", "check", "options", "info", "reload")

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "msf_search",
            "description": (
                "在 Metasploit 模块库中搜索 exploit/auxiliary 模块，"
                "如 msf_search('vsftpd') 或 msf_search('cve:2021-xxxx')。"
                "找到模块后用 msf_run 使用。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {"type": "string", "description": "搜索关键词，如服务名 / CVE 编号 / 类型"},
                },
                "required": ["keyword"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "msf_run",
            "description": (
                "非交互式使用 Metasploit 模块：use 模块、set 选项、执行动作。"
                "动作默认 run；exploit/run 会真正发起利用——必须确认目标是你有权测试的。"
                "check 只做安全检查不攻击。该操作会触发危险命令确认。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "module": {"type": "string", "description": "模块路径，如 exploit/multi/handler 或 auxiliary/scanner/ssh/ssh_version"},
                    "options": {
                        "type": "object",
                        "description": "选项字典，如 {'RHOSTS': '192.168.1.10', 'RPORT': '22'}",
                        "additionalProperties": {"type": "string"},
                    },
                    "action": {"type": "string", "enum": list(_ACTIONS), "description": "执行动作"},
                },
                "required": ["module"],
            },
        },
    },
]

_MODULE_RE = r"^[a-z0-9_]+(/[a-z0-9_]+)+$"  # exploit/multi/handler


def _check_module(module: str) -> str:
    import re

    m = module.strip()
    if not re.fullmatch(_MODULE_RE, m):
        raise ValueError(f"模块路径格式非法: {module!r}（应为 exploit/xxx/yyy）")
    return m


def _check_options(options: Any) -> dict[str, str]:
    import re

    if not isinstance(options, dict):
        raise ValueError("options 必须是字典")
    out: dict[str, str] = {}
    for k, v in options.items():
        if not re.fullmatch(r"[A-Za-z0-9_]{1,32}", str(k)):
            raise ValueError(f"选项名非法: {k!r}")
        sv = str(v).strip()
        if any(c in sv for c in ";|&`$\\\n"):
            raise ValueError(f"选项值含非法字符: {sv!r}")
        out[str(k)] = sv
    return out


def _build_script(args: dict[str, Any], *, search: bool) -> str:
    if search:
        kw = str(args.get("keyword") or "").strip()
        if not kw or any(c in kw for c in ";|&`$\\\n\""):
            raise ValueError(f"搜索关键词非法: {kw!r}")
        return f"search {kw}"
    module = _check_module(str(args.get("module") or ""))
    opts = _check_options(args.get("options") or {})
    action = str(args.get("action") or "run").strip()
    if action not in _ACTIONS:
        raise ValueError(f"action 仅支持: {', '.join(_ACTIONS)}")
    parts = [f"use {module}"]
    for k, v in opts.items():
        parts.append(f"set {k} {v}")
    if action == "run":
        parts.append("run -j")  # 后台运行，避免挂住
        parts.append("sleep 8")  # 给后台作业一点时间
    else:
        parts.append(action)
    return "; ".join(parts)


class MsfProfile(ToolProfile):
    name = "msf"
    aliases = ["metasploit", "msfconsole", "exploit", "漏洞利用"]
    summary = "Metasploit 非交互模块搜索与执行"
    lore = """### Metasploit 深度使用要点
- 工作流：`msf_search` 找模块（按服务名/CVE）→ `msf_run` 配置执行。
- 常用 auxiliary 侦察：ssh_version、smb_version、http_version、scanner/portscan/tcp 等。
- exploit 前必须确认目标与授权；`action=check` 可先做安全检查。
- 拿到 shell 后（session），提示用户进入交互式 msfconsole 更合适。
- 模块选项用 options 字典传：RHOSTS/RHOST/RPORT/LHOST/LPORT/SSL 等。
- run 采用后台作业方式避免 TUI 挂起；注意查看输出中的 [*] 信息行。"""
    extra_schemas = SCHEMAS

    async def exec_msf_search(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("msfconsole"):
            return "msfconsole 未安装（apt install metasploit-framework）。"
        script = _build_script(args, search=True)
        raw = await self._run(ex, f"msfconsole -q -x {shlex.quote(script)}", timeout=120)
        head = [l.strip() for l in raw.splitlines() if l.startswith("   ") and "/" in l][:25]
        return self._summary(raw, head or ["（无匹配模块）"], tail=25)

    async def exec_msf_run(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("msfconsole"):
            return "msfconsole 未安装（apt install metasploit-framework）。"
        script = _build_script(args, search=False)
        timeout = 240 if "run" in script else 120
        raw = await self._run(ex, f"msfconsole -q -x {shlex.quote(script)}", timeout=timeout)
        interesting = [l.strip() for l in raw.splitlines()
                       if l.startswith(("[*]", "[+]", "[!]", "[msf]"))]
        return self._summary(raw, interesting[:30] or ["（模块执行完毕，无关键事件行）"], tail=40)
