"""hydra 深度定制：在线口令爆破封装（危险操作，触发确认）。"""

from __future__ import annotations

import re
import shlex
from typing import Any

from .base import (
    ToolProfile,
    check_installed,
    sanitize_int,
    sanitize_target,
    sanitize_wordlist,
)

SERVICES = (
    "ssh", "ftp", "http-get", "http-post-form", "smb", "rdp",
    "mysql", "postgres", "snmp", "vnc", "telnet", "pop3", "imap",
)

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "hydra_brute",
            "description": (
                "对目标服务的口令进行在线爆破（hydra）。"
                "⚠ 危险操作：会触发确认弹窗；只允许对你有权测试的目标使用。"
                "用户名/密码至少要提供其一（或字典）。"
                "常见场景：nmap 发现 22/tcp ssh 开放 → 弱口令测试。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "protocol": {
                        "type": "string",
                        "enum": list(SERVICES),
                        "description": "服务协议",
                    },
                    "target": {"type": "string", "description": "目标 IP/域名"},
                    "port": {"type": "integer", "description": "端口（默认按协议）"},
                    "username": {"type": "string", "description": "单个用户名（与 userlist 二选一）"},
                    "userlist": {"type": "string", "description": "用户名字典（/usr/share/wordlists/ 下）"},
                    "password": {"type": "string", "description": "单个密码（与 passlist 二选一）"},
                    "passlist": {"type": "string", "description": "密码字典（/usr/share/wordlists/ 下）"},
                    "threads": {"type": "integer", "description": "并发线程（默认 16）"},
                    "service_options": {
                        "type": "string",
                        "description": "协议附加选项，如 http-post-form 的 'login:user^USER^&pass=^PASS^:F=incorrect'",
                    },
                },
                "required": ["protocol", "target"],
            },
        },
    },
]

_WORDLIST = re.compile(r"^/usr/share/wordlists/[\w./-]+$")
_VALUE_RE = re.compile(r"^[^\s;|&`$\\\"]{1,200}$")


def _check_value(v: str | None, label: str) -> str | None:
    if not v:
        return None
    v = v.strip()
    if not _VALUE_RE.match(v):
        raise ValueError(f"{label}含非法字符: {v!r}")
    return v


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    protocol = str(args.get("protocol") or "").strip().lower()
    if protocol not in SERVICES:
        raise ValueError(f"protocol 仅支持: {', '.join(SERVICES)}")
    target = sanitize_target(str(args["target"]))
    port = sanitize_int(args.get("port"), 0, 0, 65535, "port")
    threads = sanitize_int(args.get("threads"), 16, 1, 64, "threads")

    username = _check_value(str(args.get("username") or ""), "username")
    userlist = sanitize_wordlist(str(args.get("userlist") or ""), label="userlist") if args.get("userlist") else None
    password = _check_value(str(args.get("password") or ""), "password")
    passlist = sanitize_wordlist(str(args.get("passlist") or ""), label="passlist") if args.get("passlist") else None

    if not (username or userlist):
        raise ValueError("username 与 userlist 至少提供一个")
    if not (password or passlist):
        raise ValueError("password 与 passlist 至少提供一个")
    if username and userlist:
        raise ValueError("username 与 userlist 只能二选一")

    parts = ["hydra"]
    if username:
        parts += ["-l", username]
    else:
        parts += ["-L", userlist]
    if password:
        parts += ["-p", password]
    else:
        parts += ["-P", passlist]
    parts += ["-t", str(threads), "-f"]  # -f 命中即停
    if port:
        parts += ["-s", str(port)]
    so = str(args.get("service_options") or "").strip()
    if so:
        if len(so) > 300 or "\n" in so:
            raise ValueError("service_options 过长或含换行")
        # 表单串含 & ^ = : 等字符，必须整体 shell 引用防止拆分
        parts += ["-m", shlex.quote(so)]
    # hydra 语法要求 service://host 形式（空格分隔会被当 Unknown service）
    parts += [f"{protocol}://{target}"]
    return " ".join(parts), 600


class HydraProfile(ToolProfile):
    name = "hydra"
    aliases = ["爆破", "口令爆破", "弱口令", "brute force", "密码破解"]
    summary = "在线服务口令爆破"
    lore = """### hydra 深度使用要点
- 定位：nmap 发现开放服务后，对 ssh/ftp/rdp/http 等做弱口令测试。
- 先试单用户名+小字典（如 rockyou 前几行或常见密码表）快速验证，命中即停（-f）。
- 字典都在 /usr/share/wordlists/ 下：rockyou.txt（需先 gunzip）、dirb/、dirbuster/。
- http-post-form 需要 service_options 指定表单格式：`login=^USER^&pass=^PASS^:F=<登录失败特征>`。
- 爆破是高风险行为：确认弹窗会拦截；务必只对授权目标使用，并向用户说明计划。
- 命中后立即验证：ssh 直接尝试登录确认凭据有效。"""
    extra_schemas = SCHEMAS

    async def exec_hydra_brute(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("hydra"):
            return "hydra 未安装（apt install hydra）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        # 命中行格式: [22][ssh] host: 1.2.3.4   login: root   password: toor
        hits = [
            l.strip()
            for l in raw.splitlines()
            if re.search(r"login:\s*\S+\s+password:\s*\S+", l)
        ]
        if hits:
            head = ["🎯 爆破命中:"] + hits[:20]
            head.append("下一步：立即用该凭据验证登录。")
        else:
            head = ["未命中（尝试的组合全部失败或超时）。建议换字典/用户名单或降低并发。"]
        return self._summary(raw, head, tail=40)
