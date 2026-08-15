"""smtp-user-enum 深度定制：SMTP 用户枚举（VRFY/EXPN/RCPT，危险操作）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int, sanitize_target

MODES = {
    "vrfy": "VRFY 命令（老服务器才支持）",
    "expn": "EXPN 命令（老服务器才支持）",
    "rcpt": "RCPT TO 枚举（最通用，默认）",
}

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "smtp_enum",
            "description": (
                "用 smtp-user-enum 枚举 SMTP 服务器上的有效用户（VRFY/EXPN/RCPT 三种方法）。"
                "⚠ 危险操作：会触发确认弹窗。"
                "枚举出的用户名用于后续口令测试（hydra smtp）或定向钓鱼。"
                "默认内置常用用户名列表（/usr/share/smtp-user-enum/users.txt）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "SMTP 服务器 IP"},
                    "port": {"type": "integer", "description": "端口（默认 25）"},
                    "mode": {
                        "type": "string",
                        "enum": list(MODES),
                        "description": "枚举方法（默认 rcpt）",
                    },
                    "users": {
                        "type": "string",
                        "description": "用户文件路径（默认 /usr/share/smtp-user-enum/users.txt）",
                    },
                    "domain": {
                        "type": "string",
                        "description": "域名（可选，RCPT 时附在用户名后）",
                    },
                },
                "required": ["host"],
            },
        },
    },
]

_FILE_RE = re.compile(r"^/[\w./-]{1,200}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    host = sanitize_target(str(args["host"]))
    port = sanitize_int(args.get("port"), 25, 1, 65535, "port", strict=True)
    mode = str(args.get("mode") or "rcpt").strip().lower()
    if mode not in MODES:
        raise ValueError(f"mode 仅支持: {', '.join(MODES)}")
    users = str(args.get("users") or "/usr/share/smtp-user-enum/users.txt").strip()
    if not _FILE_RE.match(users):
        raise ValueError(f"users 必须是文件路径: {users!r}")
    domain = str(args.get("domain") or "").strip()
    if domain and not re.fullmatch(r"[\w.-]{1,128}", domain):
        raise ValueError(f"domain 格式非法: {domain!r}")

    parts = ["smtp-user-enum", "-M", mode.upper(), "-U", users, "-t", host, "-p", str(port)]
    if domain:
        parts += ["-d", domain]
    return " ".join(parts), 180


class SmtpEnumProfile(ToolProfile):
    name = "smtp-enum"
    aliases = ["smtp 枚举", "用户枚举", "smtp-user-enum", "vrfy", "25 端口", "smtp"]
    summary = "SMTP 用户枚举"
    lore = """### smtp-user-enum 深度使用要点
- 定位：发现 25 端口后枚举有效用户；现代服务器大多禁 VRFY/EXPN，RCPT 最通用。
- 输出 'is a valid user' 即命中；命中用户名单直接用于 hydra（smtp 协议）口令测试。
- 大用户字典更全（rockyou 的用户名部分/自备字典）；域参数（-d）在 RCPT 模式把用户名变完整邮箱。
- 注意：部分服务器对多次 RCPT 限速/封禁，慢速小字典更稳。
- 与 crack/cewl 联动：枚举用户名 → cewl 生成密码词表 → hydra 爆破。"""
    extra_schemas = SCHEMAS

    async def exec_smtp_enum(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("smtp-user-enum"):
            return "smtp-user-enum 未安装（apt install smtp-user-enum）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        valid = [
            l.strip() for l in raw.splitlines()
            if re.search(r"(?i)\bis a valid user\b", l)
            and not re.search(r"(?i)\b(no|not)\s+valid", l)
        ]
        if valid:
            head = [f"🎯 有效用户 ({len(valid)}):"]
            head += valid[:30]
            head.append("下一步：用该用户名单做 hydra smtp 口令测试。")
        else:
            head = ["未枚举到有效用户（服务器禁用了枚举方法或名单无命中）"]
        return self._summary(raw, head, tail=40)
