"""hashid 深度定制：hash 类型识别（配合 crack_hash 使用）。"""

from __future__ import annotations

import re
import shlex
from typing import Any

from .base import ToolProfile, check_installed

_HASH_RE = re.compile(r"^[A-Za-z0-9$:!*.\/=,]{4,512}$")  # 与 crack 档案一致

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "hash_id",
            "description": (
                "识别 hash 的类型（hashid）：MD5/SHA/NTLM/ bcrypt/kerberos 等。"
                "拿到未知 hash（来自 secretsdump/crack 目标/网站数据库）先用它判断类型，"
                "再用 crack_hash 指定正确类型破解。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hash": {"type": "string", "description": "要识别的 hash 字符串"},
                    "john": {
                        "type": "boolean",
                        "description": "输出 john 格式提示（-j），默认 false",
                    },
                },
                "required": ["hash"],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    hashv = str(args["hash"]).strip()
    if not _HASH_RE.match(hashv):
        raise ValueError("hash 含非法字符（仅允许 hash 字符集）")
    if len(hashv) > 200:
        raise ValueError("hash 过长（最大 200 字符）")
    parts = ["hashid", "-m"]
    if args.get("john"):
        parts.append("-j")
    parts.append(shlex.quote(hashv))  # hash 含 $ 会被 bash 变量展开，必须引用
    return " ".join(parts), 30


class HashidProfile(ToolProfile):
    name = "hashid"
    aliases = ["hash 识别", "hashid", "hash 类型", "识别 hash", "hash"]
    summary = "hash 类型识别"
    lore = """### hashid 深度使用要点
- 定位：破解前先识别类型——MD5 用 hashcat -m 0、NTLM 用 -m 1000、kerberos 用 crack 档案对应类型。
- -m 输出 hashcat 模式号（直接对应用法）；-j 输出 john 格式名。
- 常见混淆：MD5(32 hex) 与 NTLM(32 hex) 同形，需结合来源判断（secretsdump 的 NTLM、网站库的 MD5）。
- 带盐 hash（$1$、$6$、bcrypt $2）识别简单；识别不出时考虑自定义格式。
- 与 crack_hash 联动：hash_id 识别 → crack_hash 指定类型破解。"""
    extra_schemas = SCHEMAS

    async def exec_hash_id(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("hashid"):
            return "hashid 未安装（apt install hashid）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        lines = [l.strip() for l in raw.splitlines() if "[" in l and "]" in l]
        head = [f"hash 类型候选 ({len(lines)}):"] + lines[:15] if lines else ["未能识别（尝试 hashcat --example-hashes 对比）"]
        if lines:
            head.append("下一步：用 crack_hash 指定最可能的类型破解。")
        return self._summary(raw, head, tail=30)
