"""john / hashcat 深度定制：离线 hash 破解（危险操作，触发确认）。"""

from __future__ import annotations

import re
from typing import Any

from .base import (
    ToolProfile,
    check_installed,
    sanitize_int,
    sanitize_wordlist,
)

# 常用 hashcat 模式（-m）速查
HASHCAT_MODES: dict[str, int] = {
    "md5": 0, "sha1": 100, "sha256": 1400, "sha512": 1700,
    "ntlm": 1000, "ntlmv2": 5600, "bcrypt": 3200, "md5crypt": 500,
    "sha512crypt": 1800, "sha256crypt": 7400, "wpa": 22000,
}

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "crack_hash",
            "description": (
                "离线破解单个 hash（hashcat 优先，john 兜底）。"
                "⚠ 危险操作：会触发确认弹窗。hash 会写入临时文件再破解。"
                "典型场景：从 /etc/shadow、数据库、抓包（WPA）中获得的 hash。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hash": {"type": "string", "description": "要破解的 hash 字符串"},
                    "hash_type": {
                        "type": "string",
                        "enum": list(HASHCAT_MODES),
                        "description": "hash 类型（默认 md5）",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "字典路径（默认 /usr/share/wordlists/rockyou.txt，需存在）",
                    },
                    "rules": {
                        "type": "boolean",
                        "description": "是否启用规则变形（--rules，慢但更有效）",
                    },
                },
                "required": ["hash"],
            },
        },
    },
]

_HASH_RE = re.compile(r"^[A-Za-z0-9$:!*.\/=,]{1,512}$")


def _check_hash(h: str) -> str:
    h = h.strip()
    if not _HASH_RE.match(h):
        raise ValueError("hash 格式非法（仅允许 hex / 带 $ 分隔的密文）")
    return h


class CrackProfile(ToolProfile):
    name = "crack"
    aliases = ["破解 hash", "hash 破解", "john", "hashcat", "离线破解", "解密哈希", "破解"]
    summary = "离线 hash 破解（john/hashcat）"
    lore = """### 离线 hash 破解深度使用要点
- 类型识别：先看 hash 格式——`$6$` 开头是 sha512crypt（shadow）、`$2y$` 是 bcrypt、
  NTLM 是 32 位 hex、WPA 是 `WPA*` 开头 64 位。
- 默认用 hashcat + rockyou 字典（Kali 的 rockyou.txt 需先 `gunzip` 解压）。
- 破解失败时：启用 rules 变形 → 换大字典 → 换掩码（hashcat -a 3）逐级升级。
- bcrypt/sha512crypt 很慢：先用小字典；GPU 提速可用 `--force -D 1,2`。
- 破解出的明文密码是进一步横向/提权的关键，及时向用户汇报。"""
    extra_schemas = SCHEMAS

    async def exec_crack_hash(self, ex: Any, args: dict[str, Any]) -> str:
        hashcat_ok = check_installed("hashcat")
        john_ok = check_installed("john")
        if not (hashcat_ok or john_ok):
            return "hashcat 与 john 都未安装（apt install hashcat john）。"
        h = _check_hash(str(args.get("hash") or ""))
        htype = str(args.get("hash_type") or "md5").strip().lower()
        if htype not in HASHCAT_MODES:
            raise ValueError(f"hash_type 仅支持: {', '.join(HASHCAT_MODES)}")
        wordlist = (
            sanitize_wordlist(str(args.get("wordlist") or ""))
            if args.get("wordlist")
            else "/usr/share/wordlists/rockyou.txt"
        )
        rules = bool(args.get("rules"))

        import tempfile
        from pathlib import Path

        # hash 写入临时文件（避免命令行过长/特殊字符）
        tmp = Path(tempfile.mkdtemp(prefix="kalitui-crack-")) / "hash.txt"
        tmp.write_text(h + "\n", encoding="utf-8")

        mode = HASHCAT_MODES[htype]
        if hashcat_ok:
            cmd = (
                f"hashcat -m {mode} -a 0 {tmp} {wordlist} --force --potfile-disable"
                + (" --rules" if rules else "")
            )
            raw = await self._run(ex, cmd, timeout=600)
            # hashcat 命中格式: <hash>:<plain>
            hit = [l.strip() for l in raw.splitlines() if l.startswith(h.lower()) or l.startswith(h)]
            if hit:
                plain = hit[0].rsplit(":", 1)[-1]
                head = [f"🎯 破解成功: {htype} = {plain}（字典: {wordlist}）"]
                head.append("下一步：立即验证该密码在其他服务/系统上的复用情况。")
                return self._summary(raw, head, tail=30)
        if john_ok:
            fmt = {"ntlm": "nt", "ntlmv2": "netntlmv2", "wpa": "wpapsk"}.get(htype)
            cmd = f"john --format={fmt} {tmp} --wordlist={wordlist}" if fmt else f"john {tmp} --wordlist={wordlist}"
            raw = await self._run(ex, cmd, timeout=600)
            hit = [l.strip() for l in raw.splitlines() if " (" in l and ")" in l]
            if hit:
                return self._summary(raw, [f"🎯 john 破解结果: {hit[0]}"], tail=30)
        return (
            f"未破解成功（{htype}，字典 {wordlist}{' + rules' if rules else ''}）。\n"
            f"建议：1) 启用 rules 重试  2) 换大字典（如 rockyou 全量）  3) 确认 hash 类型是否正确。\n\n"
            f"原始输出（尾部）:\n{raw[-1500:]}"
        )
