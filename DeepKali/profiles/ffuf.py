"""ffuf 深度定制：快速 Web 模糊测试（目录/参数，Go 实现极快）。"""

from __future__ import annotations

import re
from typing import Any

from .base import (
    ToolProfile,
    check_installed,
    sanitize_int,
    sanitize_url,
    sanitize_wordlist,
)

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "ffuf_dir",
            "description": (
                "用 ffuf 对 Web 目标做高速目录/文件模糊测试（FUZZ 占位符）。"
                "比 gobuster 快一个数量级，适合大字典。"
                "与 dir_brute 互补：dir_brute 看常见目录，ffuf 可带扩展名/大字典深挖。"
                "外部目标需授权。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，FUZZ 为占位符，如 http://target/FUZZ 或 http://target/api/FUZZ",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": f"字典路径（默认 {DEFAULT_WORDLIST}）",
                    },
                    "extensions": {
                        "type": "string",
                        "description": "追加扩展名（逗号分隔），如 'php,txt,bak'",
                    },
                    "threads": {"type": "integer", "description": "并发（默认 40）"},
                    "match_codes": {
                        "type": "string",
                        "description": "只保留这些状态码，如 '200,301,403'（默认 200,204,301,302,307,401,403,405,500）",
                    },
                    "max_time": {
                        "type": "integer",
                        "description": "最大运行秒数（默认 120，防止大字典跑太久）",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_EXT_RE = re.compile(r"^[a-zA-Z0-9]{1,10}(,[a-zA-Z0-9]{1,10}){0,9}$")
_CODE_RE = re.compile(r"^\d{3}(,\d{3}){0,9}$")
_FUZZ_RE = re.compile(r"^https?://[^\s;|&`$\\]+FUZZ[^\s;|&`$\\]*$", re.IGNORECASE)


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    url = str(args["url"]).strip()
    if not _FUZZ_RE.match(url):
        raise ValueError("url 必须含 FUZZ 占位符且格式合法（如 http://target/FUZZ）")
    url = sanitize_url(url, label="url")  # 复用 URL 字符校验
    wordlist = sanitize_wordlist(str(args.get("wordlist") or DEFAULT_WORDLIST))
    threads = sanitize_int(args.get("threads"), 40, 1, 500, "threads")
    max_time = sanitize_int(args.get("max_time"), 120, 10, 3600, "max_time")
    exts = str(args.get("extensions") or "").strip().lstrip(".")
    if exts and not _EXT_RE.match(exts):
        raise ValueError(f"extensions 格式非法: {exts!r}")
    codes = str(args.get("match_codes") or "").strip()
    if codes and not _CODE_RE.match(codes):
        raise ValueError(f"match_codes 格式非法: {codes!r}")

    parts = ["ffuf", "-u", url, "-w", wordlist, "-t", str(threads), "-maxtime", str(max_time)]
    if exts:
        parts += ["-x", exts]
    parts += ["-mc", codes or "200,204,301,302,307,401,403,405,500"]
    parts.append("-s")  # 安静模式：只输出命中，便于解析
    return " ".join(parts), max_time + 15


def _summarize(raw: str) -> str:
    # 安静模式（-s）每行一个命中：裸路径或完整 URL
    hits = [
        l.strip()
        for l in raw.splitlines()
        if l.strip() and not l.strip().startswith(("::", "命令:", "ffuf", "Progress:"))
    ]
    head = hits[:50] if hits else ["未发现命中（可换字典/扩展名/放宽状态码）"]
    if len(hits) > 50:
        head.append(f"… 共 {len(hits)} 条命中")
    head.append("下一步建议：对命中的路径用 curl 查看内容，评估是否可进一步利用。")
    return ToolProfile._summary(raw, head, tail=50)


class FfufProfile(ToolProfile):
    name = "ffuf"
    aliases = ["模糊测试", "fuzz", "目录模糊", "web 模糊"]
    summary = "高速 Web 模糊测试"
    lore = """### ffuf 深度使用要点
- 与 gobuster 区别：ffuf 是 Go 写的，多核并发快一个数量级；支持多字典/扩展名矩阵。
- URL 用 FUZZ 占位符：`http://target/FUZZ` 扫目录，`http://target/?id=FUZZ` 可扫参数。
- -mc 过滤状态码减少噪音；-x 追加扩展名（php,txt,bak）；-maxtime 防止大字典失控。
- 命中 200 的路径立即 curl 看内容；403 的目录可试路径穿越/斜杠绕过。
- 配合 nikto（已知漏洞）和 gobuster（常见目录）形成 Web 枚举组合拳。"""
    extra_schemas = SCHEMAS

    async def exec_ffuf_dir(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("ffuf"):
            return "ffuf 未安装（apt install ffuf）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
