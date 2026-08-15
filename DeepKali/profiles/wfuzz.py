"""wfuzz 深度定制：Web 模糊测试（FUZZ 占位符，字典注入）。"""

from __future__ import annotations

import re
import shlex
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
            "name": "wfuzz_fuzz",
            "description": (
                "用 wfuzz 对 Web 目标做字典模糊测试（FUZZ 占位符，可多字典/多位置）。"
                "与 ffuf_dir/dir_brute 互补：wfuzz 支持复杂请求（cookie/header/多 FUZZ 位）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，FUZZ 为占位符，如 http://target/FUZZ",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": f"字典路径（默认 {DEFAULT_WORDLIST}）",
                    },
                    "match_codes": {
                        "type": "string",
                        "description": "只看这些状态码，如 '200,301'（默认 200）",
                    },
                    "hide_codes": {
                        "type": "string",
                        "description": "忽略这些状态码，如 '404'",
                    },
                    "threads": {"type": "integer", "description": "并发（默认 20）"},
                    "cookie": {
                        "type": "string",
                        "description": "Cookie（可选），如 'session=abc123'",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_CODE_RE = re.compile(r"^\d{3}(,\d{3}){0,9}$")
_COOKIE_RE = re.compile(r"^[\w;=, .@-]{1,300}$")
_FUZZ_RE = re.compile(r"^https?://[^\s;|&`$\\]+FUZZ[^\s;|&`$\\]*$", re.IGNORECASE)


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    url = str(args["url"]).strip()
    if not _FUZZ_RE.match(url):
        raise ValueError("url 必须含 FUZZ 占位符且格式合法（如 http://target/FUZZ）")
    url = sanitize_url(url, label="url")
    wordlist = sanitize_wordlist(str(args.get("wordlist") or DEFAULT_WORDLIST))
    threads = sanitize_int(args.get("threads"), 20, 1, 200, "threads")
    mc = str(args.get("match_codes") or "").strip()
    if mc and not _CODE_RE.match(mc):
        raise ValueError(f"match_codes 格式非法: {mc!r}")
    hc = str(args.get("hide_codes") or "").strip()
    if hc and not _CODE_RE.match(hc):
        raise ValueError(f"hide_codes 格式非法: {hc!r}")
    if mc and hc:
        raise ValueError("match_codes 与 hide_codes 只能指定一个")
    cookie = str(args.get("cookie") or "").strip()
    if cookie and not _COOKIE_RE.match(cookie):
        raise ValueError(f"cookie 含非法字符: {cookie!r}")

    parts = ["wfuzz", "-w", wordlist, "-t", str(threads)]
    if cookie:
        parts += ["-b", shlex.quote(cookie)]  # cookie 含 ; 空格，必须 shell 引用
    # 注：不传 --hc/--sc——实测部分版本在管道模式下过滤不生效，
    # 改为在 _summarize 里对结果行自行过滤（更可靠）。
    parts.append(url)
    return " ".join(parts), 180


def _summarize(raw: str, mc: str = "", hc: str = "") -> str:
    import re as _re

    mc_set = set(mc.split(",")) if mc else None
    hc_set = set(hc.split(",")) if hc else {"404"}

    rows = []
    for l in raw.splitlines():
        l = _re.sub(r"\x1b\[[0-9;]*m", "", l).strip()  # 剥离 ANSI 色码
        m = _re.match(r"^(\d+):\s*(\d{3})\s", l)
        if m:
            code = m.group(2)
            if mc_set is not None and code not in mc_set:
                continue
            if code in hc_set:
                continue
            rows.append(l)
        elif l.startswith("ID "):
            rows.append(l)
    if rows:
        head = ["wfuzz 命中:"] + rows[:30]
        if len(rows) > 30:
            head.append(f"… 共 {len(rows)} 条")
    else:
        head = ["未发现命中（换字典/放宽过滤）"]
    return ToolProfile._summary(raw, head, tail=45)


class WfuzzProfile(ToolProfile):
    name = "wfuzz"
    aliases = ["wfuzz", "字典爆破", "web 模糊", "fuzz 测试"]
    summary = "Web 字典模糊测试"
    lore = """### wfuzz 深度使用要点
- 与 ffuf 区别：wfuzz 更老牌，支持多 FUZZ 位置（`/FUZZ?p=FUZZ2` 多字典）、复杂 header/cookie。
- 常用：-z 指定字典（默认 -w）；--hc 404 隐藏噪音；-b 带 cookie 绕过登录页。
- 进阶：`-z range,1-100` 数字爆破；`-z file,dict1 -z file,dict2` 笛卡尔组合。
- 命中后 curl 验证内容；403 目录尝试路径绕过（/..;/、大小写、编码）。
- 本封装输出已按 状态码+大小 过滤，噪音较大时可加 hide_codes 或换 ffuf。"""
    extra_schemas = SCHEMAS

    async def exec_wfuzz_fuzz(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("wfuzz"):
            return "wfuzz 未安装（apt install wfuzz）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(
            raw,
            mc=str(args.get("match_codes") or "").strip(),
            hc=str(args.get("hide_codes") or "").strip(),
        )
