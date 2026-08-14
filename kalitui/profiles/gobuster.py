"""gobuster 深度定制：Web 目录/子域爆破 + 结果摘要。"""

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

DEFAULT_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "dir_brute",
            "description": (
                "对 Web 目标进行目录/文件枚举（gobuster dir）。"
                "适合在 nmap 发现 Web 服务、nikto 扫完已知漏洞后，寻找隐藏目录、"
                "备份文件、管理后台。会发送大量请求——外部目标需授权。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL，如 http://192.168.1.10"},
                    "wordlist": {
                        "type": "string",
                        "description": f"字典路径（默认 {DEFAULT_WORDLIST}）",
                    },
                    "extensions": {
                        "type": "string",
                        "description": "追加扩展名（逗号分隔），如 'php,txt,bak'；留空不追加",
                    },
                    "threads": {"type": "integer", "description": "并发线程数（默认 20）"},
                    "status_codes": {
                        "type": "string",
                        "description": "只显示这些状态码，如 '200,301'；留空显示全部非 404",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_EXT_RE = re.compile(r"^[a-zA-Z0-9]{1,10}(,[a-zA-Z0-9]{1,10}){0,9}$")
_STATUS_RE = re.compile(r"^\d{3}(,\d{3}){0,9}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    url = sanitize_url(str(args["url"]))
    wordlist = sanitize_wordlist(str(args.get("wordlist") or DEFAULT_WORDLIST))
    threads = sanitize_int(args.get("threads"), 20, 1, 200, "threads")
    exts = str(args.get("extensions") or "").strip().lstrip(".")
    if exts and not _EXT_RE.match(exts):
        raise ValueError(f"extensions 格式非法: {exts!r}（应为 'php,txt'）")
    codes = str(args.get("status_codes") or "").strip()
    if codes and not _STATUS_RE.match(codes):
        raise ValueError(f"status_codes 格式非法: {codes!r}（应为 '200,301'）")
    cmd = f"gobuster dir -u {url} -w {wordlist} -t {threads}"
    if exts:
        cmd += f" -x {exts}"
    if codes:
        # -s 与默认 404 黑名单互斥（gobuster v3），指定 -s 时清空黑名单
        cmd += f" -s {codes} --status-codes-blacklist \"\""
    return cmd, 300


def _summarize(raw: str) -> str:
    hits = [l.strip() for l in raw.splitlines() if re.search(r"(Status: \d{3}|Found:)", l)]
    head = hits[:40] if hits else ["未发现可访问目录/文件"]
    if len(hits) > 40:
        head.append(f"… 共 {len(hits)} 条命中")
    head.append("下一步建议：对 200 的路径用 curl 查看内容，或继续深挖子目录。")
    return ToolProfile._summary(raw, head, tail=40)


class GobusterProfile(ToolProfile):
    name = "gobuster"
    aliases = ["目录枚举", "目录爆破", "dir brute", "目录扫描"]
    summary = "Web 目录/文件枚举"
    lore = """### gobuster 深度使用要点
- 定位：nmap 发现 Web 端口后，与 nikto 配合：nikto 查已知漏洞，gobuster 找隐藏路径。
- 默认字典在 /usr/share/wordlists/dirbuster/ 与 /usr/share/wordlists/dirb/ 下。
- 关注 Status 200/301/302/403：200 直接可访问；301 可跟进跳转；403 也值得记录（可能有绕过空间）。
- 命中管理后台/备份文件（.bak/.zip/.git）时优先向用户报告——通常是突破口。
- 大字典+高并发会打爆小站点，默认 20 线程适中。"""
    extra_schemas = SCHEMAS

    async def exec_dir_brute(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("gobuster"):
            return "gobuster 未安装（apt install gobuster）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
