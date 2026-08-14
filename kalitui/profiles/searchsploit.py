"""searchsploit 深度定制：本地 ExploitDB 漏洞利用代码搜索/定位/查看。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "sploit_search",
            "description": (
                "在本地 ExploitDB 数据库中搜索已知漏洞利用代码。"
                "关键词用服务名+版本（如 'vsftpd 2.3.4'）或 CVE 编号（如 'cve-2014-6271'）。"
                "找到 exploit 后可以用 sploit_show 查看详情。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {"type": "string", "description": "搜索关键词，如服务名/版本/CVE"},
                    "exact": {
                        "type": "boolean",
                        "description": "精确匹配模式（-e），适合搜 CVE 编号",
                    },
                },
                "required": ["keyword"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sploit_show",
            "description": (
                "查看某个 exploit 的详细信息（-p 路径 + -x 利用代码预览）。"
                "用于评估该漏洞利用是否适用于当前目标环境。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "exploit_id": {
                        "type": "string",
                        "description": "ExploitDB ID（搜索结果的第一个数字列），如 '49757'",
                    },
                    "preview": {
                        "type": "boolean",
                        "description": "是否预览利用代码（-x，可能很长），默认 false 只看路径与描述",
                    },
                },
                "required": ["exploit_id"],
            },
        },
    },
]

_ID_RE = re.compile(r"^\d{1,7}$")


def _check_keyword(kw: str) -> str:
    k = kw.strip()
    if not k or len(k) > 120:
        raise ValueError("关键词不能为空且不超过 120 字符")
    if any(c in k for c in ";|&`$\\\n\""):
        raise ValueError(f"关键词含非法字符: {k!r}")
    return k


class SploitProfile(ToolProfile):
    name = "searchsploit"
    aliases = ["exploitdb", "漏洞利用代码", "exploit 搜索", "exp 搜索", "cve 搜索"]
    summary = "本地 ExploitDB 漏洞利用代码搜索"
    lore = """### searchsploit 深度使用要点
- 定位：nmap 拿到服务+版本后，用它查对应 exploit：`sploit_search('服务名 版本')`。
- 版本号要精确：'vsftpd 2.3.4' 比 'vsftpd' 命中准得多；CVE 编号用 exact 模式。
- 结果看 Title 与 Path：Path 末尾是 ExploitDB ID（sploit_show 用它）。
- 优先级：`linux/remote` 的 RCE 优先于 DoS；本地提权 exploit 需先确认目标权限。
- 找到可用 exploit 后，评估是否适合当前目标（架构/内核/服务配置），再决定是否 msf_run 或手动利用。
- 查看代码时注意 exploit 的依赖（编译器、库、python 版本）。"""
    extra_schemas = SCHEMAS

    async def exec_sploit_search(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("searchsploit"):
            return "searchsploit 未安装（apt install exploitdb）。"
        kw = _check_keyword(str(args.get("keyword") or ""))
        exact = bool(args.get("exact"))
        cmd = f"searchsploit {'-e ' if exact else ''}{kw}"
        raw = await self._run(ex, cmd, timeout=90)
        lines = raw.splitlines()
        # 新版 searchsploit 输出: "Title ... | Path（ID 在 Path 文件名里）"
        hits = []
        for l in lines:
            l = l.strip()
            if "|" not in l or l.startswith("Exploit Title") or set(l.strip()) <= set("-| "):
                continue
            title, _, path = l.partition("|")
            m = re.search(r"(\d{4,7})\.(py|rb|pl|sh|c|php|txt|java|go|js)$", path.strip())
            if m:
                hits.append(f"[{m.group(1)}] {title.strip()}  →  {path.strip()}")
        if not hits:
            return f"searchsploit 无匹配（关键词：{kw}）。建议换更短的关键词或搜 CVE 编号。\n\n原始输出:\n{raw[-1500:]}"
        head = hits[:25]
        if len(hits) > 25:
            head.append(f"… 共 {len(hits)} 条匹配")
        head.append("下一步：用 sploit_show(<ExploitDB ID>) 查看详情。")
        return self._summary(raw, head, tail=25)

    async def exec_sploit_show(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("searchsploit"):
            return "searchsploit 未安装（apt install exploitdb）。"
        eid = str(args.get("exploit_id") or "").strip()
        if not _ID_RE.match(eid):
            raise ValueError(f"exploit_id 应为数字 ID: {eid!r}")
        preview = bool(args.get("preview"))
        if preview:
            cmd = f"searchsploit -x {eid}"
            timeout = 60
        else:
            cmd = f"searchsploit -p {eid}"
            timeout = 30
        raw = await self._run(ex, cmd, timeout=timeout)
        head = [l.strip() for l in raw.splitlines() if l.strip()][:30]
        if preview:
            head = head[:15] + ["…（利用代码较长，已截断；如需完整代码可让用户手动查看）"]
        return self._summary(raw, head, tail=40)
