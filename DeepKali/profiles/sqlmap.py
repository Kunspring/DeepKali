"""sqlmap 深度定制：SQL 注入检测与利用（危险操作，触发确认）。"""

from __future__ import annotations

import re
import shlex
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int, sanitize_url

LEVELS = (1, 2, 3, 4, 5)
RISKS = (1, 2, 3)

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "sqlmap_check",
            "description": (
                "对带参数的 URL 进行 SQL 注入检测（sqlmap，--batch 全自动）。"
                "⚠ 危险操作：会触发确认弹窗；只允许对你有权测试的目标使用。"
                "适合 Web 枚举（gobuster/nikto）发现动态页面后使用。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "带参数的 URL，如 http://target/page.php?id=1",
                    },
                    "data": {
                        "type": "string",
                        "description": "POST 数据体，如 'user=admin&pass=1'（GET 参数不用填）",
                    },
                    "level": {
                        "type": "integer",
                        "enum": list(LEVELS),
                        "description": "检测深度 1-5（默认 1，越深越慢）",
                    },
                    "risk": {
                        "type": "integer",
                        "enum": list(RISKS),
                        "description": "风险等级 1-3（默认 1；3 会尝试基于时间/OR 的破坏性 payload）",
                    },
                    "cookie": {"type": "string", "description": "会话 Cookie（需要登录的页面）"},
                },
                "required": ["url"],
            },
        },
    },
]

_DATA_RE = re.compile(r"^[\w\-=&%+./:@\[\]{}]{1,2000}$")
_COOKIE_RE = re.compile(r"^[\w\-=&;% ]{1,500}$")  # 标准 cookie 头含 "; " 分隔


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    url = sanitize_url(str(args["url"]), allow_query=True)  # GET 注入 URL 必带 query
    level = sanitize_int(args.get("level"), 1, 1, 5, "level")
    risk = sanitize_int(args.get("risk"), 1, 1, 3, "risk")
    data = str(args.get("data") or "").strip()
    if data and not _DATA_RE.match(data):
        raise ValueError("data 含非法字符（仅允许 URL 编码表单字符）")
    cookie = str(args.get("cookie") or "").strip()
    if cookie and not _COOKIE_RE.match(cookie):
        raise ValueError("cookie 含非法字符")

    parts = ["sqlmap", "-u", shlex.quote(url), "--batch", "--flush-session", "--random-agent"]  # URL 含 & 已 shell 引用
    if data:
        parts += ["--data", data]
    if cookie:
        parts += ["--cookie", shlex.quote(cookie)]  # cookie 含 "; " 必须 shell 引用
    if level > 1:
        parts += ["--level", str(level)]
    if risk > 1:
        parts += ["--risk", str(risk)]
    # 检测为主：找到注入点即停，不自动拖库
    parts.append("--smart")
    return " ".join(parts), 600


def _summarize(raw: str) -> str:
    vulnerable = [
        l.strip()
        for l in raw.splitlines()
        if re.search(r"is vulnerable|Parameter: .* (GET|POST|Cookie)", l)
    ]
    payloads = [
        l.strip()
        for l in raw.splitlines()
        if re.match(r"Payload:", l) or "payload" in l.lower() and "[" in l
    ]
    if vulnerable:
        head = ["🎯 检测到注入点:"] + vulnerable[:10]
        if payloads:
            head.append("关键 Payload:")
            head += payloads[:8]
        head.append("下一步：确认数据库类型与权限后，评估是否进一步利用（拖库/写文件）。")
    else:
        head = ["未检测到可注入参数（level/risk 已按参数执行）。可提高 level 重试或换其他参数点。"]
    return ToolProfile._summary(raw, head, tail=45)


class SqlmapProfile(ToolProfile):
    name = "sqlmap"
    aliases = ["sql 注入", "注入检测", "sqli", "注入点"]
    summary = "SQL 注入自动检测"
    lore = """### sqlmap 深度使用要点
- 定位：gobuster/nikto 发现动态页面（.php?id= 等参数）后使用。
- GET 用 url 直接带参数；POST 用 data 传表单体；需要登录的页面务必带 cookie。
- level 1 只测 GET/POST 参数；level 3+ 会测 Header/JSON 等，慢很多。
- risk 3 的 payload 可能破坏数据（OR 条件），默认不开。
- --batch 全自动回答；--smart 跳过明显不存在的参数。
- 检出注入后：先看 DBMS 与当前用户权限（--current-user --current-db），
  提权/拖库等进一步动作先向用户确认再做。"""
    extra_schemas = SCHEMAS

    async def exec_sqlmap_check(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("sqlmap"):
            return "sqlmap 未安装（apt install sqlmap）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
