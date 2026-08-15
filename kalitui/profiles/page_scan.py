"""HTML 注释信息泄露检查：抓取页面并提取含敏感词的 HTML 注释。

白帽定位：高频信息泄露——开发者注释里常残留内部路径、凭据、TODO、
调试开关（<!-- admin: /internal/login?debug=1 -->），是低危但真实的
提交项，也给后续利用指路。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_SENSITIVE = (
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "user", "admin", "login", "todo", "fixme", "debug", "test", "key",
    "internal", "vpn", "ssh", "ftp", "db_", "sql", "mysql", "token",
    "session", "cookie", "upload", "/admin", "/internal", "10.0.", "192.168.",
)
_MAX_COMMENTS = 15
_MAX_LEN = 4096 * 4  # 响应体上限（防超大页面拖垮）

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "page_scan",
            "description": (
                "页面信息泄露检查：抓取页面提取 HTML 注释，筛选含 password/token/"
                "admin/debug/内部路径等敏感词的开发者残留信息。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标页面 URL，如 http://target.com/index.html",
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str) -> str:
    return f"curl -s -m 15 '{url}'"


def _extract_comments(raw: str) -> list[str]:
    return [c.strip() for c in _COMMENT_RE.findall(raw)]


def _filter_comments(comments: list[str]) -> list[str]:
    out: list[str] = []
    for c in comments:
        if not c:
            continue
        low = c.lower()
        if any(k in low for k in _SENSITIVE):
            out.append(c)
    return out


def _summarize(raw: str, url: str) -> str:
    all_comments = _extract_comments(raw)
    hits = _filter_comments(all_comments)
    head: list[str] = [f"📄 {url} 注释信息泄露检查:"]
    if hits:
        head.append(f"🚨 敏感注释命中 ({len(hits)}/{len(all_comments)}):")
        for c in hits[:_MAX_COMMENTS]:
            head.append(f"  <!-- {c[:120]} -->")
        if len(hits) > _MAX_COMMENTS:
            head.append(f"  … 共 {len(hits)} 条，其余见原始输出")
        head.append("下一步：注释里的路径/凭据/调试开关逐条验证（内部路径接目录枚举，"
                    "凭据接登录尝试——仅限授权测试）。")
    else:
        head.append(f"✅ 无敏感注释（共 {len(all_comments)} 条注释，均无敏感词）。")
    return ToolProfile._summary(raw, head, tail=20)


class PageScanProfile(ToolProfile):
    name = "page_scan"
    aliases = ["注释泄露", "页面检查", "源码注释", "html 注释", "注释扫描", "页面泄露"]
    summary = "HTML 注释信息泄露检查"
    lore = """### 页面注释泄露检查使用要点
- 定位：开发者注释残留——<!-- 内部路径 -->、<!-- admin: admin123 -->、<!-- debug=1 -->
  等是真实信息泄露（SRC 低危项），也给后续利用指路。
- 检查：抓页面 → 提取所有 HTML 注释 → 过滤敏感词（password/token/admin/todo/
  debug/内部 IP 段 192.168./10.0. 等 31 个词）。
- 结合流程：注释命中内部路径 → 直接访问或目录枚举（gobuster/ffuf）；
  命中凭据 → 登录接口尝试（hydra）；命中调试开关 → 开启看更多泄露。
- 注意：注释不敏感 ≠ 页面安全；只覆盖 HTML 注释，JS 内联字符串/源码映射
  需配合 secret_scan。动态渲染页面（SPA）注释少，需先抓渲染后 HTML。"""
    extra_schemas = SCHEMAS

    async def exec_page_scan(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://target.com/index.html）: {url!r}"
        raw = await self._run(ex, _build_cmd(url), timeout=30)
        if len(raw) > _MAX_LEN:
            raw = raw[:_MAX_LEN]
        return _summarize(raw, url)
