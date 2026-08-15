"""默认页/未配置站点检测：识别服务器默认安装页（nginx/Apache/IIS 等）。

白帽定位：默认页 = 服务器未加固的强信号——常伴默认路径、默认凭据、
未移除的示例文件（/examples/、/manual/）；也是快速确认目标技术栈
与运维水平的方式。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)

# (特征子串, 说明)
_DEFAULTS: list[tuple[str, str]] = [
    ("welcome to nginx", "nginx 默认欢迎页"),
    ("test page for the nginx http server", "nginx（Fedora 系）测试页"),
    ("apache2 ubuntu default page", "Apache2（Ubuntu）默认页"),
    ("it works!", "Apache 默认页"),
    ("apache http server test page", "Apache（CentOS/RHEL）测试页"),
    ("iis windows server", "IIS 默认页（Windows Server）"),
    ("under construction", "通用占位页"),
    ("default web site page", "IIS 默认站点页"),
    ("congratulations, you have successfully", "ISP/面板默认页"),
    ("phpmyadmin - error", "phpMyAdmin 未配置错误页"),
]
_MAX_LEN = 32768

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "default_page",
            "description": (
                "默认页检测：抓取首页匹配 nginx/Apache/IIS/phpMyAdmin 等默认安装页特征"
                "——服务器未加固信号（常伴默认路径与默认凭据）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标首页 URL，如 http://t.com/",
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str) -> str:
    return f"curl -s -m 15 '{url}'"


def _match_defaults(raw: str) -> list[str]:
    low = raw.lower()
    return [note for frag, note in _DEFAULTS if frag in low]


def _summarize(raw: str, url: str) -> str:
    hits = _match_defaults(raw)
    head: list[str] = [f"🏠 {url} 默认页检测:"]
    if hits:
        head.append(f"🚨 疑似默认安装页 ({len(hits)}):")
        head += [f"  - {h}" for h in hits]
        head.append("下一步：检查默认路径（/manual/、/examples/、/test/、/phpmyadmin/）"
                    "与默认凭据（admin/admin 类）——仅限授权；确认站点是否在正式运营。")
        head.append("修复：移除默认页/示例文件、改默认凭据、统一错误页。")
    else:
        head.append("✅ 未匹配默认页特征——站点有自定义首页（正常运营迹象）。")
        head.append("提示：技术栈指纹用 whatweb；默认路径探测用 web_leak/gobuster。")
    return ToolProfile._summary(raw, head, tail=15)


class DefaultPageProfile(ToolProfile):
    name = "default_page"
    aliases = ["默认页", "默认站点", "未配置检测", "默认安装页", "首页检测", "it works"]
    summary = "默认页/未配置站点检测"
    lore = """### 默认页检测使用要点
- 定位：服务器装完没换首页 = 加固不足信号，常伴默认路径/默认凭据/示例文件。
- 10 个特征：nginx 欢迎页、Apache（Ubuntu/CentOS 变体）、IIS（Windows Server）、
  phpMyAdmin 错误页、ISP 面板默认页等。
- 结合流程：默认页命中 → web_leak 探默认路径（/manual//examples//test/）→
  默认凭据尝试（admin/admin、root/toor——仅限授权）→ 技术栈确认（whatweb）
  → cve_lookup 查版本漏洞。
- 判定注意：自定义首页也可能含 "It works!" 字样（误报低但存在）；
  匹配不中 ≠ 安全，可能只是换了首页但未加固（结合头/错误页检查）。
- 修复：移除默认页与示例、改默认凭据、404/500 统一处理。"""
    extra_schemas = SCHEMAS

    async def exec_default_page(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://t.com/）: {url!r}"
        raw = await self._run(ex, _build_cmd(url), timeout=25)
        if len(raw) > _MAX_LEN:
            raw = raw[:_MAX_LEN]
        return _summarize(raw, url)
