"""whatweb：Web 技术栈指纹识别（服务器/框架/CMS/中间件，SRC 侦察第二步）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "whatweb",
            "description": (
                "用 whatweb 识别目标 Web 站点的技术栈（HTTP 服务器/框架/CMS/"
                "中间件/脚本语言/前端库）。nmap/httpx 摸到服务后用它确认指纹，"
                "再按指纹选专项工具（wpscan/joomla_scan/drupwn/nuclei…）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://example.com",
                    },
                    "aggression": {
                        "type": "integer",
                        "description": "探测强度 1-3（默认 1；3 最全但可能触发告警）",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_PLUGIN_RE = re.compile(r"(?<!\[)([A-Za-z][\w+.-]{1,39})(?:\[[^\]]*\])")
_URL_RE = re.compile(
    r"^https?://[^\s/;|`$(){}\[\]]+(?:/[^\s;|`$(){}\[\]]*)?$", re.IGNORECASE
)


def _build_cmd(url: str, aggression: int) -> str:
    return f"whatweb -a {aggression} --color=never {url}", 120


def _summarize(raw: str) -> str:
    # whatweb 输出：http://x [200 OK] Apache[2.4.57] PHP[8.1] WordPress[6.4] [title]
    # 插件名在 [版本] 之前；跳过状态码与 URL 片段
    skip = {"http", "https", "title", "200", "404", "301", "302", "500", "ok",
            "not", "found", "moved", "permanently", "forbidden", "internal"}
    plugins: list[str] = []
    for m in _PLUGIN_RE.finditer(raw):
        plugin = m.group(1).strip()
        low = plugin.lower()
        if plugin and low not in skip and plugin not in plugins:
            plugins.append(plugin)
    # 去重保序
    seen: set[str] = set()
    unique = [p for p in plugins if not (p in seen or seen.add(p))]
    if not unique:
        return ToolProfile._summary(raw, ["未识别出技术栈（站点无响应/被 WAF 拦截）"], tail=20)
    head = [
        f"🎯 Web 技术栈（{len(unique)} 项）:",
        "  " + " / ".join(unique[:25]),
        "下一步：按指纹选专项——",
        "  WordPress→wpscan；Joomla→joomla_scan；Drupal→drupwn；",
        "  通用→nuclei -t cves/ 或 sqlmap/ffuf 深入。",
    ]
    return ToolProfile._summary(raw, head, tail=15)


class WhatWebProfile(ToolProfile):
    name = "whatweb"
    aliases = ["web 指纹", "whatweb", "技术栈", "指纹识别", "cms 检测"]
    summary = "Web 技术栈指纹识别"
    lore = """### whatweb 深度使用要点
- 定位：SRC 侦察的"确认指纹"步。nmap/httpx 告诉你端口开没开，
  whatweb 告诉你后面是什么（Apache/Nginx、PHP/Java、WordPress/Drupal…）。
  指纹决定了后续武器选择——指纹错则工具链全错。
- 参数：`-a 3` 全强度探测（可识别更多插件，但请求多、易触发告警，
  外网目标默认 -a 1）；`--color=never` 关颜色方便解析。
- 典型指纹→工具映射：WordPress→wpscan；Joomla→joomla_scan；
  Drupal→drupwn；泛用 CMS→nuclei；登录面板→hydra；API→swagger 探测。
- 联动：whatweb 确认版本后，用 searchsploit 查该版本已知漏洞，
  再决定走 nuclei CVE 模板还是手工验证（vuln_proof）。
- 输出解读：[] 内是插件名（Apache/PHP/WordPress/jQuery…），
  版本号跟在插件名后；多个 [200 OK] 行是重定向链，看最后一跳。"""
    extra_schemas = SCHEMAS

    async def exec_whatweb(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("whatweb"):
            return "whatweb 未安装（apt install whatweb）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            raise ValueError(f"url 必须是完整 URL（含 http/https）: {url!r}")
        aggression = args.get("aggression") or 1
        try:
            aggression = int(aggression)
        except (TypeError, ValueError):
            raise ValueError(f"aggression 必须是整数: {aggression!r}") from None
        if not 1 <= aggression <= 3:
            raise ValueError(f"aggression 超出范围: {aggression}")
        raw = await self._run(ex, *_build_cmd(url, aggression))
        return _summarize(raw)
