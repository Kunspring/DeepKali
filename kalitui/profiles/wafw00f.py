"""wafw00f 深度定制：WAF（Web 应用防火墙）识别。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "waf_detect",
            "description": (
                "用 wafw00f 识别目标是否在 Web 应用防火墙（WAF）后面，以及 WAF 类型。"
                "侦察阶段重要信息：有 WAF 时直接暴力扫描/注入会被拦截，需要调整策略。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL，如 http://target.com"},
                    "verbose": {
                        "type": "boolean",
                        "description": "详细模式（显示检测细节），默认 false",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_URL_RE = re.compile(r"^https?://[^\s;|&`$\\]{1,500}$", re.IGNORECASE)


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    url = str(args["url"]).strip()
    if not _URL_RE.match(url):
        raise ValueError(f"url 格式非法: {url!r}")
    parts = ["wafw00f", url]
    if args.get("verbose"):
        parts.append("-v")
    return " ".join(parts), 60


def _summarize(raw: str) -> str:
    lines = [l.strip() for l in raw.splitlines() if l.strip()]
    head: list[str] = []
    no_waf = any("No WAF" in l or "not behind" in l.lower() for l in lines)
    if no_waf:
        head = ["未检测到 WAF——目标可能直接暴露源站。"]
    else:
        waf = [
            l for l in lines
            if re.search(r"(is behind|WAF\s*:|identified)", l, re.IGNORECASE)
        ]
        if waf:
            head.append("🎯 WAF 检测结果:")
            head += waf[:10]
            head.append("提示：有 WAF 时调整扫描节奏（低速率），SQL 注入考虑编码绕过（仅授权测试）。")
        else:
            head = ["检测无结果（目标不可达或输出格式异常）"]
    return ToolProfile._summary(raw, head, tail=30)


class Wafw00fProfile(ToolProfile):
    name = "wafw00f"
    aliases = ["waf 检测", "wafw00f", "防火墙识别", "waf"]
    summary = "WAF 识别"
    lore = """### wafw00f 深度使用要点
- 定位：侦察阶段判断目标是否在 WAF 后——决定后续工具策略（sqlmap --tamper、慢速扫描）。
- 识别出具体 WAF（Cloudflare/ModSecurity/AWS WAF 等）后针对性绕过。
- 与 nmap/nikto 结果结合：目标有明显防护特征（403 拦截、JS 挑战）时先跑 waf_detect。
- 绕过思路（授权测试）：大小写/编码混淆、超长参数、分段请求、直接打源站 IP。
- 免费 WAF 和 CDN 常被误判，结果仅供参考。"""
    extra_schemas = SCHEMAS

    async def exec_waf_detect(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("wafw00f"):
            return "wafw00f 未安装（apt install wafw00f）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
