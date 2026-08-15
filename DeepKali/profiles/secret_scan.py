"""前端密钥扫描：从页面/JS 文件中识别硬编码的 API key / 令牌 / 私钥。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "secret_scan",
            "description": (
                "扫描页面/JS 文件中的硬编码密钥（API key、令牌、私钥、JWT 等）。"
                "Web 渗透高频发现：前端 JS 打包常残留真实密钥（AWS/GitHub/Firebase/"
                "自定义 API key），可导致未授权访问云资源或调用付费接口。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL（页面或 JS 文件），如 http://target.com/app.js",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)

# (类型名, 正则) —— 按信号强度排序
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}\b")),
    ("Firebase/Google Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("JWT Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic API Key", re.compile(
        r"""(?i)(?:api[_-]?key|apikey|secret[_ -]?key|client[_ -]?secret|access[_ -]?token|bearer)\s*[:=]\s*["']([A-Za-z0-9_\-.]{16,64})["']"""
    )),
]


def _build_cmd(url: str) -> str:
    return f"curl -s --max-time 30 '{url}'"


def _scan(raw: str) -> list[tuple[str, str]]:
    """扫描命中 → [(类型, 脱敏值)]。"""
    hits: list[tuple[str, str]] = []
    for name, pat in _PATTERNS:
        for m in pat.finditer(raw or ""):
            value = m.group(1) if m.lastindex else m.group(0)
            masked = value[:8] + "…" if len(value) > 8 else value
            hit = (name, masked)
            if hit not in hits:
                hits.append(hit)
            if len(hits) >= 20:
                return hits
    return hits


class SecretScanProfile(ToolProfile):
    name = "secret_scan"
    aliases = ["密钥扫描", "硬编码密钥", "api key 扫描", "js 密钥", "secret 扫描"]
    summary = "前端硬编码密钥扫描"
    lore = """### 密钥扫描深度使用要点
- 原理：前端 JS 打包（webpack 等）常把真实密钥留在产物里；也有开发者把
  API key 直接写页面里。命中后先验证有效性（调目标 API/云控制台），再找泄露源。
- 常见泄露：AWS AKIA（可盗用云资源）、Firebase AIza（数据库未授权）、
  GitHub token（私有仓库权限）、Stripe/支付密钥（直接盗刷）。
- 流程衔接：dir_brute/ffuf 发现 JS 文件 → secret_scan 逐个扫；
  或对页面主 JS（/static/js/*.js）批量扫。
- 报告价值：有效密钥 = 高影响发现；验证成功的密钥务必记录调用结果作证据，
  并在报告中注明修复建议（密钥轮换 + 移入后端环境变量）。"""
    extra_schemas = SCHEMAS

    async def exec_secret_scan(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://target.com/app.js）: {url!r}"
        raw = await self._run(ex, _build_cmd(url), timeout=45)
        hits = _scan(raw[:200_000])  # 大文件只扫前 200KB
        if not hits:
            head = [
                "未发现硬编码密钥（或密钥已被混淆/移入后端）",
                "建议：检查其他 JS 文件 / 源码泄露（git_leak）；注意 Stripe 等 pk_ 开头公钥是公开的，不算漏洞。",
            ]
            return self._summary(raw, head, tail=10)
        head = [f"🎯 发现硬编码密钥 ({len(hits)} 处):"]
        seen_types: set[str] = set()
        for name, masked in hits:
            if name not in seen_types:
                head.append(f"  [{name}] {masked}")
                seen_types.add(name)
        head.append("下一步：验证密钥有效性（调用对应 API/云控制台），成功即高影响发现，截图取证。")
        return self._summary(raw, head, tail=15)
