"""joomscan 扫描：Joomla CMS 版本指纹 + 已知漏洞检测（wpscan 的 Joomla 姊妹）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "joomla_scan",
            "description": (
                "对 Joomla 站点做专项漏洞扫描（joomscan）：识别版本（1.x/2.x/3.x/4.x）、"
                "组件指纹、已知漏洞列表。识别出 CMS 是 Joomla 时的标准下一步，"
                "输出版本与命中漏洞，便于核对 exploit 与报告。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://target.com/",
                    },
                    "enumerate": {
                        "type": "boolean",
                        "description": "是否枚举组件/模块（较慢，默认 true）",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)


def _build_cmd(url: str, enumerate_: bool) -> str:
    base = url.rstrip("/")
    if enumerate_:
        return f"joomscan -u '{base}' --enumerate-components 2>&1 | head -80"
    return f"joomscan -u '{base}' 2>&1 | head -60"


def _parse(raw: str) -> tuple[str, list[str]]:
    """返回 (版本, 漏洞列表)。"""
    version = ""
    vulns: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        m = re.search(r"Joomla!?\s+(?:version\s+)?v?(\d+(?:\.\d+){1,3})", stripped, re.IGNORECASE)
        if m:
            version = m.group(1)
        low = stripped.lower()
        if any(k in low for k in ("vulnerable", "exploit", "cve-", "sql injection", "sqli", "xss")) and "not vulnerable" not in low:
            text = re.sub(r"\x1b\[[0-9;]*m", "", stripped)
            text = re.sub(r"^\[\+\]|^\+\s*", "", text).strip()
            if text:
                vulns.append(text[:130])
    return version, vulns[:15]


class JoomlaScanProfile(ToolProfile):
    name = "joomla_scan"
    aliases = ["joomscan", "joomla", "joomla 扫描", "cms 扫描", "joomla 漏洞"]
    summary = "Joomla CMS 专项扫描"
    lore = """### joomscan 深度使用要点
- 定位：识别到 Joomla（http_req 指纹 / wappalyzer / 页面特征）后的专项扫描。
  输出版本号 + 已知漏洞，比通用扫描更有针对性。
- 版本与漏洞对应：Joomla 3.x 常见 CVE（SQLi/文件上传/核心 RCE），
  1.5/2.5 老版本基本等于默认有洞；4.x 关注核心与组件。
- 组件枚举（--enumerate-components）发现第三方组件 → 组件版本漏洞是
  真实项目大头（组件漏洞库公开）。
- 流程衔接：joomla_scan 命中漏洞 → sploit_search 查 exploit → 授权验证。
- 报告价值：版本 + CVE 命中列表直接进报告（影响等级中-高）。"""
    extra_schemas = SCHEMAS

    async def exec_joomla_scan(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("joomscan"):
            return "joomscan 未安装（apt install joomscan）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://target.com/）: {url!r}"
        enumerate_ = bool(args.get("enumerate", True))
        raw = await self._run(ex, _build_cmd(url, enumerate_), timeout=180)
        version, vulns = _parse(raw)
        head: list[str] = []
        if version:
            head.append(f"🎯 Joomla 版本: {version}")
        if vulns:
            head.append(f"⚠ 漏洞信号 ({len(vulns)}):")
            head += [f"  · {v}" for v in vulns[:10]]
            head.append("下一步：sploit_search 查对应 exploit，授权范围内验证（vuln_proof）。")
        if not version and not vulns:
            head = ["未识别到 Joomla（站点不是 Joomla / 不可达 / 被防护拦截）"]
            return self._summary(raw, head, tail=15)
        head.append("组件枚举建议：--enumerate-components 找第三方组件版本漏洞（真实项目大头）。")
        return self._summary(raw, head, tail=20)
