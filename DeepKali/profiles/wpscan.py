"""wpscan 深度定制：WordPress 漏洞扫描。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_url

ENUM_OPTS = {
    "vuln": "已知漏洞（推荐）",
    "all": "全部（插件/主题/用户/备份）",
    "plugins": "插件",
    "themes": "主题",
    "users": "用户",
    "backups": "备份文件",
}

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "wpscan_scan",
            "description": (
                "对 WordPress 站点执行漏洞扫描（wpscan）。"
                "检测 WP 版本、插件/主题及其已知漏洞、用户枚举、备份文件。"
                "外部目标需授权；扫描过程会发送较多请求。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "WordPress 站点 URL，如 http://target/wp"},
                    "enumerate": {
                        "type": "string",
                        "enum": list(ENUM_OPTS),
                        "description": "枚举范围（默认 vuln：只查已知漏洞，最快）",
                    },
                    "api_token": {
                        "type": "string",
                        "description": "WPScan API Token（可选，漏洞库更全）",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_TOKEN_RE = re.compile(r"^[A-Za-z0-9]{10,64}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    url = sanitize_url(str(args["url"]))
    enum = str(args.get("enumerate") or "vuln").strip()
    if enum not in ENUM_OPTS:
        raise ValueError(f"enumerate 仅支持: {', '.join(ENUM_OPTS)}")
    token = str(args.get("api_token") or "").strip()
    if token and not _TOKEN_RE.match(token):
        raise ValueError("api_token 格式非法")
    parts = ["wpscan", "--url", url, "--no-banner", "--random-user-agent"]
    if enum == "vuln":
        parts.append("--enumerate")
        parts.append("v")
    elif enum == "all":
        parts.append("--enumerate")
        parts.append("vtub")
    else:
        parts.append("--enumerate")
        parts.append({"plugins": "p", "themes": "t", "users": "u", "backups": "b"}[enum])
    if token:
        parts += ["--api-token", token]
    return " ".join(parts), 600


def _summarize(raw: str) -> str:
    finds = [l.strip() for l in raw.splitlines() if l.startswith("[+]")]
    vulns = [
        l.strip()
        for l in raw.splitlines()
        if re.search(r"\[!\]|Critical|High severity|vulnerab", l, re.IGNORECASE)
    ]
    head: list[str] = []
    if finds:
        head.append("主要发现:")
        head += finds[:25]
    if vulns:
        head.append("⚠ 漏洞/高风险项:")
        head += vulns[:15]
    if not head:
        head = ["未发现明显问题（版本/插件较新）。可尝试 users 枚举找用户名后做口令测试。"]
    return ToolProfile._summary(raw, head, tail=45)


class WpscanProfile(ToolProfile):
    name = "wpscan"
    aliases = ["wordpress", "wp 扫描", "wp 漏洞"]
    summary = "WordPress 漏洞扫描"
    lore = """### wpscan 深度使用要点
- 定位：gobuster/nikto 发现 WordPress（/wp-login.php、/wp-content）后使用。
- 默认 enumerate=vuln 只查已知漏洞（快）；需要用户名做口令测试时再 users 枚举。
- 关注 [!] 高风险项：插件漏洞往往可直接 RCE；版本过旧提示升级。
- 发现用户名后，下一步可 hydra 弱口令测试（wp-login），但先向用户确认。
- api_token 可免费注册 WPScan API 获取更全漏洞数据。"""
    extra_schemas = SCHEMAS

    async def exec_wpscan_scan(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("wpscan"):
            return "wpscan 未安装（apt install wpscan）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
