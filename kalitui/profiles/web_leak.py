"""Web 敏感文件泄露探测：批量探测常见敏感路径（备份/配置/源码/管理入口）。

白帽定位：Web 渗透的经典检查项——/backup.zip、/.env、/.svn、/actuator 等
误发布文件是高频真实漏洞；robots.txt 的 Disallow 也常泄露隐藏路径。
纯 curl 实现（Kali 自带），逐路径探测状态码+响应大小。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_PATH_RE = re.compile(r"^/[\w.\-/]{1,200}$")  # 路径必须以 / 开头，仅常规字符
_MAX_PATHS = 60

# 白帽常见敏感路径字典（按价值排序）
_DEFAULT_PATHS: list[str] = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.hg/hgrc",
    "/.DS_Store",
    "/.htaccess",
    "/.htpasswd",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/data.sql",
    "/config.php.bak",
    "/config.inc.php.bak",
    "/wp-config.php.bak",
    "/config.bak",
    "/config.js",
    "/config.json",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/adminer.php",
    "/phpmyadmin/",
    "/server-status",
    "/server-info",
    "/web.config",
    "/crossdomain.xml",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/v2/api-docs",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/console",
    "/robots.txt",
    "/sitemap.xml",
]

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "web_leak",
            "description": (
                "Web 敏感文件泄露探测：批量探测常见敏感路径（备份/配置/源码/管理入口/"
                "actuator 等 38 条内置字典），并解析 robots.txt 的 Disallow 隐藏路径。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://target.com",
                    },
                    "paths": {
                        "type": "array",
                        "description": "自定义追加路径列表（可选，如 ['/api/swagger.json']）",
                        "items": {"type": "string"},
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_LEAK_CODES = ("200", "301", "302", "401", "403")


def _build_cmd(url: str, paths: list[str]) -> str:
    checks = " ".join(f"'{p}'" for p in paths)
    return (
        f"for p in {checks}; do "
        f"curl -s -o /dev/null -m 8 -w \"%{{http_code}} %{{size_download}} $p\\n\" "
        f"'{url}$p'; done"
    )


def _parse_probe(raw: str) -> list[tuple[str, str, str]]:
    """解析探测输出 'code size path' → 命中列表（排除 404/000/空响应）。"""
    hits: list[tuple[str, str, str]] = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        code, size, path = parts[0], parts[1], " ".join(parts[2:])
        if code in _LEAK_CODES and size != "0":
            hits.append((code, size, path))
    return hits


def _parse_robots(raw: str) -> list[str]:
    """解析 robots.txt → Disallow 路径列表（非空、非 *）。"""
    out: list[str] = []
    for line in raw.splitlines():
        low = line.strip().lower()
        if low.startswith("disallow:") or low.startswith("disallow "):
            val = line.split(":", 1)[-1].strip() if ":" in line else line.split(None, 1)[-1].strip()
            if val and val != "*":
                out.append(val[:150])
    return out


def _summarize(raw: str, robots_raw: str) -> str:
    hits = _parse_probe(raw)
    disallow = _parse_robots(robots_raw)
    head: list[str] = []
    if hits:
        head.append(f"🚨 敏感文件命中 ({len(hits)} 条):")
        for code, size, path in hits:
            tag = "存在" if code == "200" else ("跳转" if code in ("301", "302") else "受保护")
            head.append(f"  [{tag} {code}] {path} ({size} 字节)")
        head.append("下一步：逐个下载分析（备份/配置常含凭据）；受保护的试弱口令或路径穿越。")
    else:
        head.append("未发现敏感文件命中（全部 404/空响应）。")
    if disallow:
        head.append(f"🤖 robots.txt Disallow ({len(disallow)}):")
        head += [f"  {d}" for d in disallow[:15]]
        if len(disallow) > 15:
            head.append(f"  … 共 {len(disallow)} 条")
        head.append("下一步：对 Disallow 路径做目录枚举/直接访问。")
    return ToolProfile._summary(raw, head, tail=30)


class WebLeakProfile(ToolProfile):
    name = "web_leak"
    aliases = ["敏感文件", "备份文件", "泄露探测", "web 泄露", "路径探测", "敏感路径", "泄露扫描", "robots"]
    summary = "Web 敏感文件泄露探测"
    lore = """### Web 敏感文件探测使用要点
- 定位：Web 渗透经典检查项——备份/配置文件误发布是高频真实漏洞，robots.txt 也会泄露隐藏路径。
- 内置 38 条字典：/.env、/.git/config、/.svn/entries、/backup.zip、/db.sql、/phpinfo.php、
  /phpmyadmin/、/actuator/env、/swagger-ui.html、/web.config 等。
- 判定：200=直接存在（最高价值）；301/302=跳转（可能重定向到登录或真实路径）；
  401/403=存在但受保护（可尝试弱口令/绕过）。
- robots.txt Disallow 单独解析：隐藏路径常在这里泄露（如 /admin/、/internal/）。
- 结合流程：web_leak 命中备份 → 下载找凭据 → cve_lookup/sploit_search 找利用；
  命中 actuator → 直接访问 /actuator/env 看配置泄露。
- 注意：404 页可能返回 200（自定义错误页），用 size=0 过滤纯 404；大站慎用（38 请求/目标）。"""
    extra_schemas = SCHEMAS

    async def exec_web_leak(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://target.com）: {url!r}"
        paths = list(_DEFAULT_PATHS)
        extra = args.get("paths") or []
        if not isinstance(extra, list):
            raise ValueError("paths 必须是列表")
        for p in extra:
            p = str(p).strip()
            if not _PATH_RE.match(p):
                raise ValueError(f"path 必须以 / 开头且仅含常规字符: {p!r}")
            if p not in paths:
                paths.append(p)
        if len(paths) > _MAX_PATHS:
            raise ValueError(f"路径总数不能超过 {_MAX_PATHS} 条")
        raw = await self._run(ex, _build_cmd(url, paths), timeout=300)
        robots_raw = await self._run(
            ex, f"curl -s -m 8 '{url}/robots.txt'", timeout=15)
        return _summarize(raw, robots_raw)
