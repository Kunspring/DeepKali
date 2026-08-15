""".git 源码泄露检测：Web 目标 .git 目录暴露 → 源码可恢复 → 密钥/后端逻辑泄露。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "git_leak",
            "description": (
                "检测 Web 目标是否泄露 .git 源码目录（高频真实漏洞）。"
                "原理：开发者把 .git 目录留在 Web 根目录时，攻击者可下载整个仓库"
                "（源码/配置/硬编码密钥/数据库凭据全部暴露）。检测 .git/config 与 "
                ".git/HEAD 是否可访问，命中后提示恢复工具链。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://target.com/ 或 http://target.com/app/",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)


def _build_cmd(url: str) -> str:
    base = url.rstrip("/")
    return (
        f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 15 '{base}/.git/config'; "
        f"echo; curl -s -o /dev/null -w '%{{http_code}}' --max-time 15 '{base}/.git/HEAD'"
    )


def _parse(raw: str) -> tuple[str, str]:
    """返回 (config 状态码, HEAD 状态码)。"""
    codes = re.findall(r"^\s*(\d{3})\s*$", raw, re.MULTILINE)
    codes = [c for c in codes if c != "000"]
    return (codes[0] if len(codes) > 0 else "000",
            codes[1] if len(codes) > 1 else "000")


class GitLeakProfile(ToolProfile):
    name = "git_leak"
    aliases = [".git 泄露", "git 泄露", "源码泄露", "git-dumper", ".git"]
    summary = ".git 源码泄露检测"
    lore = """### .git 泄露检测深度使用要点
- 原理：.git/config 与 .git/HEAD 可访问 = 整个仓库可被下载。真实项目里因此泄露
  （硬编码 API key、数据库密码、后端逻辑、内部地址）的案例非常多。
- 验证步骤：git_leak 命中后 → 下载 .git 恢复源码（git-dumper 或手工
  `wget --recursive http://target/.git/` + `git checkout .`）→ 全仓库搜密钥。
- 附加检查：/.gitignore、/.svn/entries（svn 泄露同族）、备份文件（.bak/.zip）。
- 报告价值：泄露源码中的凭据/逻辑 = 高影响发现，务必截图关键文件作为证据。
- 注意：恢复源码属读取公开可访问内容，但仍需在授权范围内进行。"""
    extra_schemas = SCHEMAS

    async def exec_git_leak(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://target.com/）: {url!r}"
        raw = await self._run(ex, _build_cmd(url), timeout=45)
        cfg_code, head_code = _parse(raw)
        leaked = cfg_code in ("200", "301", "302") or head_code in ("200", "301", "302")
        if leaked:
            head = [
                f"🎯 .git 目录泄露确认！（config={cfg_code}, HEAD={head_code}）",
                "源码仓库可被完整下载——高影响发现。",
                "下一步：git-dumper 恢复源码（或 wget --recursive 抓 .git + git checkout .），",
                "然后全仓库搜索硬编码密钥/数据库凭据/内部地址，截图取证。",
            ]
        else:
            head = [
                f"未发现 .git 泄露（config={cfg_code}, HEAD={head_code}）",
                "可顺带检查：/.gitignore、/.svn/entries、*.bak、*.zip 备份文件。",
            ]
        return self._summary(raw, head, tail=10)
