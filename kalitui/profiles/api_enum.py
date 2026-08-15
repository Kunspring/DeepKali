"""API 端点枚举：批量探测常见 API 路径，找未授权可访问的接口。

白帽定位：API 测试场景——/api/v1/users、/api/admin、/api/config 等未加
鉴权是高频真实漏洞（未授权访问数据/管理接口）；401/403 也算资产发现
（存在但需认证，后续可爆破/绕过）。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_PATH_RE = re.compile(r"^/[\w./\-]{1,150}$")

_DEFAULT_PATHS: list[str] = [
    "/api/v1/users",
    "/api/v1/admin",
    "/api/v1/me",
    "/api/v1/config",
    "/api/v1/export",
    "/api/v1/logs",
    "/api/users",
    "/api/admin",
    "/api/config",
    "/api/internal",
    "/api/debug",
    "/api/status",
    "/api/version",
    "/api/health",
    "/api/v2/users",
    "/graphql",
    "/api/graphql",
]
_MAX_PATHS = 40

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "api_enum",
            "description": (
                "API 端点枚举：批量探测 17 条常见 API 路径（/api/v1/users、/api/admin、"
                "/graphql 等），200=未授权可访问（高价值），401/403=存在但需认证。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标基础 URL，如 http://t.com（含域名即可）",
                    },
                    "paths": {
                        "type": "array",
                        "description": "自定义追加路径列表（可选）",
                        "items": {"type": "string"},
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str, path: str) -> str:
    return (
        f"curl -s -o /dev/null -m 10 -w '%{{http_code}} %{{size_download}}' "
        f"'{url}{path}'"
    )


def _parse_probe(raw: str) -> tuple[str, str]:
    parts = raw.split()
    code = parts[0] if parts else "000"
    size = parts[1] if len(parts) > 1 else "0"
    return code, size


def _summarize(results: dict[str, tuple[str, str]]) -> str:
    open_hits = {p: (c, s) for p, (c, s) in results.items() if c == "200" and s != "0"}
    auth_hits = {p: (c, s) for p, (c, s) in results.items() if c in ("401", "403")}
    head: list[str] = []
    if open_hits:
        head.append(f"🚨 未授权可访问 ({len(open_hits)}):")
        for p, (c, s) in open_hits.items():
            head.append(f"  [200] {p}（{s} 字节）")
        head.append("下一步：逐个请求确认返回内容（用户数据/配置/管理功能）；"
                    "修复：接口鉴权中间件统一覆盖。")
    else:
        head.append("✅ 未发现未授权 200 端点。")
    if auth_hits:
        head.append(f"🔒 存在但需认证 ({len(auth_hits)}):")
        head += [f"  [{c}] {p}" for p, (c, s) in auth_hits.items()][:12]
        head.append("下一步：这些端点可试弱口令/越权（IDOR）、认证绕过；"
                    "配合 jwt_check 分析 token 弱点。")
    if not open_hits and not auth_hits:
        head.append("ℹ️ 全部 404——该站可能无 /api 前缀接口（试 /rest/、/v1/、/services/）。")
    return ToolProfile._summary("", head, tail=25)


class ApiEnumProfile(ToolProfile):
    name = "api_enum"
    aliases = ["api 枚举", "接口枚举", "api 端点", "未授权接口", "api 探测", "接口发现", "graphql 探测"]
    summary = "API 端点枚举（未授权接口发现）"
    lore = """### API 端点枚举使用要点
- 定位：API 鉴权遗漏是高频漏洞——/api/v1/users、/api/admin 直接 200 返回数据。
- 17 条内置路径：/api/v1/*（users/admin/me/config/export/logs）、/api/*、
  /graphql、/api/graphql 等。
- 判定：200 且非空 = 未授权可访问（最高价值）；401/403 = 存在但需认证
  （资产发现，后续爆破/越权）；404 = 无。
- 结合流程：未授权端点 → 请求看数据（用户 PII/配置/内部信息）→ 若返回
  token/凭据接登录；401 端点 → jwt_check 分析 → 弱口令 hydra；
  graphql 端点 → introspection 查询（常见配置漏洞）。
- 修复：鉴权中间件统一覆盖所有 /api 前缀；graphql 关 introspection。
- 注意：只发 GET；POST-only 接口会 405（不算未授权）；响应 200 也可能是
  自定义 404 页（用 size>0 过滤 + 手工确认内容）。"""
    extra_schemas = SCHEMAS

    async def exec_api_enum(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://t.com）: {url!r}"
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
            raise ValueError(f"路径总数不能超过 {_MAX_PATHS}")
        results: dict[str, tuple[str, str]] = {}
        for p in paths:
            raw = await self._run(ex, _build_cmd(url, p), timeout=15)
            results[p] = _parse_probe(raw)
        return _summarize(results)
