"""目录列表检测：探测常见目录是否开启 autoindex（Index of / 列目录）。

白帽定位：目录无 index 文件且服务器开 autoindex → 直接列出源码/备份/
上传文件，是真实信息泄露（可下载源码审计、找备份库）。检测特征：
'Index of /'、'Parent Directory'、'[To Parent Directory]'。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_PATH_RE = re.compile(r"^/[\w./\-]{0,150}$")

_DEFAULT_PATHS: list[str] = [
    "/", "/images/", "/uploads/", "/upload/", "/files/", "/static/",
    "/assets/", "/download/", "/data/", "/backup/", "/logs/", "/tmp/",
    "/admin/", "/test/", "/docs/", "/media/",
]
_AUTOINDEX_RE = re.compile(
    r"index of /|parent directory|\[to parent directory\]|"
    r"directory listing for", re.IGNORECASE)
_MAX_PATHS = 30

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "directory_list",
            "description": (
                "目录列表检测：探测 16 个常见目录是否开启 autoindex（Index of / 特征）"
                "——开启则源码/备份/上传文件可直接列出下载。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://t.com",
                    },
                    "paths": {
                        "type": "array",
                        "description": "自定义追加目录路径（可选）",
                        "items": {"type": "string"},
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str, path: str) -> str:
    return f"curl -s -m 10 '{url}{path}'"


def _is_listing(raw: str) -> bool:
    return bool(_AUTOINDEX_RE.search(raw))


def _summarize(results: dict[str, str]) -> str:
    hits = {p: raw for p, raw in results.items() if _is_listing(raw)}
    head: list[str] = []
    if hits:
        head.append(f"🚨 目录列表开启 ({len(hits)}):")
        for p, raw in hits.items():
            title = next(
                (l.strip()[:60] for l in raw.splitlines()
                 if "index of" in l.lower()), "")
            head.append(f"  {p}" + (f"（{title}）" if title else ""))
        head.append("下一步：逐个目录列出文件 → 源码/备份/配置文件直接下载分析"
                    "（找凭据/未发布功能）；修复：关闭 autoindex（Options -Indexes）。")
    else:
        head.append("✅ 未发现目录列表——常见目录均返回 404/自定义页。")
        head.append("提示：试更多业务目录（/api/docs/、/storage/、/private/）；"
                    "目录存在但无列表时用 gobuster 爆破文件名。")
    return ToolProfile._summary("", head, tail=25)


class DirectoryListProfile(ToolProfile):
    name = "directory_list"
    aliases = ["目录列表", "autoindex", "列目录", "目录浏览", "index of", "目录遍历"]
    summary = "目录列表（autoindex）检测"
    lore = """### 目录列表检测使用要点
- 定位：目录无 index 文件 + 服务器开 autoindex → 整个目录文件列表暴露
  （源码/备份/上传文件直接可下载），真实信息泄露。
- 16 个常见目录：/、/images/、/uploads/、/files/、/static/、/backup/、
  /logs/、/admin/、/docs/、/media/ 等。
- 判定：'Index of /'、'Parent Directory'、'[To Parent Directory]' 特征。
- 结合流程：列表命中 → 下载源码审计（硬编码凭据/未发布接口）→ 备份文件
  （.sql/.zip）→ 数据库凭据；修复：Options -Indexes / autoindex off。
- 注意：与 path_traversal 不同——这是配置缺陷（列表开启）而非注入；
  有些站点目录存在但列表关闭（403），此时用 gobuster 爆破文件名。"""
    extra_schemas = SCHEMAS

    async def exec_directory_list(self, ex: Any, args: dict[str, Any]) -> str:
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
        results: dict[str, str] = {}
        for p in paths:
            results[p] = await self._run(ex, _build_cmd(url, p), timeout=15)
        return _summarize(results)
