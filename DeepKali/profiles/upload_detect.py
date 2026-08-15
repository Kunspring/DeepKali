"""文件上传点发现：提取页面上传表单 + 探测常见上传路径。

白帽定位：上传漏洞（任意文件上传→webshell）的前置发现——页面里
<input type=file> 表单、enctype=multipart 接口、常见上传路径
（/upload、/api/upload）都是攻击面入口。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_ATTR_RE = re.compile(r'\b(action|enctype)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_FILE_INPUT_RE = re.compile(r'<input\b[^>]*\btype\s*=\s*["\']file["\']', re.IGNORECASE)
_UPLOAD_PATHS: list[str] = [
    "/upload", "/upload/", "/uploads/", "/api/upload", "/file/upload",
    "/upload_file", "/upfile", "/upload.do", "/upload.action",
]
_MAX_PATHS = 20

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "upload_detect",
            "description": (
                "文件上传点发现：提取页面上传表单（file input/enctype=multipart）+"
                "探测 9 个常见上传路径——上传漏洞测试的入口清单。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://t.com/profile",
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


def _build_cmd(url: str) -> str:
    return f"curl -s -m 15 '{url}'"


def _probe_cmd(url: str, path: str) -> str:
    return (
        f"curl -s -o /dev/null -m 10 -w '%{{http_code}} %{{size_download}}' "
        f"'{url}{path}'"
    )


def _extract_forms(raw: str) -> list[dict[str, str]]:
    """提取含上传特征的表单：file input 或 multipart enctype。"""
    out: list[dict[str, str]] = []
    for block in _FORM_RE.findall(raw):
        sep = block.index(">")
        attrs = dict(_ATTR_RE.findall(block[: sep + 1]))
        body = block[sep + 1:]
        is_upload = bool(_FILE_INPUT_RE.search(body)) or \
            "multipart/form-data" in attrs.get("enctype", "").lower()
        if is_upload:
            out.append({
                "action": attrs.get("action", "（同页）"),
                "enctype": attrs.get("enctype", ""),
            })
    return out


def _summarize(raw: str, url: str, probe_results: dict[str, tuple[str, str]]) -> str:
    forms = _extract_forms(raw)
    open_paths = {p: c for p, (c, s) in probe_results.items() if c == "200" and s != "0"}
    head: list[str] = [f"📤 {url} 上传点发现:"]
    if forms:
        head.append(f"🚨 页面上传表单 ({len(forms)}):")
        for f in forms[:8]:
            head.append(f"  action={f['action']} enctype={f['enctype'] or '（缺省）'}")
    else:
        head.append("  （页面未发现上传表单）")
    if open_paths:
        head.append(f"🔎 上传路径可达 ({len(open_paths)}):")
        head += [f"  [200] {p}" for p in open_paths][:10]
    if not forms and not open_paths:
        head.append("ℹ️ 未发现上传入口——上传点可能在登录后/其他子域（api.）或走对象存储直传。")
    head.append("下一步：对上传点做文件类型绕过测试（扩展名/Content-Type/MIME 魔术头）、"
                "路径穿越上传（../）、大小限制探测——仅限授权；修复：白名单扩展名+内容校验+随机文件名。")
    return ToolProfile._summary("", head, tail=25)


class UploadDetectProfile(ToolProfile):
    name = "upload_detect"
    aliases = ["上传点发现", "上传检测", "文件上传", "upload 检测", "上传入口", "multipart"]
    summary = "文件上传点发现"
    lore = """### 上传点发现使用要点
- 定位：任意文件上传（→webshell/RCE）的前置发现——先找到所有上传入口。
- 检查：页面提取 <input type=file> 表单（含 action/enctype）+ 探测 9 个常见
  上传路径（/upload、/api/upload、/file/upload、/upload.do 等）。
- 判定：表单含 file input 或 enctype=multipart = 上传点；路径 200 且非空 = 可达。
- 结合流程：upload_detect 找到入口 → 上传测试：扩展名白名单绕过
  （.php5/.phtml/.jspx）、Content-Type 伪造、MIME 魔术头、二次渲染绕过、
  路径穿越（../shell.php）→ 若上传成功且可执行 = RCE。
- 修复：白名单扩展名 + 内容/MIME 双重校验 + 随机文件名 + 存储目录不可执行。
- 注意：只测 GET 页面；登录后上传入口（个人头像/附件）需带会话重测；
  对象存储直传（OSS/S3 签名 URL）是另一个面（web_leak 探 /api/oss 类路径）。"""
    extra_schemas = SCHEMAS

    async def exec_upload_detect(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://t.com/profile）: {url!r}"
        raw = await self._run(ex, _build_cmd(url), timeout=20)
        paths = list(_UPLOAD_PATHS)
        extra = args.get("paths") or []
        if not isinstance(extra, list):
            raise ValueError("paths 必须是列表")
        for p in extra:
            p = str(p).strip()
            if not re.fullmatch(r"/[\w./\-]{1,120}", p):
                raise ValueError(f"path 必须以 / 开头且仅含常规字符: {p!r}")
            if p not in paths:
                paths.append(p)
        if len(paths) > _MAX_PATHS:
            raise ValueError(f"路径总数不能超过 {_MAX_PATHS}")
        probe_results: dict[str, tuple[str, str]] = {}
        for p in paths:
            out = await self._run(ex, _probe_cmd(url, p), timeout=12)
            parts = out.split()
            probe_results[p] = (
                parts[0] if parts else "000",
                parts[1] if len(parts) > 1 else "0")
        return _summarize(raw, url, probe_results)
