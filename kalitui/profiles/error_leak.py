"""错误页信息泄露检测：触发异常请求，检查响应泄露版本/堆栈/路径。

白帽定位：SRC 常见低危项——错误处理不当泄露 PHP/Java 版本、堆栈路径、
框架类型（辅助指纹与定向利用）；生产环境开 debug 模式属配置缺陷。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)

# 泄露特征：堆栈/异常/版本/绝对路径/框架提示
_LEAK_RE = re.compile(
    r"stack trace|traceback|exception in|at [\w.]+\.(java|php|py):\d+|"
    r"on line \d+|fatal error|warning:|notice:|deprecated:|"
    r"\bnginx/\d|apache/\d|iis/\d|php/\d|tomcat|spring|django|flask|"
    r"rails|laravel|thinkphp|struts|/var/www/|/usr/local/|C:\\|"
    r"com\.\w+\.\w+Exception|java\.lang\.",
    re.IGNORECASE,
)

# 触发变体（相对 url 的拼接）
_VARIANTS: list[tuple[str, str]] = [
    ("数组参数错误", "?x[]=1"),
    ("超长参数", "?x=" + "a" * 500),
    ("空字节", "/%00"),
    ("缺失参数", ""),
]
_MAX_VARIANTS = 10

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "error_leak",
            "description": (
                "错误页信息泄露检测：发送异常请求（数组参数/超长/空字节）触发错误，"
                "检查响应泄露版本号、堆栈路径、框架类型（debug 模式/错误处理缺陷）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://t.com/app.php",
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str, variant: str) -> str:
    return f"curl -s -m 15 '{url}{variant}'"


def _find_leak(raw: str) -> str | None:
    """返回首个泄露特征片段（≤80 字符）。"""
    m = _LEAK_RE.search(raw)
    if not m:
        return None
    start = max(0, m.start() - 25)
    return raw[start: m.start() + 55].replace("\n", " ")


def _summarize(baseline: str, results: list[tuple[str, str]]) -> str:
    head: list[str] = []
    leaks: list[tuple[str, str, str]] = []
    for name, raw in results:
        if raw == baseline or not raw.strip():
            continue
        frag = _find_leak(raw)
        if frag:
            leaks.append((name, frag, raw))
    if leaks:
        head.append(f"🚨 错误页泄露 ({len(leaks)}/{len(results)}):")
        for name, frag, raw in leaks:
            head.append(f"  [{name}] …{frag}…")
        head.append("下一步：版本/框架信息接 cve_lookup 查已知漏洞；堆栈路径辅助源码"
                    "定位（/var/www/... 接目录枚举）；修复：关闭 debug、自定义错误页、"
                    "日志不外泄。")
    else:
        head.append("✅ 未发现错误页泄露——异常请求返回统一错误页（处理较规范）。")
        head.append("提示：试 404 页/500 页差异、Accept 头变体、HTTP 方法错误"
                    "（TRACE/PUT 已有工具）；SPA 场景抓 API 层错误。")
    return ToolProfile._summary("", head, tail=25)


class ErrorLeakProfile(ToolProfile):
    name = "error_leak"
    aliases = ["错误页泄露", "信息泄露", "堆栈泄露", "debug 模式", "错误信息", "异常泄露", "版本泄露"]
    summary = "错误页信息泄露检测"
    lore = """### 错误页泄露检测使用要点
- 定位：生产环境开 debug/错误处理不当 → 版本号、堆栈、绝对路径、框架类型泄露。
- 4 种触发变体：数组参数（?x[]=1，PHP 经典 TypeError）、超长参数（500 字符触发
  长度校验错误）、空字节（/%00，老框架路径处理异常）、缺失参数。
- 判定：堆栈（Traceback/at xxx.java:12/on line N）、版本（nginx/1.18、PHP/8.1）、
  绝对路径（/var/www/、C:\\）、框架（Spring/Django/Laravel/ThinkPHP）。
- 结合流程：版本/框架 → cve_lookup 查已知漏洞（如 ThinkPHP RCE 系列）；
  路径泄露 → 目录枚举（gobuster）确认源码结构。
- 修复：关闭 debug 模式、自定义统一错误页、敏感异常记录日志不返前端。
- 注意：泄露是辅助信息而非直接漏洞——需结合其他面（版本漏洞利用/源码定位）
  才构成实际风险；基线对比排除 404 页固有内容。"""
    extra_schemas = SCHEMAS

    async def exec_error_leak(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://t.com/app.php）: {url!r}"
        baseline = await self._run(ex, _build_cmd(url, ""), timeout=20)
        results: list[tuple[str, str]] = []
        for name, variant in _VARIANTS:
            raw = await self._run(ex, _build_cmd(url, variant), timeout=20)
            results.append((name, raw))
        return _summarize(baseline, results)
