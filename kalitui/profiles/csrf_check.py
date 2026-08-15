"""CSRF 检测：解析页面表单，检查有无 CSRF token 防护字段。

白帽定位：CSRF（跨站请求伪造）是 OWASP 常驻 Top 10——表单无 token
且用 Cookie 认证时，攻击者可诱导受害者提交敏感操作（改密/转账/删数据）。
本工具抓页面提取表单，检查 token 字段（csrf/token/authenticity/nonce）。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_ATTR_RE = re.compile(r'\b(action|method)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_NAME_RE = re.compile(r'\bname\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_TOKEN_HINT = ("csrf", "token", "authenticity", "nonce", "_token", "xsrf", "csrfmiddleware")

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "csrf_check",
            "description": (
                "CSRF 检测：抓取页面解析所有表单，检查 CSRF token 字段"
                "（csrf/token/authenticity/nonce）——无 token 表单为候选风险。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标页面 URL，如 http://t.com/settings",
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str) -> str:
    return f"curl -s -m 15 '{url}'"


def _extract_forms(raw: str) -> list[dict[str, Any]]:
    """提取表单：action/method（开标签）+ 所有 input name 列表（表单体）。"""
    forms: list[dict[str, Any]] = []
    for block in _FORM_RE.findall(raw):
        sep = block.index(">")
        attrs = dict(_ATTR_RE.findall(block[: sep + 1]))
        body = block[sep + 1:]
        inputs = [_NAME_RE.search(i).group(1) for i in _INPUT_RE.findall(body)
                  if _NAME_RE.search(i)]
        forms.append({
            "action": attrs.get("action", ""),
            "method": attrs.get("method", "get").lower(),
            "inputs": inputs,
        })
    return forms


def _has_token(inputs: list[str]) -> bool:
    low = " ".join(inputs).lower()
    return any(h in low for h in _TOKEN_HINT)


def _summarize(raw: str, url: str) -> str:
    forms = _extract_forms(raw)
    head: list[str] = [f"🛡️ {url} CSRF 表单检查（{len(forms)} 个表单）:"]
    no_token = [f for f in forms if not _has_token(f["inputs"])]
    if no_token:
        head.append(f"🚨 无 CSRF token 的表单 ({len(no_token)}):")
        for f in no_token[:10]:
            head.append(
                f"  [{f['method'].upper()}] action={f['action'] or '（同页）'} "
                f"字段={', '.join(f['inputs'][:5]) or '（无 input）'}")
        head.append("下一步：确认表单是否敏感操作 + 是否 Cookie 认证（是则 CSRF 可利用）→"
                    "构造跨站表单验证（仅限授权）；修复：加 token + SameSite Cookie。")
        if len(no_token) > 10:
            head.append(f"  … 共 {len(no_token)} 个无 token 表单")
    else:
        head.append("✅ 全部表单均含 CSRF token 字段——基础防护到位。")
        head.append("提示：仍需确认 token 是否绑定会话/是否可预测（重放测试）；"
                    "AJAX/JSON 接口的 CSRF 需单独检查（无表单场景）。")
    return ToolProfile._summary(raw, head, tail=20)


class CsrfCheckProfile(ToolProfile):
    name = "csrf_check"
    aliases = ["csrf 检测", "跨站请求伪造", "csrf", "表单检查", "token 检查", "csrf 验证"]
    summary = "CSRF 检测（表单 token 检查）"
    lore = """### CSRF 检测使用要点
- 定位：表单无 token + Cookie 认证 → 诱导受害者提交敏感操作（改密/转账）。
- 检查：抓页面 → 提取所有 <form>（action/method/input 字段）→ token 字段判定
  （csrf/token/authenticity/nonce/xsrf/csrfmiddleware）。
- 判定：无 token 表单 = 候选风险，需人工确认敏感性与认证方式；
  有 token 也需验证绑定（重放旧 token 是否有效、token 是否全局共用）。
- 结合流程：csrf_check 命中 → 构造跨站表单（自动提交 JS）验证 → 配合社工
  评估影响；修复：Anti-CSRF token + SameSite=Lax/Strict + 敏感操作二次验证。
- 注意：只覆盖 HTML 表单；AJAX/JSON API（Authorization 头认证）一般不受
  CSRF 影响但需单独确认；多步流程（先 token 再提交）也可能绕过。"""
    extra_schemas = SCHEMAS

    async def exec_csrf_check(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://t.com/settings）: {url!r}"
        raw = await self._run(ex, _build_cmd(url), timeout=30)
        if len(raw) > 16384:
            raw = raw[:16384]
        return _summarize(raw, url)
