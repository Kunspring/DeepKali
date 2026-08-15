"""明文凭据传输检测：检查登录表单是否走 HTTP（无 TLS）传输密码。

白帽定位：SRC 常见低危项——登录页/表单 action 用 http:// 明文传输密码
（可被中间人抓包）；HTTPS 页面内嵌 http action 也属同类缺陷。
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_PWD_INPUT_RE = re.compile(
    r'<input\b[^>]*\btype\s*=\s*["\']?password["\']?', re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_ATTR_RE = re.compile(r'\baction\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "plain_login",
            "description": (
                "明文凭据传输检测：检查页面登录表单（type=password）与表单 action "
                "是否走 http 明文——中间人可抓包窃取密码。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标登录页 URL，如 http://t.com/login",
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str) -> str:
    return f"curl -s -m 15 '{url}'"


def _has_password_input(raw: str) -> bool:
    return bool(_PWD_INPUT_RE.search(raw))


def _form_actions(raw: str) -> list[str]:
    """所有表单 action 列表（相对路径原样返回）。"""
    out: list[str] = []
    for block in _FORM_RE.findall(raw):
        m = _ATTR_RE.search(block[: block.index(">") + 1])
        if m:
            out.append(m.group(1))
    return out


def _summarize(raw: str, url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    has_pwd = _has_password_input(raw)
    actions = _form_actions(raw)
    head: list[str] = [f"🔐 {url} 登录传输检查:"]
    if not has_pwd:
        head.append("  （页面无密码输入框——可能不是登录页或 SPA 渲染）")
        head.append("提示：找真实登录页（/login、/signin、/admin、api_enum 探 /api/login）；"
                    "SPA 抓渲染后 HTML。")
        return ToolProfile._summary(raw, head, tail=15)
    if scheme == "http":
        head.append("🚨 登录表单在 HTTP 明文页面上——密码明文传输，中间人可抓包窃取！")
        head.append("  下一步：确认是否强制跳转 HTTPS（Location 检查）、HSTS 是否存在"
                    "（header_check）；修复：全站 HTTPS + HSTS + 登录页 301 跳转。")
    else:
        head.append("✅ 登录页走 HTTPS（传输加密）。")
    bad_actions = [a for a in actions if a.startswith("http://")]
    if bad_actions:
        head.append(f"🚨 表单 action 指向 http 明文: {', '.join(bad_actions[:5])}")
        head.append("  修复：action 统一 https 或相对路径。")
    elif actions:
        head.append(f"ℹ️ 表单 action: {', '.join(actions[:5]) or '（同页提交）'}")
    head.append("下一步：配合 cookie_check 确认会话 Cookie Secure 属性；"
                "HSTS 缺失时即使跳转 HTTPS 也可被降级（sslstrip）。")
    return ToolProfile._summary(raw, head, tail=15)


class PlainLoginProfile(ToolProfile):
    name = "plain_login"
    aliases = ["明文登录", "明文传输", "http 登录", "密码明文", "降级检测", "登录传输"]
    summary = "明文凭据传输检测"
    lore = """### 明文凭据传输检测使用要点
- 定位：登录页或表单 action 用 http:// → 密码明文过网络（中间人抓包）。
- 检查：页面含 type=password 输入框 → 判定页面协议（http=🚨/https=✅）→
  再检查表单 action 是否指向 http://。
- 组合缺陷：HTTPS 页面 + http action（开发者漏改）；HSTS 缺失时 sslstrip
  可把 https 降级 http（配合 header_check 确认 HSTS）。
- 结合流程：plain_login 命中 → header_check 看 HSTS/跳转 → 报告中按
  "凭据明文传输" 低-中危提交；修复：全站 HTTPS + HSTS + 表单相对路径。
- 注意：只测 GET 页面；登录后流程（API 提交密码）需看 JS 里请求 URL
  （js_extract/secret_scan 辅助）；HTTP/2 明文 h2c 场景同样适用。"""
    extra_schemas = SCHEMAS

    async def exec_plain_login(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://t.com/login）: {url!r}"
        raw = await self._run(ex, _build_cmd(url), timeout=25)
        if len(raw) > 32768:
            raw = raw[:32768]
        return _summarize(raw, url)
