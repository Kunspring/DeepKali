"""JWT 本地分析：解析 token 并检查常见弱点（不接触目标、零网络依赖）。

白帽定位：拿到 JWT 后先本地分析——alg=none、算法混淆（RS256→HS256）、
exp 过期/永不过期、敏感 payload 字段（admin/role）——再决定是否值得
对目标做签名绕过尝试。
"""

from __future__ import annotations

import base64
import json
import re
import time
from typing import Any

from .base import ToolProfile

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "jwt_check",
            "description": (
                "JWT 本地分析：解析 token 的 header/payload，检查 alg=none、算法混淆、"
                "exp 过期/缺失、敏感权限字段等弱点（纯本地，不请求目标）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "JWT 字符串（header.payload.signature）",
                    },
                },
                "required": ["token"],
            },
        },
    },
]


def _b64u_decode(part: str) -> str:
    """base64url 解码（补 padding），失败抛 ValueError。"""
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad).decode("utf-8", "replace")


def _parse(token: str) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """解析 token → (header, payload, 是否有签名段)。"""
    header_s, payload_s, sig_s = token.split(".")
    header = json.loads(_b64u_decode(header_s))
    payload = json.loads(_b64u_decode(payload_s))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT 段不是 JSON 对象")
    return header, payload, bool(sig_s)


def _analyze(
    header: dict[str, Any], payload: dict[str, Any], sig: bool, now: float,
) -> list[str]:
    risks: list[str] = []
    alg = str(header.get("alg") or "").upper()
    if not alg:
        risks.append("缺少 alg 字段——部分实现按空 alg 处理（风险）")
    elif alg == "NONE":
        risks.append("alg=none——无签名校验，可伪造任意 token（若服务端未拒绝）")
    elif alg == "HS256":
        risks.append("算法混淆攻击面：若服务端原用 RS256 且接受 HS256，可用公钥当 HMAC 密钥伪造")
    if not sig:
        risks.append("无签名段——若服务端不校验签名可任意伪造")
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        if exp < now:
            risks.append("token 已过期（exp 早于当前时间）")
        else:
            left = int(exp - now)
            risks.append(f"token 有效（exp 剩余 {left} 秒）")
    else:
        risks.append("无 exp 字段——永不过期 token（若被泄露长期有效）")
    for k in ("admin", "role", "is_admin", "isadmin"):
        v = payload.get(k)
        if v is not None:
            risks.append(f"payload 含权限字段 {k}={v!r}——可尝试篡改后重签/无签名提交")
    return risks


def _summarize(token: str, now: float) -> str:
    try:
        header, payload, sig = _parse(token)
    except (ValueError, json.JSONDecodeError) as e:
        head = [f"❌ JWT 解析失败: {e}", "建议：确认 token 完整（header.payload.signature 三段 base64url）。"]
        return ToolProfile._summary(token, head, tail=20)
    head = ["🔐 JWT 分析:"]
    head.append(f"  alg: {header.get('alg', '（缺失）')} | typ: {header.get('typ', 'JWT')}")
    head.append(f"  签名: {'有' if sig else '无'}")
    risk = _analyze(header, payload, sig, now)
    head += [f"  {'🚨' if ('none' in r.lower() or '伪造' in r or '混淆' in r) else '⚠️'} {r}" for r in risk]
    head.append("下一步：alg=none/无签名 → 构造伪造 token 对目标提交验证（授权内）；")
    head.append("HS256 混淆 → 尝试用公钥当密钥签名后再验证。")
    return ToolProfile._summary(token, head, tail=30)


def _make_token(header: dict[str, Any], payload: dict[str, Any], sig: str = "c2ln") -> str:
    """测试辅助：构造 JWT（不导出）。"""
    def enc(d: dict[str, Any]) -> str:
        raw = json.dumps(d, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return f"{enc(header)}.{enc(payload)}.{sig}"


class JwtCheckProfile(ToolProfile):
    name = "jwt_check"
    aliases = ["jwt 分析", "jwt 检查", "token 分析", "jwt", "伪造 token", "jwt 弱点"]
    summary = "JWT 本地弱点分析"
    lore = """### JWT 分析使用要点
- 定位：拿到 JWT（如登录接口返回 / cookie）后本地分析弱点，纯本地零请求。
- 检查项：alg=none（无签名）、无签名段、算法混淆（RS256 公钥当 HS256 密钥）、
  exp 缺失（永不过期）、payload 权限字段（admin/role）可篡改面。
- 流程：jwt_check(token) 看风险 → 若有 alg=none/无签名，构造伪造 token
  （改 payload 为 admin）对目标提交验证——仅限授权测试。
- 算法混淆利用：服务端若接受 HS256 且你知道 RSA 公钥，把 alg 改为 HS256、
  用公钥内容当 HMAC 密钥签名，可能通过校验（经典 CVE-2016-5431 系）。
- 注意：JWT 的 base64 是 urlsafe 变体（- _ 替代 + /）；exp 是 Unix 时间戳秒。"""
    extra_schemas = SCHEMAS

    async def exec_jwt_check(self, ex: Any, args: dict[str, Any]) -> str:
        token = str(args.get("token") or "").strip()
        if not token:
            return "token 不能为空。"
        if len(token) > 4096 or not _TOKEN_RE.match(token):
            return "token 格式非法（应为 header.payload.signature 三段 base64url）。"
        return _summarize(token, time.time())
