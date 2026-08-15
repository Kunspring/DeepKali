"""子域名接管检测：crt.sh 枚举子域 → 逐个查 CNAME → 匹配已知接管指纹。

白帽定位：经典高价值漏洞——子域 CNAME 指向已注销的第三方服务
（GitHub Pages/Heroku/S3/Netlify 等）即可被注册接管，用来挂钓鱼页/
恶意代码（父域 Cookie 作用域内）。被动侦察 + DNS 查询，零主动扫描。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", re.IGNORECASE)
_CNAME_RE = re.compile(r"^\S+\s+\d+\s+IN\s+CNAME\s+(\S+\.)\.?$", re.IGNORECASE)
_MAX_SUBS = 40

# (CNAME 指纹子串, 服务商名)
_FINGERPRINTS: list[tuple[str, str]] = [
    ("github.io", "GitHub Pages"),
    ("herokuapp.com", "Heroku"),
    ("herokudns.com", "Heroku"),
    ("s3.amazonaws.com", "AWS S3"),
    ("s3-website", "AWS S3"),
    ("cloudfront.net", "CloudFront"),
    ("azurewebsites.net", "Azure Web Apps"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("readthedocs.io", "ReadTheDocs"),
    ("surge.sh", "Surge"),
    ("netlify.app", "Netlify"),
    ("vercel.app", "Vercel"),
    ("ghost.io", "Ghost"),
    ("pantheon.io", "Pantheon"),
    ("fastly.net", "Fastly"),
    ("cargocollective.com", "Cargo"),
    ("zendesk.com", "Zendesk"),
    ("shopify.com", "Shopify"),
    ("bitbucket.io", "Bitbucket Pages"),
    ("pages.dev", "Cloudflare Pages"),
]

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "sub_takeover",
            "description": (
                "子域名接管检测：crt.sh 枚举子域后逐个查 CNAME，匹配 GitHub Pages/"
                "Heroku/S3/Netlify 等 20 个已知接管指纹——发现可注册接管的高价值风险。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "目标域名，如 example.com",
                    },
                },
                "required": ["domain"],
            },
        },
    },
]


def _build_cmd(sub: str) -> str:
    return f"dig +short CNAME {sub}"


def _parse_cname(raw: str) -> str:
    """解析 dig CNAME 输出（可能多行/多段）→ 首个 CNAME 目标。"""
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("cname"):
            continue
        m = _CNAME_RE.match(line)
        if m:
            return m.group(1).rstrip(".")
        if "." in line and not line.startswith((";", "dig ", ";;")):
            return line.split()[-1].rstrip(".")
    return ""


def _fingerprint(cname: str) -> str | None:
    """CNAME 目标匹配接管指纹 → 服务商名；否则 None。"""
    low = cname.lower()
    for frag, provider in _FINGERPRINTS:
        if frag in low:
            return provider
    return None


def _summarize(results: dict[str, tuple[str, str]]) -> str:
    hits = {sub: (cname, p) for sub, (cname, p) in results.items() if p}
    head: list[str] = []
    if hits:
        head.append(f"🚨 疑似子域名接管 ({len(hits)} 个):")
        for sub, (cname, provider) in hits.items():
            head.append(f"  {sub} → CNAME {cname}（{provider}）")
        head.append("下一步：访问该子域确认返回 404/未托管（接管条件：CNAME 目标无人注册），"
                    "在授权范围内注册验证；修复：删除失效 CNAME 或绑定同源服务。")
    else:
        head.append("✅ 未发现接管指纹（子域 CNAME 均指向有效托管或本域）——"
                    "注意仅覆盖 20 个常见服务商，小众服务需手工核对。")
    return ToolProfile._summary("", head, tail=25)


class SubTakeoverProfile(ToolProfile):
    name = "sub_takeover"
    aliases = ["子域接管", "接管检测", "cname 检查", "dangling dns", "子域名接管", "subdomain takeover"]
    summary = "子域名接管检测"
    lore = """### 子域名接管检测使用要点
- 定位：经典高价值漏洞——子域 CNAME 指向已注销/未注册的第三方服务即可被接管，
  用于挂钓鱼页、恶意 JS（父域 Cookie 作用域内读取）。
- 流程：crt.sh 证书日志枚举子域（前 40 个）→ 逐个 dig CNAME → 匹配 20 个已知
  接管指纹（GitHub Pages/Heroku/S3/CloudFront/Azure/Netlify/Vercel 等）。
- 验证三条件：1) CNAME 指向未托管服务 2) 访问子域返回 404/错误页（NXDOMAIN 样式）
  3) 该服务商允许注册该名字——三条齐备才可接管。
- 修复：删除失效 CNAME 记录，或重新绑定同源服务；定期审计 DNS 记录。
- 注意：CNAME 指向第三方 ≠ 漏洞；只有"未托管可注册"才是。指纹匹配是初筛，需人工确认。"""
    extra_schemas = SCHEMAS

    async def exec_sub_takeover(self, ex: Any, args: dict[str, Any]) -> str:
        from .crtsh import _build_cmd as crtsh_build_cmd
        from .crtsh import _parse as crtsh_parse

        if not check_installed("dig") or not check_installed("curl"):
            return "dig/curl 未安装（apt install dnsutils curl）。"
        domain = str(args.get("domain") or "").strip().lower()
        if not _DOMAIN_RE.match(domain) or "." not in domain:
            return f"domain 格式非法: {domain!r}"
        raw = await self._run(ex, crtsh_build_cmd(domain), timeout=90)
        subs = crtsh_parse(raw, _MAX_SUBS)
        results: dict[str, tuple[str, str]] = {}
        for sub in subs[: _MAX_SUBS]:
            cname = _parse_cname(
                await self._run(ex, _build_cmd(sub), timeout=15))
            results[sub] = (cname, _fingerprint(cname))
        if not subs:
            return self._summary(
                "", {"": ("", "")}) + "\nℹ️ crt.sh 未发现子域记录（域名可能无证书日志）。"
        return _summarize(results)
