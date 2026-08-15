"""邮件安全记录检查：查询域名的 SPF / DKIM / DMARC 配置，评估邮件伪造面。

白帽定位：钓鱼/邮件伪造风险评估——SPF 缺失或 +all 宽松、DMARC 缺失或 none
都意味着攻击者可伪造该域名发信（仿冒官方邮件钓鱼）。dig 查询 TXT 记录，
零外部依赖。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", re.IGNORECASE)

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "email_auth",
            "description": (
                "邮件安全记录检查：查询域名 SPF/DKIM/DMARC 记录，评估邮件伪造面"
                "（SPF 缺失或 +all、DMARC 缺失或 none = 可被仿冒钓鱼）。"
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


def _build_cmd(domain: str, record: str) -> str:
    prefix = f"{record}." if record else ""
    return f"dig +short TXT {prefix}{domain}"


def _parse_txt(raw: str) -> str:
    """合并 dig 的 TXT 输出（多段引号拼接）→ 单字符串（压缩多余空格）。"""
    parts: list[str] = []
    for line in raw.splitlines():
        line = line.replace('"', "").strip()
        if line:
            parts.append(line)
    return re.sub(r"\s+", " ", "".join(parts)).strip()


def _analyze(domain: str, spf_raw: str, dmarc_raw: str) -> str:
    spf = _parse_txt(spf_raw)
    dmarc = _parse_txt(dmarc_raw)
    head: list[str] = [f"📧 {domain} 邮件伪造面评估:"]
    # SPF
    if not spf:
        head.append("  🚨 SPF: 缺失——发件人可被任意伪造（无发信方校验）")
    elif "v=spf1" in spf.lower():
        if "+all" in spf.lower():
            head.append(f"  🚨 SPF: 存在但 +all 宽松（{spf[:80]}）——等于没限制")
        else:
            head.append(f"  ✅ SPF: 存在（{spf[:80]}）")
    else:
        head.append(f"  ⚠️ 无 v=spf1 的 TXT 记录（{spf[:60]}）——可能只有验证类记录")
    # DMARC
    if not dmarc:
        head.append("  🚨 DMARC: 缺失——SPF 失败邮件无处置策略，伪造面大")
    else:
        low = dmarc.lower()
        if "p=none" in low:
            head.append(f"  ⚠️ DMARC: 策略 p=none（仅监控，{dmarc[:80]}）——仍可被伪造")
        elif "p=reject" in low or "p=quarantine" in low:
            head.append(f"  ✅ DMARC: 策略 {low.split('p=')[1].split(';')[0].strip()}（{dmarc[:80]}）")
        else:
            head.append(f"  ⚠️ DMARC: 格式异常（{dmarc[:80]}）")
    # DKIM 提示（无 selector 无法直接查，提示用常见 selector 验证）
    head.append("  ℹ️ DKIM: 需具体 selector 验证（常见：default/google/s1；dig TXT <selector>._domainkey.<域名>）")
    head.append("下一步：SPF/DMARC 缺失或宽松 → 该域可被伪造发信（钓鱼场景）；修复见各服务商 SPF/DMARC 配置指南。")
    return ToolProfile._summary(spf_raw + "\n" + dmarc_raw, head, tail=20)


class EmailAuthProfile(ToolProfile):
    name = "email_auth"
    aliases = ["邮件安全", "spf 检查", "dmarc 检查", "dkim", "邮件伪造", "spf", "dmarc", "邮件头安全"]
    summary = "邮件安全记录检查（SPF/DKIM/DMARC）"
    lore = """### 邮件安全记录检查使用要点
- 定位：钓鱼风险评估——SPF/DMARC 缺失或宽松 = 攻击者可伪造该域名发信（仿冒官方钓鱼）。
- SPF：v=spf1 存在且 -all/~all = 严格；+all = 形同虚设；缺失 = 可伪造。
- DMARC：p=reject/quarantine = 处置严格；p=none = 仅监控；缺失 = 无兜底。
- DKIM：需要具体 selector（如 google._domainkey），先发信再 dig TXT 验证签名域名。
- 结合流程：email_auth 发现伪造面 → 目标若在钓鱼/社工场景，说明仿冒官方邮件可行；
  防御建议：SPF 收紧 + DMARC reject + DKIM 签名，三者齐备才防伪造。
- 注意：查询的是公共 DNS 记录，属被动侦察（无流量接触目标服务器）。"""
    extra_schemas = SCHEMAS

    async def exec_email_auth(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("dig"):
            return "dig 未安装（apt install dnsutils）。"
        domain = str(args.get("domain") or "").strip().lower()
        if not _DOMAIN_RE.match(domain):
            return f"domain 格式非法: {domain!r}"
        spf_raw = await self._run(ex, _build_cmd(domain, ""), timeout=15)
        dmarc_raw = await self._run(ex, _build_cmd(domain, "_dmarc"), timeout=15)
        return _analyze(domain, spf_raw, dmarc_raw)
