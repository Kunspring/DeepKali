"""crt.sh 证书透明度子域枚举：从 CA 公开签发记录提取目标子域。"""

from __future__ import annotations

import json
import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "crt_sh",
            "description": (
                "查询 crt.sh 证书透明度日志，枚举目标的子域名（subdomain 枚举补充手段）。"
                "原理：CA 签发的每个证书都公开记录，证书里包含所有子域名。"
                "适合在拿到主域名后第一时间使用——往往能发现 dnsrecon 字典爆破不到的"
                "vpn/dev/staging/admin 等内部系统域名，是白帽子域枚举的标配来源。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "域名，如 example.com（不含协议和路径）",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "最多输出多少个子域（默认 60，防输出爆炸）",
                    },
                },
                "required": ["target"],
            },
        },
    },
]

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$")


def _build_cmd(target: str) -> str:
    # % 是 crt.sh 的任意前缀通配；单引号包裹防 shell 注入
    return f"curl -sS --max-time 60 'https://crt.sh/?q=%25{target}&output=json'"


def _parse(raw: str, limit: int) -> list[str]:
    """解析 crt.sh JSON：提取 name_value 里的所有域名，去重排序。"""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value") or ""
        for name in str(name_value).splitlines():
            name = name.strip().lower()
            if not name or name.startswith("*"):
                continue
            if name not in seen:
                seen.add(name)
                out.append(name)
    out.sort()
    return out[:limit]


class CrtshProfile(ToolProfile):
    name = "crt.sh"
    aliases = ["证书透明度", "子域枚举", "crt.sh", "证书日志", "subdomain 枚举"]
    summary = "证书透明度子域枚举"
    lore = """### crt.sh 证书透明度深度使用要点
- 定位：与 dnsrecon 互补的子域枚举来源——证书是 CA 强制公开的，无法被目标隐藏。
- 价值点：dnsrecon 字典爆破依赖字典质量，crt.sh 却能拿到"真实签发过证书"的
  子域（staging/vpn/mail/内部管理后台等），是白帽子域枚举的第一梯队来源。
- 拿到子域清单后：按域名存活探测（httpx/nmap）→ 挑高价值目标（后台/API/vpn）
  做服务识别与漏洞检测；注意排除通配符证书（*.example.com）噪音。
- 多个子域集中在同一证书上是常见现象（SAN 多域名证书），去重后逐个跟进。
- 与 crt.sh 联动：如果 crt.sh 被限流或超时，改用 dnsrecon brt 模式兜底。"""
    extra_schemas = SCHEMAS

    async def exec_crt_sh(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        target = sanitize_target(str(args.get("target") or ""), label="域名")
        if not _DOMAIN_RE.match(target):
            return f"域名格式非法: {target!r}（应如 example.com）"
        limit = max(1, min(int(args.get("limit") or 60), 200))
        cmd = _build_cmd(target)
        raw = await self._run(ex, cmd, timeout=90)
        domains = _parse(raw, limit)
        if not domains:
            head = ["未从证书日志解析到子域（网络不可达 / 被限流 / 该域名无公开证书）"]
            head.append("建议：改用 dnsrecon（mode=brt）字典爆破兜底。")
            return self._summary(raw, head, tail=20)
        head = [f"📜 证书日志子域 ({len(domains)} 个，来自 crt.sh):"]
        head += [f"  {d}" for d in domains]
        if len(domains) >= limit:
            head.append(f"… 超出显示上限，共 {len(domains)} 个（可提高 limit）")
        head.append("下一步：对高价值子域（staging/vpn/admin/api）做存活探测与服务识别。")
        return self._summary(raw, head, tail=0)
