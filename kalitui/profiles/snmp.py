"""SNMP 枚举：public 团体串探测 + 系统信息提取（内网高频配置缺陷）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "snmp_enum",
            "description": (
                "SNMP 枚举：用常见团体串（默认 public）探测目标 SNMP 服务。"
                "内网高频配置缺陷：设备/服务器开了 SNMP 且团体串是默认值，"
                "可读取系统信息（主机名/系统描述/接口/运行时间），进一步可枚举"
                "用户、进程、路由表，甚至拿到含密码的配置字符串。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "目标 IP 或域名，如 10.0.0.5",
                    },
                    "community": {
                        "type": "string",
                        "description": "团体串（默认 public，可试 public/private 等）",
                    },
                },
                "required": ["target"],
            },
        },
    },
]

_COMMUNITY_RE = re.compile(r"^[\w@.-]{1,64}$")
# 数字 OID 关键行：sysDescr(.1.0)/sysObjectID(.2.0)/sysUpTime(.3.0)/sysContact(.4.0)/sysName(.5.0)
_KEY_OIDS = (
    ".1.3.6.1.2.1.1.1.0",   # sysDescr
    ".1.3.6.1.2.1.1.5.0",   # sysName
    ".1.3.6.1.2.1.1.4.0",   # sysContact
    ".1.3.6.1.2.1.1.6.0",   # sysLocation
    ".1.3.6.1.2.1.2.2.1.2", # 接口名
)


def _build_cmd(target: str, community: str) -> str:
    return (
        f"snmpwalk -v2c -c {community} -t 5 {target} 1.3.6.1.2.1.1 2>&1 | head -40"
    )


def _parse(raw: str) -> list[str]:
    """提取关键 OID 行的值。"""
    out: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or "No Response" in stripped or "Timeout" in stripped:
            continue
        if any(oid in stripped for oid in _KEY_OIDS):
            # 格式: .1.3.6.1.2.1.1.1.0 = STRING: "Linux xxx 6.1"
            parts = stripped.split("=", 1)
            if len(parts) == 2:
                value = parts[1].strip()
                value = re.sub(r"^(STRING|OCTET STRING|INTEGER|Gauge32|Counter32|IpAddress|Timeticks):\s*", "", value)
                value = value.strip('"')
                out.append(f"{parts[0].strip()[:45]} = {value[:100]}")
    return out


class SnmpEnumProfile(ToolProfile):
    name = "snmp_enum"
    aliases = ["snmp", "snmpwalk", "团体串", "snmp 枚举", "网络设备枚举"]
    summary = "SNMP 公共团体串枚举"
    lore = """### SNMP 枚举深度使用要点
- 原理：SNMP v1/v2c 靠团体串（community string）认证，默认 public/private。
  开在 161/udp 的服务如果没改团体串，等于把系统信息开放给全网。
- 枚举价值：sysDescr（系统/版本）→ 查已知漏洞；sysName/接口 → 网络拓扑；
  进一步全 OID 枚举（1.3.6.1.2.1）可拿到进程、用户、路由表，
  部分设备配置里直接含明文密码（如 Cisco 设备配置串）。
- 进阶：尝试常见团体串（public/private/community/设备厂商默认值）；
  UDP 161 用 nmap -sU -p 161 先确认端口开放。
- 报告价值：默认团体串可读 = 中危信息泄露，截图关键 OID 输出作证据。"""
    extra_schemas = SCHEMAS

    async def exec_snmp_enum(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("snmpwalk"):
            return "snmpwalk 未安装（apt install snmp）。"
        target = sanitize_target(str(args.get("target") or ""), label="目标")
        community = str(args.get("community") or "public").strip()
        if not _COMMUNITY_RE.match(community):
            return f"community 含非法字符: {community!r}"
        raw = await self._run(ex, _build_cmd(target, community), timeout=60)
        rows = _parse(raw)
        if not rows:
            head = [
                f"未读取到信息（团体串 '{community}' 可能无效 / SNMP 未开放 / 目标不可达）",
                "建议：试其他团体串（private/community），或用 nmap -sU -p 161 确认端口。",
            ]
            return self._summary(raw, head, tail=15)
        head = [f"🎯 SNMP 团体串 '{community}' 有效（{len(rows)} 项系统信息）:"]
        head += [f"  {r}" for r in rows[:15]]
        if len(rows) > 15:
            head.append(f"  … 共 {len(rows)} 项")
        head.append("下一步：全 OID 枚举拿进程/用户/配置，部分设备含明文密码（中危信息泄露）。")
        return self._summary(raw, head, tail=15)
