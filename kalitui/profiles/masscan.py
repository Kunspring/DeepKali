"""masscan：超大网段高速端口扫描（SRC 场景先快速发现存活主机与服务，再 nmap 深入）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "masscan",
            "description": (
                "用 masscan 对 IP/CIDR 网段做高速端口扫描（异步 TCP 握手，"
                "比 nmap 快几十倍）。适合 SRC 场景先快速摸清网段内开放端口，"
                "再用 nmap 对存活主机做服务识别。输出存活主机+端口清单与下一步建议。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP 或 CIDR 网段，如 10.0.0.0/24",
                    },
                    "ports": {
                        "type": "string",
                        "description": "端口范围（默认 1-10000），如 1-1000 或 80,443,8080",
                    },
                    "rate": {
                        "type": "integer",
                        "description": "发包速率 pps（默认 1000；授权范围内可调高）",
                    },
                },
                "required": ["target"],
            },
        },
    },
]

_LINE_RE = re.compile(r"Discovered open port (\d+)/tcp on ([\d.]+)")


def _build_cmd(target: str, ports: str, rate: int) -> str:
    parts = ["masscan", "--rate", str(rate)]
    if ports:
        parts += ["-p", ports]
    else:
        parts += ["-p", "1-10000"]
    parts += ["--wait", "5", target]
    return " ".join(parts), 420


def _summarize(raw: str) -> str:
    found: list[tuple[int, str]] = []
    for line in raw.splitlines():
        m = _LINE_RE.search(line)
        if m:
            found.append((int(m.group(1)), m.group(2)))
    if not found:
        return ToolProfile._summary(
            raw,
            ["未发现开放端口（网段无响应/防火墙丢弃/rate 过低）"],
            tail=20,
        )
    hosts = sorted({ip for _, ip in found})
    lines = [
        f"🎯 masscan 存活 {len(hosts)} 台主机 / {len(found)} 个开放端口:",
        "",
    ]
    for port, ip in sorted(found):
        lines.append(f"  {ip}:{port}")
    lines.append("")
    lines.append(
        f"下一步：对 {len(hosts)} 台存活主机用 nmap -sV 做服务识别，"
        "再按端口建议链深入（http/445/22…）。"
    )
    return ToolProfile._summary(raw, lines, tail=15)


class MasscanProfile(ToolProfile):
    name = "masscan"
    aliases = ["大网段扫描", "masscan", "快速发现", "网段扫描", "端口发现"]
    summary = "CIDR 网段高速端口扫描"
    lore = """### masscan 深度使用要点
- 定位：SRC 授权网段的"第一眼"。nmap -sP 一个 /24 要几分钟，masscan
  千级 pps 几秒出结果。先 masscan 摸存活，再 nmap -sV 深入——省时省力。
- 参数：`--rate` 是发包速率（授权网段内 1000-10000 pps 常见；对外网段
  别乱拉高，会触发告警）；`-p 1-10000` 常用范围；`--wait 5` 等收尾包。
- 结果解析：masscan 只输出 "Discovered open port"，不输出关闭端口——
  没出现 = 关闭/被丢包；被防火墙丢包时会漏报，可降低 rate 重扫。
- 与 KaliTUI 联动：masscan 得到存活列表 → nmap -sV 服务识别 →
  playbook 按端口给建议链（http/445/22/9200…）→ 专项工具深入。
- 注意：masscan 需要 root 权限（raw socket）；TUI 运行在 root 环境没问题。"""
    extra_schemas = SCHEMAS

    async def exec_masscan(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("masscan"):
            return "masscan 未安装（apt install masscan）。"
        target = sanitize_target(str(args.get("target") or ""))
        ports = str(args.get("ports") or "").strip()
        if ports and not re.fullmatch(r"[\d,\-]{1,64}", ports):
            raise ValueError(f"ports 格式非法: {ports!r}")
        rate = args.get("rate")
        if rate is None:
            rate = 1000
        try:
            rate = int(rate)
        except (TypeError, ValueError):
            raise ValueError(f"rate 必须是整数: {rate!r}") from None
        if not 1 <= rate <= 1_000_000:
            raise ValueError(f"rate 超出范围: {rate}")
        raw = await self._run(ex, *_build_cmd(target, ports, rate))
        return _summarize(raw)
