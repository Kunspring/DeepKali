"""nmap 深度定制：参数化扫描 + 结果摘要。"""

from __future__ import annotations

from typing import Any

from .base import (
    ToolProfile,
    check_installed,
    sanitize_int,
    sanitize_ports,
    sanitize_target,
)

_SCAN_MODES: dict[str, str] = {
    "quick": "快速：默认 -T4 -F（前100常用端口）",
    "version": "服务版本识别：-sV -T4",
    "aggressive": "全面：-sV -sC -O -T4（版本+默认脚本+OS）",
    "udp": "UDP 常用端口：-sU --top-ports 20",
    "ping": "主机发现（Ping 扫描）：-sn",
    "all": "全端口：-p- -T4（慢，慎重）",
}

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": (
                "对目标执行 nmap 扫描（深度定制）。按阶段选用 scan_type："
                "先 ping 主机发现，再 quick/version 端口与服务识别，最后 aggressive 深挖。"
                "比裸 run_command 更安全（参数校验+自动摘要）。"
                "对局域网主机用 quick/version 即可；扫描外部目标前必须先经用户授权。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "目标 IP / CIDR / 域名，如 192.168.1.0/24 或 scanme.nmap.org",
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": list(_SCAN_MODES),
                        "description": "扫描模式：" + "；".join(f"{k}={v}" for k, v in _SCAN_MODES.items()),
                    },
                    "ports": {
                        "type": "string",
                        "description": "指定端口，如 '22,80,443' 或 '1-1000'（默认按扫描模式）",
                    },
                    "sudo": {
                        "type": "boolean",
                        "description": "是否用 sudo（SYN 半开扫描/OS 检测需要；root 下通常不需要）",
                    },
                },
                "required": ["target"],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    target = sanitize_target(str(args["target"]))
    mode = str(args.get("scan_type") or "quick").strip().lower()
    if mode not in _SCAN_MODES:
        raise ValueError(f"scan_type 仅支持: {', '.join(_SCAN_MODES)}")
    sudo = bool(args.get("sudo"))
    ports = sanitize_ports(args.get("ports"))

    base = "sudo nmap" if sudo else "nmap"
    if mode == "ping":
        cmd = f"{base} -sn -T4 {target}"
        return cmd, 120
    if mode == "quick":
        cmd = f"{base} -T4 -F {target}"
    elif mode == "version":
        cmd = f"{base} -sV -T4 {target}"
    elif mode == "aggressive":
        cmd = f"{base} -sV -sC -O -T4 {target}"
    elif mode == "udp":
        cmd = f"{base} -sU --top-ports 20 -T4 {target}"
    else:  # all
        cmd = f"{base} -p- -T4 {target}"
    if ports:
        cmd = f"{base} -p{ports} {target}" if mode in ("quick", "version") else cmd
    timeout = 600 if mode == "all" else (300 if mode in ("aggressive", "udp") else 180)
    return cmd, timeout


def _summarize(raw: str) -> str:
    open_ports: list[str] = []
    hosts_up = 0
    os_guess = ""
    for line in raw.splitlines():
        if re_search_port(line):
            open_ports.append(line.strip())
        if line.startswith("Nmap scan report"):
            hosts_up += 1
        if line.startswith("OS details:"):
            os_guess = line.split(":", 1)[1].strip()
    head: list[str] = []
    if hosts_up:
        head.append(f"存活主机: {hosts_up} 台")
    if open_ports:
        head.append(f"开放端口 ({len(open_ports)}):")
        head.extend(open_ports[:30])
        if len(open_ports) > 30:
            head.append(f"… 共 {len(open_ports)} 个开放端口")
    else:
        head.append("未发现开放端口（或全部过滤/关闭）")
    if os_guess:
        head.append(f"OS 猜测: {os_guess}")
    head.append("下一步建议：对开放端口做 version 扫描（scan_type=version）或针对性服务枚举。")
    return ToolProfile._summary(raw, head, tail=50)


def re_search_port(line: str) -> bool:
    # "22/tcp   open  ssh" / "443/tcp  open  ssl/http"
    return "/tcp" in line and "open" in line


class NmapProfile(ToolProfile):
    name = "nmap"
    aliases = ["端口扫描", "portscan", "扫描端口", "nmap 扫描", "扫描一下", "帮我扫描", "端口"]
    summary = "端口扫描与服务识别"
    lore = """### nmap 深度使用要点
- 分阶段：`ping`(主机发现) → `quick`(快速端口) → `version`(服务版本) → `aggressive`(脚本+OS)。
- 常用组合：`-sV` 版本识别；`-sC` 默认安全脚本；`-O` 操作系统指纹；`-sU` UDP（慢）。
- 输出关注：`open` 端口 + 服务/版本字段；版本号是后续漏洞匹配（searchsploit）的关键。
- 全端口 `all` 很慢，先 quick 摸底再定点深入；大批量目标用 CIDR，如 192.168.1.0/24。
- 扫描外部目标前必须确认授权；扫描结果出来后主动提出下一步（如针对 22 弱口令、80 Web 枚举）。"""
    extra_schemas = SCHEMAS

    async def exec_nmap_scan(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("nmap"):
            return "nmap 未安装（apt install nmap）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
