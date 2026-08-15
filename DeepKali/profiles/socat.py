"""socat 深度定制：端口转发/双向数据通道（危险操作，触发确认）。"""

from __future__ import annotations

from typing import Any

from .base import ToolProfile, check_installed, sanitize_int, sanitize_target
SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "socat_tunnel",
            "description": (
                "用 socat 建立端口转发/数据通道（穿透防火墙或连接目标内网服务）。"
                "⚠ 危险操作：会触发确认弹窗（可被用于隧道渗透）。"
                "典型用法：把目标内网端口转发到本机，或双向数据桥接。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "listen_port": {"type": "integer", "description": "本机监听端口"},
                    "target_host": {"type": "string", "description": "转发目标主机"},
                    "target_port": {"type": "integer", "description": "转发目标端口"},
                    "seconds": {
                        "type": "integer",
                        "description": "转发保持秒数（默认 30）",
                    },
                },
                "required": ["listen_port", "target_host", "target_port"],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    listen_port = sanitize_int(args.get("listen_port"), 0, 1, 65535, "listen_port", strict=True)
    host = sanitize_target(str(args.get("target_host") or ""))
    tport = sanitize_int(args.get("target_port"), 0, 1, 65535, "target_port", strict=True)
    seconds = sanitize_int(args.get("seconds"), 30, 5, 3600, "seconds")
    cmd = (
        f"timeout {seconds} socat TCP-LISTEN:{listen_port},reuseaddr,fork "
        f"TCP:{host}:{tport}"
    )
    return cmd, seconds + 15


class SocatProfile(ToolProfile):
    name = "socat"
    aliases = ["socat", "端口转发", "数据通道", "桥接"]
    summary = "端口转发与数据桥接"
    lore = """### socat 深度使用要点
- 定位：无 chisel 时的轻量转发；单向/双向数据桥接（如把内网 RDP 转出来）。
- 监听端 `TCP-LISTEN:<port>,reuseaddr,fork` 支持多连接；加 `,bind=0.0.0.0` 可对外监听。
- 配合 nc：`socat TCP-LISTEN:4444,fork TCP:127.0.0.1:22` 把内网 SSH 转出。
- UDP 转发用 UDP-LISTEN/UDP 对；文件/串口等特殊通道也能桥。
- 持久隧道建议用户开独立终端；本封装限时运行用于连通性验证。"""
    extra_schemas = SCHEMAS

    async def exec_socat_tunnel(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("socat"):
            return "socat 未安装（apt install socat）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        head = ["socat 转发已启动（限时运行）。测试连通：nc_connect 到本机监听端口。"]
        return self._summary(raw, head, tail=30)
