"""netcat 深度定制：监听/连接（危险操作，触发确认——常与反弹 shell 相关）。"""

from __future__ import annotations

import re
import time
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "nc_listen",
            "description": (
                "用 netcat 在本地端口监听并接收数据（限时，默认 15 秒后自动停止）。"
                "⚠ 危险操作：会触发确认弹窗。"
                "用途：接收反弹 shell 的回连数据 / 临时搭个文件接收服务 / 排障端口连通性。"
                "收到的数据会保存到 /tmp 供分析。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "port": {"type": "integer", "description": "监听端口（1-65535）"},
                    "seconds": {
                        "type": "integer",
                        "description": "监听时长秒数（默认 15，反弹 shell 场景建议 30-60）",
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "详细输出（-v），默认 true",
                    },
                },
                "required": ["port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nc_connect",
            "description": (
                "用 netcat 连接目标端口并发送数据（如 HTTP 请求、服务 banner 探测）。"
                "⚠ 危险操作：会触发确认弹窗（连接可能被用于反弹 shell 回连）。"
                "banner 探测也可以用 run_command 'nc -zv host port' 或 nmap 完成。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "目标 IP/域名"},
                    "port": {"type": "integer", "description": "目标端口"},
                    "data": {
                        "type": "string",
                        "description": "要发送的数据（可选，如 'GET / HTTP/1.0\\r\\n\\r\\n'）",
                    },
                    "seconds": {"type": "integer", "description": "等待响应秒数（默认 5）"},
                },
                "required": ["host", "port"],
            },
        },
    },
]

_DATA_RE = re.compile(r"^[\x20-\x7e]{0,1000}$")  # 仅可打印 ASCII，防注入


def _nc_bin() -> str:
    if check_installed("netcat"):
        return "netcat"
    if check_installed("nc"):
        return "nc"
    return ""


def _escape_data(data: str) -> str:
    """数据用单引号包裹 + 转义单引号，防止 shell 注入。"""
    return "'" + data.replace("'", "'\\''") + "'"


class NcProfile(ToolProfile):
    name = "netcat"
    aliases = ["nc 监听", "nc 连接", "反弹 shell 接收", "端口监听", "banner 探测", "监听", "反弹 shell"]
    summary = "网络连接与监听"
    lore = """### netcat 深度使用要点
- 监听：`nc -lvnp <port>` 接收回连；配合 msfvenom 生成的 payload 和 msf multi/handler。
- 探测：`nc -zv <host> <port>` 快速连通性测试（比 nmap 轻量）。
- banner 抓取：`echo | nc <host> <port>` 看服务指纹（FTP/SSH/HTTP 版本）。
- 反弹 shell 接收是危险动作：安全层会确认；确保目标是你控制的机器。
- 大流量传输用 nc 管道文件流；注意 nc 不同版本（openbsd/traditional）参数略不同。"""
    extra_schemas = SCHEMAS

    async def exec_nc_listen(self, ex: Any, args: dict[str, Any]) -> str:
        if not _nc_bin():
            return "netcat 未安装（apt install netcat-openbsd）。"
        port = sanitize_int(args.get("port"), 0, 1, 65535, "port", strict=True)
        seconds = sanitize_int(args.get("seconds"), 15, 5, 120, "seconds")
        verbose = bool(args.get("verbose", True))
        outfile = f"/tmp/nc-listen-{int(time.time())}.txt"
        vflag = "-v" if verbose else ""
        cmd = f"timeout {seconds} {_nc_bin()} -l -n -p {port} {vflag} > {outfile} 2>&1"
        raw = await self._run(ex, cmd, timeout=seconds + 10)
        try:
            got = open(outfile, "r", errors="replace").read().strip()
        except OSError:
            got = ""
        head = []
        if got:
            head.append(f"🎯 收到数据（{len(got)} 字符，已存 {outfile}）:")
            head += got.splitlines()[:20]
        else:
            head.append(f"监听 {seconds} 秒无数据到达（端口 {port}）。")
        return "\n".join(head) + "\n\n原始输出:\n" + raw[-800:]

    async def exec_nc_connect(self, ex: Any, args: dict[str, Any]) -> str:
        if not _nc_bin():
            return "netcat 未安装（apt install netcat-openbsd）。"
        host = sanitize_target(str(args["host"]))
        port = sanitize_int(args.get("port"), 0, 1, 65535, "port", strict=True)
        seconds = sanitize_int(args.get("seconds"), 5, 2, 30, "seconds")
        data = str(args.get("data") or "").strip()
        if data and not _DATA_RE.match(data):
            raise ValueError("data 仅允许可打印 ASCII 字符")
        if data:
            cmd = f"printf %s {_escape_data(data)} | timeout {seconds} {_nc_bin()} -q 1 -n {host} {port}"
        else:
            cmd = f"timeout {seconds} {_nc_bin()} -n {host} {port}"
        raw = await self._run(ex, cmd, timeout=seconds + 10)
        body = [l.strip() for l in raw.splitlines() if l.strip()][:25]
        if not body:
            body = ["无响应（连接成功但对方未返回数据，或连接被拒）"]
        return self._summary(raw, body, tail=40)
