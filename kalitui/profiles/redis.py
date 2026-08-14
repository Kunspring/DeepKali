"""redis-cli 深度定制：Redis 未授权访问/弱口令检查（危险操作，触发确认）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "redis_check",
            "description": (
                "检查 Redis 服务是否未授权访问（默认 6379 无密码）或弱口令。"
                "⚠ 危险操作：会触发确认弹窗。"
                "未授权 Redis 可直接读写数据甚至写计划任务/SSH key 拿 shell（仅授权测试）。"
                "只做无害检查：INFO + 键数量统计。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Redis 主机 IP"},
                    "port": {"type": "integer", "description": "端口（默认 6379）"},
                    "password": {
                        "type": "string",
                        "description": "密码（可选，测试弱口令时用）",
                    },
                },
                "required": ["host"],
            },
        },
    },
]

_PASS_RE = re.compile(r"^[\w.\-\\$@!]{1,128}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    host = sanitize_target(str(args["host"]))
    port = sanitize_int(args.get("port"), 6379, 1, 65535, "port", strict=True)
    password = str(args.get("password") or "").strip()
    if password and not _PASS_RE.match(password):
        raise ValueError(f"password 含非法字符: {password!r}")

    if password:
        # 用 redis-cli -a 传密码（--no-auth-warning 去警告行）
        cmd = (
            f"redis-cli -h {host} -p {port} -a '{password}' --no-auth-warning "
            f"INFO server | head -12"
        )
    else:
        cmd = f"redis-cli -h {host} -p {port} INFO server | head -12"
    return cmd, 30


class RedisProfile(ToolProfile):
    name = "redis"
    aliases = ["redis", "未授权访问", "6379", "redis 检查"]
    summary = "Redis 访问检查"
    lore = """### Redis 未授权检查深度使用要点
- 定位：内网常见高危配置——Redis 绑定 0.0.0.0 且无密码 = 未授权访问。
- 判断：INFO server 返回 redis_version 即未授权成功；(error) NOAUTH 则需密码。
- 无害检查：INFO/键数统计；不执行危险命令（CONFIG SET/SLAVEOF）。
- 未授权利用（授权测试）：写 SSH key（CONFIG SET dir）、写 crontab、主从复制 RCE。
- 弱口令测试用密码参数逐个试；配合 hydra（redis 协议）批量测更高效。"""
    extra_schemas = SCHEMAS

    async def exec_redis_check(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("redis-cli"):
            return "redis-cli 未安装（apt install redis-tools）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        if re.search(r"redis_version", raw):
            head = ["🎯 Redis 未授权/凭据有效！可直接访问:"]
            head += [l.strip() for l in raw.splitlines() if ":" in l][:15]
            head.append("下一步：确认授权后评估利用面（写 SSH key/计划任务等）。")
        elif "NOAUTH" in raw or "ERR Client sent AUTH" in raw:
            head = ["需要密码（认证失败/未提供）——可尝试 redis 弱口令或 hydra。"]
        else:
            head = ["无法连接（主机不可达/端口关闭/超时）"]
        return self._summary(raw, head, tail=30)
