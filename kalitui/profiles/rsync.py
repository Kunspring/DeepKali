"""rsync 枚举：daemon 模式模块列表 + 无认证读取检查（内网高频配置缺陷）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "rsync_enum",
            "description": (
                "rsync 枚举：列出目标 rsync daemon（873/tcp）导出的模块。"
                "内网高频配置缺陷：rsyncd.conf 模块没设认证或 read only=false，"
                "可匿名列出/下载敏感文件，甚至上传写入（横向移动入口）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "目标 IP 或域名，如 10.0.0.5",
                    },
                },
                "required": ["target"],
            },
        },
    },
]

_ERR_MARKERS = ("Connection refused", "timed out", "unable to connect", "access denied", "@ERROR")


def _build_cmd(target: str) -> str:
    return f"rsync --list-only --timeout=10 rsync://{target}/ 2>&1"


def _parse(raw: str) -> list[str]:
    """提取模块行（如 'backup  Backup data'）。"""
    out: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(m in stripped for m in _ERR_MARKERS):
            continue
        # 模块行：名字 + 描述
        parts = stripped.split(None, 1)
        if parts and re.match(r"^[A-Za-z0-9._-]{1,64}$", parts[0]) and len(parts) >= 1:
            out.append(stripped[:120])
    return out


class RsyncEnumProfile(ToolProfile):
    name = "rsync_enum"
    aliases = ["rsync", "rsync 枚举", "rsync daemon", "备份同步"]
    summary = "rsync 共享枚举"
    lore = """### rsync 枚举深度使用要点
- 原理：rsync daemon（873/tcp）通过 /etc/rsyncd.conf 暴露模块。很多运维把
  备份目录直接 rsync 出来且无认证（或 read only=false）。
- 无认证读取：`rsync rsync://target/module/ /tmp/d/` 直接下载；
  可写模块（read only=false）可上传（写 authorized_keys 等 → 横向入口）。
- 常见敏感模块名：backup、www、home、data、logs、etc、root。
- 报告价值：无认证读 = 中危信息泄露；可写 = 高危，记录模块名与下载内容作证据。"""
    extra_schemas = SCHEMAS

    async def exec_rsync_enum(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("rsync"):
            return "rsync 未安装（apt install rsync）。"
        target = sanitize_target(str(args.get("target") or ""), label="目标")
        raw = await self._run(ex, _build_cmd(target), timeout=45)
        modules = _parse(raw)
        if not modules:
            head = [
                "未发现可枚举的 rsync 模块（daemon 未开 / 有认证 / 目标不可达）",
                "建议：nmap -sV -p 873 确认端口；有认证时可试常见弱口令（rsync 密码文件）。",
            ]
            return self._summary(raw, head, tail=15)
        head = [f"🎯 rsync 模块 ({len(modules)} 个，无认证可读):"]
        head += [f"  {m}" for m in modules[:20]]
        if len(modules) > 20:
            head.append(f"  … 共 {len(modules)} 个")
        head.append(
            "下一步：rsync rsync://target/module/ /tmp/d/ 下载检查敏感文件；"
            "若可写（read only=false）可上传文件 → 高价值横向入口。"
        )
        return self._summary(raw, head, tail=15)
