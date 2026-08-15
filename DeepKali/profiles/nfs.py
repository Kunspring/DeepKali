"""NFS 枚举：showmount 导出列表 + 无认证挂载检查（内网高频配置缺陷）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "nfs_enum",
            "description": (
                "NFS 枚举：showmount 列出目标导出的 NFS 共享目录。"
                "内网高频配置缺陷：NFS 共享配置了 no_root_squash 或弱权限，"
                "可匿名挂载读敏感文件（甚至写），是横向移动的常见入口。"
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


def _build_cmd(target: str) -> str:
    return f"showmount -e {target} 2>&1"


def _parse(raw: str) -> list[str]:
    """提取导出目录行（排除表头与错误信息）。"""
    out: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(k in stripped for k in ("Export list", "clnt_create", "mount clnt", "rpc", "Sorry")):
            continue
        if stripped.startswith("/") or re.match(r"^[\w.-]+:", stripped):
            out.append(stripped)
    return out


class NfsEnumProfile(ToolProfile):
    name = "nfs_enum"
    aliases = ["nfs", "showmount", "共享目录", "nfs 枚举", "网络共享"]
    summary = "NFS 共享枚举"
    lore = """### NFS 枚举深度使用要点
- 原理：showmount -e 列出目标 NFS 导出的共享。很多内网环境导出权限过宽
  （world readable / no_root_squash），可匿名挂载。
- 挂载检查：`mkdir /tmp/m && mount -t nfs target:/share /tmp/m` →
  读敏感文件（备份、配置、密钥）；可写则可能是横向入口（写 authorized_keys）。
- 重点排查：no_root_squash 挂载 = root 权限映射，最高危；
  /home、/backup、/etc 导出 = 常见敏感目标。
- 报告价值：可匿名挂载读/写 = 中高危配置缺陷，记录挂载选项（rw/ro、squash）作证据。"""
    extra_schemas = SCHEMAS

    async def exec_nfs_enum(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("showmount"):
            return "showmount 未安装（apt install nfs-common）。"
        target = sanitize_target(str(args.get("target") or ""), label="目标")
        raw = await self._run(ex, _build_cmd(target), timeout=45)
        shares = _parse(raw)
        if not shares:
            head = [
                "未发现可枚举的 NFS 共享（服务未开放 / 导出受限 / 目标不可达）",
                "建议：nmap -sV -p 2049 确认 NFS 端口；或换端口扫描确认。",
            ]
            return self._summary(raw, head, tail=15)
        head = [f"🎯 NFS 导出 ({len(shares)} 个共享):"]
        head += [f"  {s}" for s in shares[:20]]
        if len(shares) > 20:
            head.append(f"  … 共 {len(shares)} 个")
        head.append(
            "下一步：逐个挂载检查（mount -t nfs target:/share /tmp/m）→ 读敏感文件；"
            "no_root_squash / 可写共享 = 高价值横向入口。"
        )
        return self._summary(raw, head, tail=15)
