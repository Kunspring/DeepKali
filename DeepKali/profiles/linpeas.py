"""linpeas 提权枚举：Linux 本地提权自动化检查（拿到 shell 后第一步）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "linpeas",
            "description": (
                "运行 PEASS-ng 做本地提权枚举（快速模式 -q）：Linux 目标用 linpeas，"
                "Windows 目标用 winpeas。拿到 shell 后的标准第一步：自动检查 sudo 配置、"
                "SUID、定时任务、可写路径、环境变量、内核版本、弱权限文件、"
                "Windows 服务/令牌/ACL 等提权向量，输出带 [+]/[!] 标记的高价值发现。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "quick": {
                        "type": "boolean",
                        "description": "快速模式（-q，跳过耗时检查），默认 true",
                    },
                    "os": {
                        "type": "string",
                        "enum": ["linux", "windows"],
                        "description": "目标系统类型（默认 linux；Windows 目标用 winpeas）",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "超时秒数（默认 300，大目标/慢机器可加大）",
                    },
                },
            },
        },
    },
]

_HIT_RE = re.compile(r"^\s*\[\s*([+!])\s*\]\s*(.+)$")


def _parse(raw: str) -> tuple[list[str], list[str]]:
    """提取 [+] 高价值发现与 [!] 警告行（先剥 ANSI 色码）。"""
    hits: list[str] = []
    warns: list[str] = []
    for line in raw.splitlines():
        clean = re.sub(r"\x1b\[[0-9;]*m", "", line)
        m = _HIT_RE.match(clean)
        if not m:
            continue
        text = m.group(2).strip()
        if not text:
            continue
        if m.group(1) == "+":
            hits.append(text)
        else:
            warns.append(text)
    return hits, warns


class LinpeasProfile(ToolProfile):
    name = "linpeas"
    aliases = ["提权枚举", "linpeas", "linux 提权", "提权检查", "peass"]
    summary = "Linux 本地提权枚举"
    lore = """### linpeas 提权枚举深度使用要点
- 定位：拿到目标 shell 后第一步——自动枚举 70+ 提权向量，比手动翻快十倍。
- 高价值发现（[+]）优先级：SUID 二进制（gtfobins 查利用）、sudo -l 免密条目、
  定时任务（cron 可写脚本）、可写 PATH 目录、docker/lxc 组、内核版本（脏牛类 CVE）、
  敏感文件（/etc/shadow 可读、备份、.ssh）。
- 流程衔接：linpeas 输出 [+] 后 → searchsploit 查对应 CVE/工具 → 提权利用
  （注意：利用属攻击行为，仅在明确授权的测试环境执行）。
- -q 快速模式够用；大目标可去掉 quick 跑全量（更慢但更全）。
- 提权成功后立即记录 flag/新权限证据，继续内网横向（privesc 知识库联动）。"""
    extra_schemas = SCHEMAS

    async def exec_linpeas(self, ex: Any, args: dict[str, Any]) -> str:
        os_type = str(args.get("os") or "linux").strip().lower()
        binary = "winpeas" if os_type == "windows" else "linpeas"
        if not check_installed(binary):
            return f"{binary} 未安装（apt install peass，或从 github.com/peass-ng/PEASS-ng 下载）。"
        quick = bool(args.get("quick", True))
        timeout = max(30, min(int(args.get("timeout") or 300), 1800))
        cmd = f"{binary} -q" if quick else binary
        raw = await self._run(ex, cmd, timeout=timeout)
        hits, warns = _parse(raw)
        head: list[str] = []
        if hits:
            head.append(f"🎯 {binary} 提权线索 ({len(hits)} 条):")
            head += [f"  [+] {h[:110]}" for h in hits[:25]]
            if len(hits) > 25:
                head.append(f"  … 共 {len(hits)} 条，其余见原始输出")
        if warns:
            head.append(f"⚠ 警告 ({len(warns)} 条):")
            head += [f"  [!] {w[:110]}" for w in warns[:10]]
        if not head:
            head = ["未发现明显提权线索（仍需人工确认：sudo -l、内核版本、敏感文件）"]
        head.append("下一步：对 [+] 线索逐条验证可利用性（SUID→gtfobins、内核→CVE 匹配）。")
        return self._summary(raw, head, tail=40)
