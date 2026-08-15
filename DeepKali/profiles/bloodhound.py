"""bloodhound-python 采集：Active Directory 域关系数据收集（SharpHound 的 Python 版）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "bloodhound_py",
            "description": (
                "用 bloodhound-python 采集 AD 域关系数据（用户/组/计算机/ACL），"
                "供 BloodHound 分析最短攻击路径。拿到域凭据（或 NTLM hash）后"
                "的标准下一步：先采集再分析路径，定位可达 DA 的链条。"
                "输出采集统计与后续分析建议。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "目标域，如 corp.local",
                    },
                    "username": {
                        "type": "string",
                        "description": "域用户，如 john@corp.local 或 corp.local\\\\john",
                    },
                    "password": {
                        "type": "string",
                        "description": "密码（与 hash 二选一）",
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash（与密码二选一，如 31d6cfe0...）",
                    },
                    "dc": {
                        "type": "string",
                        "description": "目标域控 IP/主机名（可选，默认 DNS 发现）",
                    },
                },
                "required": ["domain", "username"],
            },
        },
    },
]

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _build_cmd(domain: str, username: str, password: str, hash_: str, dc: str) -> str:
    parts = [
        "bloodhound-python",
        "-d", domain,
        "-u", username,
        "--zip",
    ]
    if password:
        parts += ["-p", password]
    elif hash_:
        parts += ["-k", hash_]
    if dc:
        parts += ["--dc", dc]
    parts += ["-c", "All"]
    return " ".join(parts), 300


def _summarize(raw: str) -> str:
    stats: list[str] = []
    for line in raw.splitlines():
        m = re.search(r"(users|groups|computers|domains|gpos|ous|containers)\s*:\s*(\d+)", line, re.IGNORECASE)
        if m:
            stats.append(f"{m.group(1)}: {m.group(2)}")
    done = "Done" in raw or "COMPLETE" in raw.upper() or "已完成" in raw
    head: list[str] = []
    if done:
        head.append("🎯 AD 采集完成:")
        if stats:
            head.append("  " + " / ".join(stats[:8]))
        head.append("下一步：neo4j 导入 bloodhound 数据，用最短路径查询（Shortest Path）定位到 DA 的链条。")
    else:
        head = ["采集未完成（凭据无效/网络不可达/目标非域控）——检查凭据与 DC 可达性"]
    return ToolProfile._summary(raw, head, tail=25)


class BloodHoundPyProfile(ToolProfile):
    name = "bloodhound_py"
    aliases = ["bloodhound", "bloodhound-python", "域信息采集", "ad 采集", "域关系", "shortest path"]
    summary = "AD 域关系数据采集"
    lore = """### bloodhound-python 深度使用要点
- 定位：拿到域凭据后的标准第二步（第一步是侦察域结构）。采集结果导入
  BloodHound（neo4j）后跑 Shortest Path 查询，直接得到"当前用户 → DA"链条。
- 凭据来源：evilwinrm/impacket 会话、secretsdump 的 hash、Kerberoast 破解的 TGS。
- 常见用法：`bloodhound-python -d corp.local -u user -p pass -c All --zip`；
  有 hash 用 `-k`（NTLM）替代密码。
- 采集失败排查：DC 不可达、DNS 解析错误、凭据过期、LDAP 签名（LDAPS）要求。
- 数据价值：域管理员成员、跨域信任、ACL 滥用点（GenericAll/WriteDacl）、
  GPO 写权限——这些是横向/提权攻击路径的原材料。
- 与 DeepKali 联动：bloodhound_py 采集 → 分析路径（neo4j 查询可用 run_command 跑）→
  沿路径用 evilwinrm/imp_exec 验证。"""
    extra_schemas = SCHEMAS

    async def exec_bloodhound_py(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("bloodhound-python"):
            return "bloodhound-python 未安装（apt install bloodhound.py）。"
        domain = str(args.get("domain") or "").strip()
        username = str(args.get("username") or "").strip()
        if not re.fullmatch(r"[\w.-]{1,128}", domain):
            raise ValueError(f"domain 格式非法: {domain!r}")
        if not re.fullmatch(r"[\w.\\@-]{1,256}", username):
            raise ValueError(f"username 格式非法: {username!r}")
        password = str(args.get("password") or "").strip()
        hash_ = str(args.get("hash") or "").strip()
        if bool(password) == bool(hash_):
            raise ValueError("password 与 hash 必须且只能提供一个")
        if hash_ and not _HASH_RE.match(hash_):
            raise ValueError("hash 必须是 32 位 hex（NTLM）")
        dc = sanitize_target(str(args.get("dc") or "")) if args.get("dc") else ""
        raw = await self._run(ex, *_build_cmd(domain, username, password, hash_, dc))
        return _summarize(raw)
