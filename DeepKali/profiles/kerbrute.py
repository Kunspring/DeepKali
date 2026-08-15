"""kerbrute：无凭据 AD 用户枚举 / 密码喷洒（KDC 错误差异判断用户存在性）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "kerbrute",
            "description": (
                "用 kerbrute 做无凭据 AD 用户枚举（userenum，KDC 返回差异判断"
                "用户是否存在）或密码喷洒（passwordspray，单密码多用户，规避锁定）。"
                "拿到有效用户后下一步：getnpusers 查 ASREP-roastable、密码喷洒/爆破。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "目标域，如 corp.local",
                    },
                    "userlist": {
                        "type": "string",
                        "description": "用户名列表：文件路径，或逗号分隔的用户名（如 admin,guest）",
                    },
                    "password": {
                        "type": "string",
                        "description": "喷洒密码（passwordspray 模式用；userenum 模式省略）",
                    },
                    "dc": {
                        "type": "string",
                        "description": "目标域控 IP/主机名（可选）",
                    },
                },
                "required": ["domain", "userlist"],
            },
        },
    },
]

_VALID_RE = re.compile(r"\[\+\]\s*VALID USERNAME:\s*(\S+)")
_ERR_RE = re.compile(r"\[\*\]|failed|timed out|no response|KDC_ERR", re.IGNORECASE)


def _build_cmd(domain: str, userlist: str, password: str, dc: str) -> str:
    mode = "passwordspray" if password else "userenum"
    parts = ["kerbrute", mode, "-d", domain]
    if dc:
        parts += ["--dc", dc]
    if "," in userlist:
        parts += [u.strip() for u in userlist.split(",") if u.strip()]
    else:
        parts += [userlist]
    if password:
        parts += ["-p", password]
    return " ".join(parts), 240


def _summarize(raw: str) -> str:
    users = sorted({m.group(1) for m in _VALID_RE.finditer(raw)})
    if not users:
        reason = "KDC 无响应/网络不通" if _ERR_RE.search(raw) else "未发现有效用户"
        return ToolProfile._summary(raw, [f"枚举未发现有效用户（{reason}）"], tail=20)
    head = [
        f"🎯 有效用户 {len(users)} 个:",
        "  " + " ".join(users),
        "下一步：getnpusers 查 ASREP-roastable（无需密码哈希）；",
        "对有效用户做密码喷洒（kerbrute passwordspray，单密码规避锁定）。",
    ]
    return ToolProfile._summary(raw, head, tail=25)


class KerbruteProfile(ToolProfile):
    name = "kerbrute"
    aliases = ["用户枚举", "kerbrute", "密码喷洒", "ad 用户", "域用户枚举"]
    summary = "无凭据 AD 用户枚举/密码喷洒"
    lore = """### kerbrute 深度使用要点
- 定位：无任何域凭据时的 AD 侦察第一步。KDC 对存在/不存在用户的
  AS-REQ 返回错误不同（KDC_ERR_PREAUTH_REQUIRED vs KDC_ERR_C_PRINCIPAL_UNKNOWN），
  kerbrute 据此枚举有效用户名，全程无凭据、不锁定账号。
- 用法：`kerbrute userenum -d corp.local users.txt`；密码喷洒用
  `kerbrute passwordspray -d corp.local users.txt -p Summer2024`——
  单密码多用户，规避 5 次锁定策略。域控可达性差时加 `--dc <IP>`。
- 用户字典：Kali 自带 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt，
  或按目标命名习惯生成（姓+名/工号/服务账号 svc_*）。
- 拿到有效用户后：getnpusers（ASREP-roastable 目标）→ 喷洒/爆破 →
  evilwinrm/impacket 登录验证 → bloodhound_py 采域关系定路径。
- 注意：passwordspray 默认 -t 并发会触发告警，先小字典 + 低速试水；
  喷洒前确认授权范围（用户枚举也属于主动探测，需目标书面授权）。"""
    extra_schemas = SCHEMAS

    async def exec_kerbrute(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("kerbrute"):
            return "kerbrute 未安装（https://github.com/ropnop/kerbrute 下载二进制）。"
        domain = str(args.get("domain") or "").strip()
        if not re.fullmatch(r"[\w.-]{1,128}", domain):
            raise ValueError(f"domain 格式非法: {domain!r}")
        userlist = str(args.get("userlist") or "").strip()
        if not userlist:
            raise ValueError("userlist 不能为空")
        if "," not in userlist and (" " in userlist or "/" in userlist):
            # 单值路径含空格/斜杠 → 疑似路径注入/格式错误
            raise ValueError(f"userlist 格式非法: {userlist!r}（用逗号分隔用户名或给文件路径）")
        password = str(args.get("password") or "").strip()
        dc = sanitize_target(str(args.get("dc") or "")) if args.get("dc") else ""
        raw = await self._run(ex, *_build_cmd(domain, userlist, password, dc))
        return _summarize(raw)
