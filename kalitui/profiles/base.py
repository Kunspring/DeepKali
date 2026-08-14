"""工具档案基类：深度定制一个 Kali 工具的骨架。

一个 ToolProfile 包含：
  - lore：注入系统提示词的深度知识（何时用、怎么用、注意事项）
  - extra_schemas：专属 function calling schema（参数化封装）
  - 执行器：校验参数 → 构造命令 → 复用 run_command 的安全审批与超时机制
            → 输出摘要（避免把几百行原始输出全塞进 LLM 上下文）

安全约定：所有外部输入（目标、URL、路径）必须过 sanitize_* 校验，
拒绝任何 shell 注入字符；命令一律走 Executor，危险操作自动触发审批。
"""

from __future__ import annotations

import re
from typing import Any

# 注入字符黑名单：出现即拒绝
_INJECTION = re.compile(r"[;&|`$(){}<>]|\b(?:sudo|rm|dd|mkfs|shutdown|reboot)\b|\n")

# 目标格式：IPv4 / IPv4 段 / CIDR / 域名 / 主机名
_TARGET_RE = re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|"
    r"localhost|(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{0,4})$"
)

_URL_RE = re.compile(r"^https?://[a-zA-Z0-9.\-:]+(?:/[^\s]*)?$", re.IGNORECASE)

_WORDLIST_ROOT = re.compile(r"^/usr/share/wordlists/[\w./-]+$|^/[\w./-]+\.(txt|lst|lst.gz)$")


def sanitize_target(value: str, *, label: str = "目标") -> str:
    v = value.strip()
    if not v:
        raise ValueError(f"{label}不能为空")
    if _INJECTION.search(v) or not _TARGET_RE.match(v):
        raise ValueError(f"{label}格式非法（仅允许 IP/CIDR/域名）: {v!r}")
    # IPv4 CIDR 前缀必须 0-32
    if "/" in v and not v.rsplit("/", 1)[1].isdigit():
        raise ValueError(f"{label} CIDR 前缀非法: {v!r}")
    if "/" in v and int(v.rsplit("/", 1)[1]) > 32:
        raise ValueError(f"{label} CIDR 前缀超过 32: {v!r}")
    return v


_URL_QUERY_RE = re.compile(r"^https?://[a-zA-Z0-9.\-:]+(?:/[^\s;|`$\\<>{}]*)?$", re.IGNORECASE)


def sanitize_url(value: str, *, label: str = "URL", allow_query: bool = False) -> str:
    """URL 校验。allow_query=True 时允许 & 作为 query 分隔符（调用方必须 shlex.quote）。"""
    v = value.strip()
    if not v:
        raise ValueError(f"{label}不能为空")
    if allow_query:
        if not _URL_QUERY_RE.match(v):
            raise ValueError(f"{label}格式非法（仅允许 http(s)://host[:port][/path?query]）: {v!r}")
    elif _INJECTION.search(v) or not _URL_RE.match(v):
        raise ValueError(f"{label}格式非法（仅允许 http(s)://host[:port][/path]）: {v!r}")
    return v


def sanitize_wordlist(value: str, *, label: str = "字典") -> str:
    v = value.strip()
    if not v:
        raise ValueError(f"{label}不能为空")
    if _INJECTION.search(v) or not _WORDLIST_ROOT.match(v):
        raise ValueError(f"{label}仅允许 /usr/share/wordlists/ 下的路径: {v!r}")
    return v


def sanitize_int(value: Any, default: int, lo: int, hi: int, label: str, strict: bool = False) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    if strict and not lo <= n <= hi:
        raise ValueError(f"{label} 必须在 {lo}-{hi}: {value!r}")
    return max(lo, min(n, hi))


def sanitize_ports(value: str | None) -> str | None:
    """端口串：22 / 22,80,443 / 1-1000 / top-100"""
    if not value:
        return None
    v = str(value).strip()
    if re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", v):
        lo, _, hi = v.partition("-")
        if 1 <= int(lo) <= 65535 and (not hi or int(hi) <= 65535):
            return v
    if re.fullmatch(r"\d{1,5}(?:,\d{1,5}){1,19}", v):
        if all(1 <= int(p) <= 65535 for p in v.split(",")):
            return v
    if v.startswith("top-") and v[4:].isdigit():
        return v
    raise ValueError(f"端口格式非法: {value!r}")


def check_installed(binary: str) -> bool:
    from shutil import which

    return which(binary) is not None


class ToolProfile:
    """工具档案基类。子类覆盖类属性并实现 exec_<toolname> 方法。"""

    name: str = ""
    aliases: list[str] = []
    summary: str = ""
    lore: str = ""
    extra_schemas: list[dict[str, Any]] = []

    # ---------- 注册 ----------
    def matches(self, text: str) -> bool:
        low = text.lower()
        return any(a in low for a in [self.name, *self.aliases])

    def tool_names(self) -> list[str]:
        return [
            s["function"]["name"]
            for s in self.extra_schemas
        ]

    def register(self, executor: Any) -> None:
        for schema in self.extra_schemas:
            tname = schema["function"]["name"]
            fn = getattr(self, f"exec_{tname}", None)
            if fn is None:
                raise AttributeError(f"{self.name} profile 缺少 exec_{tname}")
            executor.extensions[tname] = fn

    # ---------- 执行辅助 ----------
    async def _run(
        self, ex: Any, command: str, timeout: int = 120, max_keep: int = 60
    ) -> str:
        """复用 run_command：自动过安全分级（危险命令触发审批）+ 超时终止。"""
        return await ex.execute(
            "run_command",
            {"command": command, "timeout": timeout},
        )

    @staticmethod
    def _summary(raw: str, head: list[str], tail: int = 40) -> str:
        """摘要 = 头部（关键发现）+ 原始输出尾部。"""
        lines = [l for l in raw.splitlines() if l.strip()]
        if not lines:
            return raw
        return "关键结果：\n" + "\n".join(head) + "\n\n原始输出（尾部）:\n" + "\n".join(lines[-tail:])
