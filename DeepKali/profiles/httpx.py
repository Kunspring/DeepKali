"""httpx 批量存活探测：对目标列表批量做 HTTP 指纹（状态码/标题/技术栈）。"""

from __future__ import annotations

import re
import shlex
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "httpx_probe",
            "description": (
                "用 httpx 批量探测目标列表的 HTTP 存活与指纹（状态码/标题/技术栈）。"
                "适合拿到子域清单（crt_sh/dnsrecon）后的一键存活筛选——"
                "几十个域名几秒出结果，挑出 vpn/admin/api 等高价值目标继续深挖；"
                "探测结果可直接管道给 nuclei 做漏洞扫描。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "逗号分隔的目标列表（域名或 IP），如 'vpn.example.com,admin.example.com,10.0.0.5'",
                    },
                    "with_tech": {
                        "type": "boolean",
                        "description": "同时探测技术栈指纹（-tech-detect），默认 true",
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "跟随重定向（-follow-redirects），默认 true",
                    },
                },
                "required": ["targets"],
            },
        },
    },
]

_MAX_TARGETS = 20
# httpx 输出行: https://vpn.example.com [200] [标题] [nginx] [http3] ...
_LINE_RE = re.compile(
    r"^(https?://\S+)(?:\s+\[(\d{3})\])?(?:\s+\[([^\]]*)\])?(?:\s+\[([^\]]*)\])?"
)


def _split_targets(raw: str) -> list[str]:
    out: list[str] = []
    for tok in str(raw or "").split(","):
        tok = tok.strip()
        if tok and tok not in out:
            out.append(tok)
    if len(out) > _MAX_TARGETS:
        raise ValueError(f"目标数量过多（{len(out)} > {_MAX_TARGETS}）")
    return out


def _build_cmd(targets: list[str]) -> str:
    quoted = " ".join(shlex.quote(t) for t in targets)
    return (
        f"printf '%s\\n' {quoted} | "
        "httpx -silent -status-code -title -tech-detect -follow-redirects -timeout 10"
    )


def _parse(raw: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        url, status, title, tech = m.group(1), m.group(2), m.group(3), m.group(4)
        if not status and not title and not tech:
            continue  # 不是 httpx 结果行
        rows.append({
            "url": url,
            "status": status or "-",
            "title": title or "",
            "tech": tech or "",
        })
    return rows


class HttpxProbeProfile(ToolProfile):
    name = "httpx"
    aliases = ["批量探测", "存活探测", "httpx", "web 指纹", "批量指纹"]
    summary = "批量 HTTP 存活与指纹探测"
    lore = """### httpx 批量探测深度使用要点
- 定位：子域清单 → 存活的 Web 入口的"筛子"。一次探测几十个域名，
  几秒内区分存活/死链、看状态码与标题，快速定位高价值目标。
- 工作流衔接：crt_sh / dnsrecon 拿到子域 → httpx_probe 存活筛选 →
  对存活的高价值目标（后台/API/vpn/staging）做 nmap 服务识别 + nuclei 漏洞扫描。
- 状态码解读：200 直接可看；301/302 注意重定向落点（可能跳到登录页）；
  403 可能是权限受限但存在；404 基本无价值。
- 技术栈指纹价值：识别出框架（如 Spring/ThinkPHP/Laravel）后，
  直接对照已知 CVE 或走 sqlmap/ffuf 定向测试。
- 注意：httpx 只探 HTTP(S) 存活，纯 TCP 服务（SSH/SMB/数据库）用 nmap 补充。"""
    extra_schemas = SCHEMAS

    async def exec_httpx_probe(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("httpx"):
            return "httpx 未安装（apt install httpx-toolkit）。"
        try:
            targets = _split_targets(str(args.get("targets") or ""))
        except ValueError as e:
            return str(e)
        if not targets:
            return "targets 不能为空（逗号分隔的域名/IP 列表）"
        for t in targets:
            try:
                sanitize_target(t, label="目标")
            except ValueError as e:
                return str(e)
        cmd = _build_cmd(targets)
        raw = await self._run(ex, cmd, timeout=120)
        rows = _parse(raw)
        if not rows:
            head = ["未探测到存活 HTTP 目标（全部超时/拒绝连接，或 httpx 输出格式变化）"]
            head.append("建议：改用 nmap 对目标列表做端口扫描确认服务存活。")
            return self._summary(raw, head, tail=20)
        head = [f"🌐 HTTP 存活目标 ({len(rows)}/{len(targets)}):"]
        for r in rows:
            parts = [r["url"], f"[{r['status']}]"]
            if r["title"]:
                parts.append(f"「{r['title'][:40]}」")
            if r["tech"]:
                parts.append(f"({r['tech'][:60]})")
            head.append("  " + " ".join(parts))
        head.append("下一步：对 200/403 目标做服务识别与漏洞检测（nuclei/sqlmap/ffuf）。")
        return self._summary(raw, head, tail=0)
