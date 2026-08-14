"""nikto 深度定制：Web 服务器漏洞扫描 + 发现摘要。"""

from __future__ import annotations

from typing import Any

from .base import ToolProfile, check_installed, sanitize_url

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "nikto_scan",
            "description": (
                "对 Web 目标执行 nikto 漏洞扫描（服务端配置/已知漏洞探测）。"
                "被动分析为主，比主动 exploit 安全，但仍会发送大量请求——外部目标需授权。"
                "适合对 nmap 发现的 http/https 端口做进一步探测。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "URL，如 http://192.168.1.10 或 https://example.com:8443",
                    },
                    "tuning": {
                        "type": "string",
                        "description": "tuning 参数串（可选），如 'x' 排除危险测试；留空用默认",
                    },
                },
                "required": ["target"],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    target = sanitize_url(str(args["target"]))
    tuning = str(args.get("tuning") or "").strip()
    if tuning and not all(c in "123456789abcdex" for c in tuning):
        raise ValueError(f"tuning 仅允许数字/abcdex 组合: {tuning!r}")
    cmd = f"nikto -h {target}"
    if tuning:
        cmd += f" -Tuning {tuning}"
    return cmd, 300


class NiktoProfile(ToolProfile):
    name = "nikto"
    aliases = ["web 扫描", "web漏洞", "nikto 扫描", "网站漏洞"]
    summary = "Web 服务器漏洞扫描"
    lore = """### nikto 深度使用要点
- 定位：对 nmap 发现的 http(80)/https(443/8443) 端口使用。
- 输出关注 `+` 开头的发现行：服务器版本、潜在漏洞、敏感文件（如 /admin、备份文件）。
- nikto 是黑盒指纹/已知漏洞检查，误报较多；发现后应人工或进一步用 curl/脚本验证。
- 与 gobuster（目录枚举）配合：nikto 看已知漏洞，gobuster 找隐藏目录。
- 大站点扫描慢，默认超时 5 分钟；结果按严重性向用户汇报。"""
    extra_schemas = SCHEMAS

    async def exec_nikto_scan(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("nikto"):
            return "nikto 未安装（apt install nikto）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        finds = [l.strip() for l in raw.splitlines() if l.startswith("+")]
        head = finds[:40] if finds else ["未发现明显问题（或扫描被中断）"]
        if len(finds) > 40:
            head.append(f"… 共 {len(finds)} 条发现")
        head.append("提示：发现项需人工验证，避免误报。")
        return self._summary(raw, head, tail=50)
