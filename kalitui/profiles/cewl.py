"""cewl 深度定制：网站词表生成（配合 hydra 口令爆破）。"""

from __future__ import annotations

import re
import shlex
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "cewl_words",
            "description": (
                "用 cewl 从目标网站爬取关键词生成自定义密码词表。"
                "针对性爆破利器：站内词汇（公司名/产品名/人名）常被用作密码。"
                "生成的词表直接用于 hydra_brute 或 crack_hash 的字典。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL，如 http://target.com"},
                    "depth": {
                        "type": "integer",
                        "description": "爬取深度（默认 2）",
                    },
                    "min_length": {
                        "type": "integer",
                        "description": "词最小长度（默认 4，过滤噪音）",
                    },
                    "output": {
                        "type": "string",
                        "description": "词表输出路径（默认 /tmp/cewl-words.txt）",
                    },
                    "email": {
                        "type": "boolean",
                        "description": "同时提取邮箱（-e），默认 false",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_URL_RE = re.compile(r"^https?://[^\s;|&`$\\]{1,500}$", re.IGNORECASE)
_OUT_RE = re.compile(r"^/[\w./-]{1,200}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    url = str(args["url"]).strip()
    if not _URL_RE.match(url):
        raise ValueError(f"url 格式非法: {url!r}")
    depth = sanitize_int(args.get("depth"), 2, 1, 10, "depth")
    minlen = sanitize_int(args.get("min_length"), 4, 1, 20, "min_length")
    output = str(args.get("output") or "/tmp/cewl-words.txt").strip()
    if not _OUT_RE.match(output) or not output.startswith(("/tmp/", "/root/")):
        raise ValueError(f"output 必须是 /tmp 或 /root 下路径: {output!r}")

    parts = ["cewl", url, "-d", str(depth), "-m", str(minlen), "-w", output]
    if args.get("email"):
        parts.append("-e")
    return " ".join(parts), 180


class CewlProfile(ToolProfile):
    name = "cewl"
    aliases = ["cewl", "词表生成", "密码词表", "网站关键词"]
    summary = "网站词表生成"
    lore = """### cewl 深度使用要点
- 定位：生成"贴合目标"的密码词表——比通用字典（rockyou）命中率高得多。
- 常见密码构成：公司名+年份、产品名+数字、人名+生日——cewl 都能从页面里抓到。
- 配合 hydra_brute（指定生成的词表文件）做定向爆破；配合 hashcat -r 规则变形扩展词表。
- 爬取深度控制：-d 2 默认；大站加大 depth 但会慢；-m 4 过滤短词噪音。
- -e 顺带提取邮箱（页面联系邮箱），可用于用户名枚举确认。"""
    extra_schemas = SCHEMAS

    async def exec_cewl_words(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("cewl"):
            return "cewl 未安装（apt install cewl）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        output = str(args.get("output") or "/tmp/cewl-words.txt")
        try:
            n = sum(1 for _ in open(output, errors="replace"))
        except OSError:
            n = 0
        if n:
            head = [f"✅ 词表已生成: {output}（{n} 词）"]
            head.append("下一步：hydra_brute 用该词表做口令测试；或 hashcat -r 规则扩展。")
        else:
            head = ["词表为空（目标不可达/无内容可提取）"]
        return self._summary(raw, head, tail=30)
