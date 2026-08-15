"""drupwn：Drupal CMS 专项扫描（版本/模块枚举，CMS 三巨头：WP/Joomla/Drupal）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "drupwn",
            "description": (
                "用 drupwn 对 Drupal 站点做专项扫描（版本识别/模块主题枚举）。"
                "whatweb 指纹确认是 Drupal 后用它深入，识别版本后查已知漏洞"
                "（Drupalgeddon 系列 CVE-2014-3704 / CVE-2018-7600 等）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://example.com",
                    },
                    "mode": {
                        "type": "string",
                        "description": "枚举模式：enumerate（默认）/ version_only",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_URL_RE = re.compile(
    r"^https?://[^\s/;|`$(){}\[\]]+(?:/[^\s;|`$(){}\[\]]*)?$", re.IGNORECASE
)
_VERSION_RE = re.compile(r"(?:Drupal|drupal)\s*(?:version)?\s*[:\-]?\s*v?(\d+(?:\.\d+){1,3})")
_MODULE_RE = re.compile(r"(?:Module|module|模块)\s*[:\-]\s*([\w-]+)", re.IGNORECASE)
_KNOWN_CVE = {
    "CVE-2018-7600": "Drupalgeddon2（RCE，8.x/7.x 高危）",
    "CVE-2014-3704": "Drupalgeddon1（SQLi RCE，7.x）",
    "CVE-2019-6340": "REST 反序列化 RCE（8.5.x/8.6.x）",
}


def _build_cmd(url: str, mode: str) -> str:
    if mode == "version_only":
        return f"drupwn --mode version --url {url}", 120
    return f"drupwn --mode enumerate --url {url}", 180


def _summarize(raw: str) -> str:
    vm = _VERSION_RE.search(raw)
    version = vm.group(1) if vm else ""
    modules = list(dict.fromkeys(_MODULE_RE.findall(raw)))[:15]
    head: list[str] = []
    if version:
        head.append(f"🎯 Drupal 版本: {version}")
        for cve, desc in _KNOWN_CVE.items():
            if version.startswith(("7", "8")):
                head.append(f"  ⚠ 可能受影响: {cve} {desc}")
        head.append("验证：用 vuln_proof 构造 PoC 复现（注意授权），或 searchsploit drupal 查历史漏洞。")
    else:
        head.append("未识别出 Drupal 版本（站点响应异常/非 Drupal/被 WAF 拦截）")
    if modules:
        head.append(f"枚举到模块/主题 {len(modules)} 个: " + " ".join(modules))
    return ToolProfile._summary(raw, head, tail=25)


class DrupwnProfile(ToolProfile):
    name = "drupwn"
    aliases = ["drupal", "drupal 扫描", "drupwn", "cms 扫描"]
    summary = "Drupal CMS 专项扫描"
    lore = """### drupwn 深度使用要点
- 定位：CMS 三巨头（WordPress/Joomla/Drupal）最后一环。whatweb 指纹确认
  Drupal 后用 drupwn 枚举版本与模块，版本决定漏洞面。
- 高危版本速查：7.x 全部受 Drupalgeddon1（CVE-2014-3704）影响；
  8.x < 8.6.10 受 Drupalgeddon2（CVE-2018-7600，无需认证 RCE）；
  8.5.x/8.6.x 受 REST 反序列化（CVE-2019-6340）影响。9.x/10.x 修复了
  老 Drupalgeddon，重点看模块漏洞与配置问题。
- 模块枚举价值：第三方模块（如 ubercart/webform）常带独立漏洞，
  版本出来后 searchsploit / nuclei 按模块名搜。
- 联动：whatweb 确认 Drupal → drupwn 枚举 → searchsploit 查版本 CVE →
  vuln_proof 验证 → 报告。绕过 WAF 时可用 --random-agent 换 UA。
- 注意：drupwn 枚举会发大量请求，外网目标控制并发与频率。"""
    extra_schemas = SCHEMAS

    async def exec_drupwn(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("drupwn"):
            return "drupwn 未安装（apt install drupwn）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            raise ValueError(f"url 必须是完整 URL（含 http/https）: {url!r}")
        mode = str(args.get("mode") or "enumerate").strip().lower()
        if mode not in ("enumerate", "version_only"):
            raise ValueError(f"mode 非法: {mode!r}（enumerate / version_only）")
        raw = await self._run(ex, *_build_cmd(url, mode))
        return _summarize(raw)
