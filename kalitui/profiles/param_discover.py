"""隐藏参数探测：批量注入常见调试/开关参数，比较响应差异找生效项。

白帽定位：隐藏参数（debug/test/admin/callback 等）开启后常泄露额外
信息或改变行为——JSONP callback 反射可窃取数据，debug=1 泄露堆栈，
是 API/Web 测试的进阶手法。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_PARAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")

_DEFAULT_PARAMS: list[str] = [
    "debug", "test", "admin", "verbose", "config", "callback", "jsonp",
    "mode", "env", "action", "cmd", "file", "download", "redirect", "url",
    "host", "ip", "user", "id", "type", "format", "output", "raw", "source",
    "edit", "dev", "trace", "internal",
]
_MAX_PARAMS = 40
_VALUE = "1"

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "param_discover",
            "description": (
                "隐藏参数探测：批量注入 28 个常见调试/开关参数（debug/test/admin/"
                "callback/jsonp 等），响应与基线差异 = 参数生效（debug 泄露/JSONP 窃取面）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://t.com/api/search?q=1",
                    },
                    "params": {
                        "type": "array",
                        "description": "自定义参数名列表（可选，追加到内置 28 个）",
                        "items": {"type": "string"},
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str, param: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"curl -s -m 12 '{url}{sep}{param}={_VALUE}'"


def _summarize(baseline: str, results: dict[str, str]) -> str:
    base_len = len(baseline)
    head: list[str] = []
    hits: list[tuple[str, str, int]] = []
    for p, raw in results.items():
        if raw == baseline or not raw.strip():
            continue
        diff = len(raw) - base_len
        if abs(diff) > max(10, base_len * 0.05) or p in raw.lower():
            hits.append((p, raw, diff))
    if hits:
        head.append(f"🚨 参数生效 ({len(hits)}/{len(results)}):")
        for p, raw, diff in hits[:12]:
            head.append(f"  {p}={_VALUE} → 响应 {'+' if diff >= 0 else ''}{diff} 字节"
                        f"{'（含参数回显）' if p in raw.lower() else ''}")
        head.append("下一步：逐个看响应内容（debug=1 泄露堆栈/配置、callback 反射=JSONP"
                    "数据窃取面、admin=1 可能切换角色）；确认影响后修复：参数白名单+关闭调试。")
    else:
        head.append("✅ 未发现生效参数——28 个常见参数响应均与基线一致。")
        head.append("提示：试值变体（debug=true/1/yes、callback=jsonpCallback）、"
                    "POST 参数（curl -d）、自定义业务参数名（业务文档/JS 里找）。")
    return ToolProfile._summary("", head, tail=25)


class ParamDiscoverProfile(ToolProfile):
    name = "param_discover"
    aliases = ["参数发现", "隐藏参数", "参数探测", "debug 参数", "jsonp 探测", "参数枚举"]
    summary = "隐藏参数探测（调试开关/回调）"
    lore = """### 隐藏参数探测使用要点
- 定位：后端未公开参数（debug/test/admin/callback）开启后改变行为或泄露信息。
- 28 个内置参数：debug/test/admin/verbose/config/callback/jsonp/mode/env/
  action/cmd/file/download/redirect/url/host/ip/user/id/type/format 等。
- 判定：响应与基线差异 >5% 或参数名回显 = 生效。
- 高价值场景：callback/jsonp 反射 = JSONP 端点（跨域读取数据）；debug=1 =
  堆栈/配置泄露（配合 error_leak 判定内容）；admin=1/role 类 = 越权开关。
- 结合流程：param_discover 命中 debug → 看泄露内容 → 命中 JSONP → 评估数据
  敏感性（cookie 携带数据）；修复：参数白名单、关闭调试开关、JSONP 加
  referer 校验。
- 注意：参数名来自业务文档/JS（js_extract 辅助）；值变体多试；
  POST 场景用 curl -d 手工扩展。"""
    extra_schemas = SCHEMAS

    async def exec_param_discover(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法: {url!r}"
        params = list(_DEFAULT_PARAMS)
        extra = args.get("params") or []
        if not isinstance(extra, list):
            raise ValueError("params 必须是列表")
        for p in extra:
            p = str(p).strip()
            if not _PARAM_RE.match(p):
                raise ValueError(f"参数名非法: {p!r}")
            if p not in params:
                params.append(p)
        if len(params) > _MAX_PARAMS:
            raise ValueError(f"参数总数不能超过 {_MAX_PARAMS}")
        baseline = await self._run(ex, _build_cmd(url, "x"), timeout=15)
        results: dict[str, str] = {}
        for p in params:
            results[p] = await self._run(ex, _build_cmd(url, p), timeout=15)
        return _summarize(baseline, results)
