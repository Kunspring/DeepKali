"""漏洞报告生成：把验证过的发现整理成结构化 markdown 报告。

白帽定位：挖洞链路的收尾环节——发现验证完成后（vuln_proof），
把目标、风险评级、复现步骤、修复建议整理成可提交 SRC/渗透测试报告的 markdown。
纯本地生成（无外部依赖），不触碰网络。
"""

from __future__ import annotations

import time
from typing import Any

from .base import ToolProfile

_SEV = {"info": "低", "low": "低", "medium": "中", "high": "高", "critical": "严重"}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_MAX_FINDINGS = 20

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "report_gen",
            "description": (
                "漏洞报告生成：把已验证的发现整理成结构化 markdown 报告"
                "（含目标/风险评级/复现步骤/修复建议），写入本地文件。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "报告标题，如 'XX 系统渗透测试报告'",
                    },
                    "target": {
                        "type": "string",
                        "description": "测试目标（域名/IP/应用名）",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                        "description": "总体风险评级",
                    },
                    "findings": {
                        "type": "array",
                        "description": "漏洞发现列表（最多 20 条）",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string", "description": "漏洞名称"},
                                "severity": {
                                    "type": "string",
                                    "enum": ["info", "low", "medium", "high", "critical"],
                                },
                                "description": {"type": "string", "description": "漏洞描述与影响"},
                                "poc": {"type": "string", "description": "复现步骤/PoC 摘要"},
                                "fix": {"type": "string", "description": "修复建议"},
                            },
                            "required": ["title", "severity"],
                        },
                    },
                    "output": {
                        "type": "string",
                        "description": "输出路径（默认 /tmp/DeepKali-report-<时间戳>.md）",
                    },
                },
                "required": ["title", "target"],
            },
        },
    },
]


def _check_output(path: str) -> str:
    p = path.strip()
    if not p.startswith(("/tmp/", "/root/", "./")):
        raise ValueError("output 必须位于 /tmp/、/root/ 或当前目录（./）")
    if len(p) > 300 or any(c in p for c in (";", "|", "&", "`", "$", "\\", "\n")):
        raise ValueError("output 路径含非法字符或过长")
    return p


def _build_report(args: dict[str, Any]) -> str:
    title = str(args.get("title") or "").strip()
    target = str(args.get("target") or "").strip()
    sev = str(args.get("severity") or "medium").strip().lower()
    findings = args.get("findings") or []
    if not 1 <= len(title) <= 120:
        raise ValueError("title 长度需在 1-120 字符")
    if not 1 <= len(target) <= 200:
        raise ValueError("target 长度需在 1-200 字符")
    if sev not in _SEV:
        raise ValueError(f"severity 仅支持: {', '.join(_SEV)}")
    if not isinstance(findings, list):
        raise ValueError("findings 必须是列表")
    if len(findings) > _MAX_FINDINGS:
        raise ValueError(f"findings 最多 {_MAX_FINDINGS} 条")
    cleaned: list[dict[str, str]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        ft = str(f.get("title") or "").strip()
        fs = str(f.get("severity") or "low").strip().lower()
        if not ft or fs not in _SEV:
            continue
        cleaned.append({
            "title": ft[:200],
            "severity": fs,
            "description": str(f.get("description") or "").strip()[:500],
            "poc": str(f.get("poc") or "").strip()[:500],
            "fix": str(f.get("fix") or "").strip()[:500],
        })
    cleaned.sort(key=lambda x: _SEV_ORDER.get(x["severity"], 9))
    lines = [
        f"# {title}",
        "",
        f"- 测试目标: `{target}`",
        f"- 报告时间: {time.strftime('%Y-%m-%d %H:%M')}",
        f"- 总体风险: **{_SEV.get(sev, sev)}**",
        f"- 发现数量: {len(cleaned)}",
        "",
        "> 免责声明：本报告仅限授权测试范围使用，未经授权扫描/利用属违法行为。",
        "",
        "## 漏洞发现",
    ]
    for i, f in enumerate(cleaned, 1):
        lines += [
            f"### {i}. [{_SEV[f['severity']]}] {f['title']}",
            "",
            f"- **描述**: {f['description'] or '（待补充）'}",
            f"- **复现步骤**: {f['poc'] or '（待补充）'}",
            f"- **修复建议**: {f['fix'] or '（待补充）'}",
            "",
        ]
    if not cleaned:
        lines += ["未记录漏洞发现（可补充 findings 列表）。", ""]
    lines += ["---", "由 DeepKali report_gen 生成。"]
    return "\n".join(lines)


class ReportGenProfile(ToolProfile):
    name = "report_gen"
    aliases = ["报告生成", "漏洞报告", "写报告", "渗透报告", "报告模板", "出报告", "报告"]
    summary = "漏洞报告生成"
    lore = """### 漏洞报告生成使用要点
- 定位：挖洞收尾——把验证过的发现（vuln_proof 确认）整理成结构化 markdown 报告。
- 用法：report_gen(title='XX 系统测试报告', target='10.0.0.9', severity='high',
  findings=[{title:'SQL 注入', severity:'high', description:'...', poc:'...', fix:'...'}])。
- 严重级别自动排序：critical > high > medium > low > info；输出路径默认 /tmp/。
- 报告结构：标题/目标/时间/总体风险/免责声明/逐条发现（描述、复现、修复）。
- 建议：复现步骤写清楚可操作性（curl 命令、参数、回显特征）；修复建议给出具体版本/配置。
- 出报告前先确认：每条发现都经过实际验证（误报宁可标注待确认，不要直接写死）。"""
    extra_schemas = SCHEMAS

    async def exec_report_gen(self, ex: Any, args: dict[str, Any]) -> str:
        outfile = _check_output(str(args.get("output") or "/tmp/DeepKali-report.md"))
        report = _build_report(args)
        with open(outfile, "w", encoding="utf-8") as f:
            f.write(report)
        lines = report.splitlines()
        preview = lines[:14]
        return (
            f"📄 报告已生成: {outfile}（{len(report)} 字符，{len(lines)} 行）\n"
            + "\n".join(preview)
            + "\n…（完整内容见文件）"
        )
