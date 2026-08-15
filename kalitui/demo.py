"""Demo 模式：无 API key 时用「脚本大脑」驱动真实工具执行，用于预览 UI 与测试。

它不调用任何 LLM，但完整走 Agent 的 emit 事件流 + Executor 真实执行，
所以安全确认弹窗、命令输出、中断等机制都能被真实触发。
"""

from __future__ import annotations

import asyncio
from typing import Any

from .evidence import AgentMemory
from .tools import Executor, NeedsApproval, ToolError


class DemoAgent:
    """与 Agent 接口兼容（chat/reset），但大脑是本地脚本。

    也挂 AgentMemory：demo 模式同样产生证据，/report /targets /export
    等证据驱动的命令在 demo 下同样可用。
    """

    def __init__(self, executor: Executor, emit=None):
        self.executor = executor
        self.emit = emit or (lambda _e: None)
        self.turn = 0
        self.messages: list[dict] = []
        self.memory = AgentMemory()

    async def chat(self, user_message: str) -> str:
        self.turn += 1
        msg = user_message.strip()
        self.messages.append({"role": "user", "content": msg})

        async def tool(name: str, args: dict[str, Any]) -> str:
            await self.emit({"type": "tool_start", "name": name, "arguments": args})
            try:
                out = await self.executor.execute(name, args)
                ok = True
            except NeedsApproval as e:
                out, ok = f"（{e.reason}，命令未执行）", True
            except ToolError as e:
                out, ok = str(e), False
            await self.emit({"type": "tool_result", "name": name, "ok": ok, "output": out})
            if ok:
                self.memory.record(name, args, out)
            else:
                self.memory.record_failure(name, args, out)
            return out

        await self.emit({"type": "thinking"})
        await asyncio.sleep(0.3)  # 模拟思考

        sysinfo = await tool("get_system_info", {})

        low = msg.lower()
        if "masscan" in low or "网段" in low:
            out = await tool("masscan", {"target": "127.0.0.1", "ports": "1-1000"})
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）网段高速扫描：\n{out}"

        if "nmap" in low or "扫描" in low or "scan" in low:
            target = "127.0.0.1"
            if " " in msg:
                for tok in msg.split():
                    if tok.startswith(("10.", "192.168.", "172.", "127.")):
                        target = tok
                        break
            await self.emit({"type": "thinking"})
            out = await tool(
                "run_command", {"command": f"nmap -T4 -F {target}", "timeout": 90}
            )
            await self.emit({"type": "thinking"})
            return (
                f"（Demo 模式：脚本大脑，非真实 LLM）\n"
                f"已按你的要求对 {target} 做了快速端口扫描（-F，前 100 个常用端口）。\n"
                f"关键发现：\n{out[-1200:]}\n\n"
                f"提示：真实模式下我会结合 nmap 结果自动规划下一步（服务识别、漏洞匹配…）。"
            )
        if "whoami" in low or "身份" in low:
            out = await tool("run_command", {"command": "whoami && id", "timeout": 15})
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）\n当前身份：\n{out}\n\n配置好 API key 后，我会基于此决定提权/横向等后续动作。"
        if "hydra" in low or "爆破" in low:
            # 触发安全确认弹窗，演示危险命令审批
            out = await tool(
                "run_command",
                {"command": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1", "timeout": 30},
            )
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）爆破命令结果：\n{out}\n\n看到了吗？危险命令会先弹窗问你是否允许～"
        if "msf" in low or "exploit" in low or "metasploit" in low:
            out = await tool("run_command", {"command": "msfconsole -q -x 'version'", "timeout": 30})
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）Metasploit 就绪：\n{out}"
        if "joomla" in low:
            out = await tool("joomla_scan", {"url": "http://127.0.0.1/"})
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）Joomla 专项扫描：\n{out}"
        if "bloodhound" in low or "域关系" in low or "ad 采集" in low:
            out = await tool(
                "bloodhound_py",
                {"domain": "demo.local", "username": "demo",
                 "password": "DemoPass!", "dc": "127.0.0.1"},
            )
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）AD 域关系采集：\n{out}"
        if "kerbrute" in low or "用户枚举" in low:
            out = await tool("kerbrute", {"domain": "demo.local", "userlist": "admin,guest"})
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）AD 用户枚举：\n{out}"
        if "whatweb" in low or "指纹" in low:
            out = await tool("whatweb", {"url": "http://127.0.0.1/"})
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）Web 指纹识别：\n{out}"
        if "drupwn" in low or "drupal" in low:
            out = await tool("drupwn", {"url": "http://127.0.0.1/"})
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）Drupal 专项扫描：\n{out}"
        if "subfinder" in low or "子域名" in low:
            out = await tool("subfinder", {"domain": "demo.local"})
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）子域名枚举：\n{out}"
        if "dnsx" in low or "dns 解析" in low or "解析验证" in low:
            out = await tool("dnsx", {"domains": "demo.local,www.demo.local"})
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）DNS 批量解析：\n{out}"
        if "katana" in low or "js 端点" in low or "爬虫" in low:
            out = await tool("katana", {"url": "http://127.0.0.1/"})
            await self.emit({"type": "thinking"})
            return f"（Demo 模式）JS 端点提取：\n{out}"

        # 默认：系统概览
        await self.emit({"type": "thinking"})
        return (
            f"（Demo 模式：脚本大脑，未配置 API key）\n"
            f"我看了下这台 Kali：\n{sysinfo}\n\n"
            f"试试让我「扫描 127.0.0.1」或「爆破测试」，可以体验工具调用和安全确认弹窗。\n"
            f"配置方法：export KALITUI_API_KEY=sk-xxx 后重启，就是真正的 AI 了。"
        )

    def export_findings_csv(self, path: str | None = None) -> str:
        """与 Agent 相同的 findings CSV 导出（demo 下 /export 同样可用）。"""
        import csv
        import os

        from .evidence import severity_of, sort_findings

        if path is None:
            out_dir = os.path.join(os.getcwd(), "kalitui-reports")
            os.makedirs(out_dir, exist_ok=True)
            path = os.path.join(out_dir, "findings.csv")
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["severity", "type", "value", "evidence"])
            for finding in sort_findings(self.memory.findings):
                writer.writerow([
                    severity_of(finding),
                    finding["type"],
                    finding["value"],
                    finding.get("evidence", ""),
                ])
        return path

    def write_report(self, final_answer: str = "", path: str | None = None) -> str:
        """基于证据确定性生成 Markdown 复盘报告（与真实 Agent 同款模板）。"""
        import os
        from datetime import datetime

        from .evidence import severity_of, sort_findings

        if path is None:
            out_dir = os.path.join(os.getcwd(), "kalitui-reports")
            os.makedirs(out_dir, exist_ok=True)
            path = os.path.join(out_dir, f"report-{datetime.now():%Y%m%d-%H%M%S}.md")

        findings = sort_findings(self.memory.findings)
        lines = [
            "# KaliTUI 侦察复盘报告",
            "",
            f"- 生成时间: {datetime.now():%Y-%m-%d %H:%M:%S}",
            f"- 会话消息: {len(self.messages)} 条",
            f"- 证据: {len(self.memory.evidence)} 条 / 发现: {len(findings)} 条",
            "",
            "## 最终结论",
            "",
        ]
        if final_answer.strip():
            lines.append(final_answer.strip())
        else:
            lines.append("（会话未产出明确结论）")
        lines += ["", "## 发现清单", ""]
        if findings:
            for f in findings:
                lines.append(
                    f"- [{severity_of(f)}] {f['type']}: {f['value']}（证据 {f.get('evidence', '')}）"
                )
        else:
            lines.append("（暂无明确发现）")
        lines += ["", "## 侦察时间线", ""]
        steps = [
            f"- `{e.tool}`: {e.summary}（证据 {e.id}）"
            for e in self.memory.evidence[:10]
        ]
        lines += steps if steps else ["（无工具执行记录）"]
        gaps = self.memory.attack_surface_gaps()
        if gaps:
            lines += ["", "## 后续建议（未探索的高信号方向）", ""]
            lines += [f"- {g}" for g in gaps[:6]]
        targets = self.memory.targets_summary()
        if targets:
            lines += ["", "## 目标统计", ""]
            lines += [f"- {t}" for t in targets[:8]]
        lines.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def save_state(self) -> bool:
        """demo 不持久化（避免污染真实会话的 resume.json）。"""
        return False

    def restore_state(self, data: dict) -> None:
        """demo 可恢复证据记忆（/resume 后 /report 仍可用）。"""
        from .evidence import AgentMemory

        if isinstance(data, dict):
            restored = AgentMemory.from_dict(data.get("memory") or {})
            if restored is not None:
                self.memory = restored
        msgs = data.get("messages") if isinstance(data, dict) else None
        if isinstance(msgs, list):
            self.messages = [m for m in msgs if isinstance(m, dict)]

    def reset(self) -> None:
        self.turn = 0
        self.messages.clear()
        self.memory.reset()

    async def aclose(self) -> None:
        pass
