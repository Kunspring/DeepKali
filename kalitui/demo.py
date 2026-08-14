"""Demo 模式：无 API key 时用「脚本大脑」驱动真实工具执行，用于预览 UI 与测试。

它不调用任何 LLM，但完整走 Agent 的 emit 事件流 + Executor 真实执行，
所以安全确认弹窗、命令输出、中断等机制都能被真实触发。
"""

from __future__ import annotations

import asyncio
from typing import Any

from .tools import Executor, NeedsApproval, ToolError


class DemoAgent:
    """与 Agent 接口兼容（chat/reset），但大脑是本地脚本。"""

    def __init__(self, executor: Executor, emit=None):
        self.executor = executor
        self.emit = emit or (lambda _e: None)
        self.turn = 0
        self.messages: list[dict] = []

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
            return out

        await self.emit({"type": "thinking"})
        await asyncio.sleep(0.3)  # 模拟思考

        sysinfo = await tool("get_system_info", {})

        low = msg.lower()
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

        # 默认：系统概览
        await self.emit({"type": "thinking"})
        return (
            f"（Demo 模式：脚本大脑，未配置 API key）\n"
            f"我看了下这台 Kali：\n{sysinfo}\n\n"
            f"试试让我「扫描 127.0.0.1」或「爆破测试」，可以体验工具调用和安全确认弹窗。\n"
            f"配置方法：export KALITUI_API_KEY=sk-xxx 后重启，就是真正的 AI 了。"
        )

    def reset(self) -> None:
        self.turn = 0
        self.messages.clear()

    async def aclose(self) -> None:
        pass
