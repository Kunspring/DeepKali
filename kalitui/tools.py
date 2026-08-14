"""工具定义与执行器：AI 通过工具驾驭 Kali。

执行器均为 async；危险命令经 safety.classify 分级，
确认级抛 NeedsApproval，由上层（TUI/测试）决定放行与否。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from .safety import classify

# 提交给 LLM 的工具 JSON Schema（OpenAI 格式）
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": (
                "在 Kali 上执行一条 shell 命令（bash -c）。适合 nmap、msfconsole -q -x、"
                "whoami、ip a、cat 等几乎所有终端操作。输出会回传给你。"
                "注意：危险命令（删除、格式化、爆破工具等）会被拦截并询问用户。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "要执行的完整 shell 命令"},
                    "timeout": {"type": "integer", "description": "超时秒数，默认 60", "minimum": 1, "maximum": 3600},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "读取一个文本文件的内容（带行号）。适合查看配置、日志、源码。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件路径"},
                    "offset": {"type": "integer", "description": "起始行（1 起），默认 1"},
                    "limit": {"type": "integer", "description": "最多读取行数，默认 200"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "写入/创建文本文件（UTF-8）。已有文件会被覆盖，写入前会询问用户。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件路径"},
                    "content": {"type": "string", "description": "完整文件内容"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ask_user",
            "description": "向用户提出一个问题并等待回答。当你需要目标信息、选择或授权时使用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {"type": "string", "description": "要问的问题（简洁）"},
                },
                "required": ["question"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_info",
            "description": "获取 Kali 系统概况：发行版、内核、当前用户、IP、已装的安全工具等。",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]


class NeedsApproval(Exception):
    """命令需要用户确认（confirm 级）或用户强制（blocked 级）。"""

    def __init__(self, command: str, level: str, reason: str):
        super().__init__(f"[{level}] {reason}: {command}")
        self.command = command
        self.level = level
        self.reason = reason


class ToolError(Exception):
    pass


@dataclass
class ApprovalRequest:
    command: str
    level: str
    reason: str
    future: asyncio.Future = field(default_factory=asyncio.Future)

    def resolve(self, allow: bool, edited: str | None = None, force: bool = False) -> None:
        if not self.future.done():
            self.future.set_result(
                {"allow": allow, "edited": edited or self.command, "force": force}
            )


# 审批回调：由 TUI 注册，返回一个 ApprovalRequest 即可（调用方 await future）
ApprovalCallback = Callable[[str, str, str], ApprovalRequest]


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)


class Executor:
    """工具执行器：持有审批回调 + 系统信息缓存。"""

    def __init__(
        self,
        request_approval: ApprovalCallback | None = None,
        danger_policy: str = "ask",
        max_output_lines: int = 2000,
    ):
        self.request_approval = request_approval
        self.danger_policy = danger_policy
        self.max_output_lines = max_output_lines
        self._sysinfo_cache: tuple[float, str] | None = None
        self._pending: set[asyncio.Task] = set()
        # 深度定制工具扩展：name -> async fn(executor, args) -> str
        self.extensions: dict[str, Callable[["Executor", dict[str, Any]], Awaitable[str]]] = {}

    # ---------- 执行入口 ----------
    async def execute(self, name: str, arguments: dict[str, Any]) -> str:
        fn = getattr(self, f"_exec_{name}", None)
        is_builtin = fn is not None
        if fn is None:
            fn = self.extensions.get(name)
        if fn is None:
            raise ToolError(f"未知工具: {name}")
        try:
            if is_builtin:
                result = fn(arguments)
            else:
                result = fn(self, arguments)
            if isinstance(result, Awaitable):
                result = await result
            return result
        except NeedsApproval:
            raise
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — 工具错误要回传给 LLM 消化
            raise ToolError(f"{name} 执行失败: {e}") from e

    # ---------- 审批 ----------
    async def _approve(self, command: str, level: str, reason: str) -> dict:
        policy = self.danger_policy
        if policy == "always_allow":
            return {"allow": True, "edited": command, "force": level == "blocked"}
        if policy == "always_block":
            return {"allow": False, "edited": command, "force": False}
        if self.request_approval is None:
            # 无 UI（headless）：默认拒绝危险命令
            return {"allow": False, "edited": command, "force": False}
        req = self.request_approval(command, level, reason)
        return await req.future

    # ---------- 工具实现 ----------
    async def _exec_run_command(self, args: dict[str, Any]) -> str:
        command = str(args.get("command", "")).strip()
        if not command:
            raise ToolError("command 为空")
        timeout = int(args.get("timeout") or 60)
        timeout = max(1, min(timeout, 3600))

        verdict = classify(command)
        if verdict.level in ("confirm", "blocked"):
            decision = await self._approve(command, verdict.level, verdict.reason)
            if not decision["allow"]:
                return (
                    f"命令被用户拒绝：{command}\n"
                    f"原因：{verdict.reason}\n"
                    "建议：换用更安全的做法，或先向用户说明目的。"
                )
            if decision["edited"] != command:
                command = decision["edited"]
                verdict = classify(command)
                if verdict.level == "blocked" and not decision["force"]:
                    return f"编辑后的命令仍被判定为危险并已拦截：{command}\n原因：{verdict.reason}"
            if verdict.level == "blocked" and not decision["force"]:
                return f"命令被安全策略拦截：{command}\n原因：{verdict.reason}"

        env = dict(os.environ)
        # 保证关键环境变量存在（某些工具如 msfvenom/ruby 依赖 HOME）
        if not env.get("HOME"):
            env["HOME"] = str(Path.home())
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL,
            start_new_session=True,  # 独立进程组，便于整体中断
            env=env,
        )
        task = asyncio.create_task(proc.communicate())
        self._pending.add(task)
        out = b""
        try:
            out, _ = await asyncio.wait_for(task, timeout=timeout)
        except asyncio.TimeoutError:
            self._kill_group(proc)
            return (
                f"命令超时（>{timeout}s）已被终止：{command}\n"
                f"已捕获输出：\n{self._fmt_output(out or b'')}"
            )
        except asyncio.CancelledError:
            self._kill_group(proc)
            raise
        finally:
            self._pending.discard(task)

        text = self._fmt_output(out or b"")
        code = proc.returncode
        head = f"命令: {command}\n退出码: {code}\n" if code != 0 else f"命令: {command}\n"
        return head + text

    @staticmethod
    def _kill_group(proc: asyncio.subprocess.Process) -> None:
        try:
            if proc.returncode is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    def _fmt_output(self, data: bytes) -> str:
        text = _strip_ansi(data.decode("utf-8", errors="replace"))
        lines = text.splitlines()
        if len(lines) > self.max_output_lines:
            kept = lines[: self.max_output_lines]
            text = "\n".join(kept) + f"\n…（输出过长，已截断，共 {len(lines)} 行）"
        return text.strip()

    async def _exec_read_file(self, args: dict[str, Any]) -> str:
        path = Path(str(args["path"])).expanduser()
        offset = max(1, int(args.get("offset") or 1))
        limit = max(1, min(int(args.get("limit") or 200), 2000))
        if not path.exists():
            return f"文件不存在: {path}"
        if path.is_dir():
            entries = sorted(os.listdir(path))
            return f"{path}/ 目录，共 {len(entries)} 项:\n" + "\n".join(entries[:500])
        raw = path.read_bytes()
        text = _strip_ansi(raw.decode("utf-8", errors="replace"))
        lines = text.splitlines()
        total = len(lines)
        chunk = lines[offset - 1 : offset - 1 + limit]
        out = "\n".join(f"{i + offset:>6} | {ln}" for i, ln in enumerate(chunk))
        return f"{path}（共 {total} 行，显示 {offset}-{offset + len(chunk) - 1}）:\n{out}"

    async def _exec_write_file(self, args: dict[str, Any]) -> str:
        path = Path(str(args["path"])).expanduser()
        content = str(args.get("content") or "")
        existed = path.exists()
        if existed:
            decision = await self._approve(
                f"覆盖写入文件 {path}", "confirm", "覆盖已有文件"
            )
            if not decision["allow"]:
                return f"用户拒绝覆盖 {path}，文件未改动。"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        size = path.stat().st_size
        return f"已{'覆盖' if existed else '写入'} {path}（{size} 字节，{len(content.splitlines())} 行）。"

    async def _exec_ask_user(self, args: dict[str, Any]) -> str:
        question = str(args.get("question") or "").strip()
        if not question:
            return "（问题为空）"
        if self.request_approval is None:
            return "（无交互界面，无法提问，请基于现有信息继续）"
        req = self.request_approval(f"ASK_USER:::{question}", "ask", "向用户提问")
        answer = await req.future
        return f"用户的回答: {answer.get('edited', '') or answer.get('answer', '（用户未回答）')}"

    async def _exec_get_system_info(self, _args: dict[str, Any]) -> str:
        now = time.time()
        if self._sysinfo_cache and now - self._sysinfo_cache[0] < 30:
            return self._sysinfo_cache[1]

        def _sh(cmd: str) -> str:
            try:
                r = os.popen(cmd).read().strip()
                return r or "（无）"
            except OSError:
                return "（无）"

        lines = [
            f"主机: {_sh('hostname')}",
            f"发行版: {_sh('grep PRETTY /etc/os-release | cut -d= -f2')}",
            f"内核: {_sh('uname -r')}",
            f"架构: {_sh('uname -m')}",
            f"用户: {_sh('whoami')} @ {_sh('id -u')}",
            f"IP: {_sh('ip -4 -o addr show | awk \'{print $2, $4}\' | tr \'\\n\' \' \'')}",
            f"工作目录: {os.getcwd()}",
            f"已装工具: {_sh('for t in nmap msfconsole nikto hydra john hashcat sqlmap gobuster ffuf netcat; do command -v $t >/dev/null && printf \'%s \' $t; done')}",
        ]
        text = "\n".join(lines)
        self._sysinfo_cache = (now, text)
        return text


def format_tool_result(name: str, arguments: dict, output: str) -> str:
    """把工具调用+结果组装成回传 LLM 的 tool message content。"""
    try:
        arg_str = json.dumps(arguments, ensure_ascii=False)
    except (TypeError, ValueError):
        arg_str = str(arguments)
    return f"工具 {name}({arg_str}) 的结果:\n{output}"
