"""KaliTUI 主界面：Textual 应用。

布局：
  ┌ Header（标题 + 模型） ┐
  │ 对话 RichLog  │ 工具输出 RichLog │
  │ 状态栏（agent 状态/策略/工作目录） │
  │ Input（> 输入） │
  └ Footer ┘

交互：
  - 输入消息回车发送；/help /clear /new /danger /model /quit
  - Ctrl+C 中断当前 agent（会连带杀掉正在运行的子进程组）
  - 危险命令/覆盖文件/提问 → 弹窗确认
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Input, RichLog, Static

from . import APP_NAME, __version__
from .config import Config, SESSION_DIR
from .demo import DemoAgent
from .llm import Agent, LLMError
from .tools import ApprovalRequest, Executor


# ---------------------------------------------------------------------------
# 确认弹窗
# ---------------------------------------------------------------------------
class ApprovalModal(ModalScreen[dict]):
    """危险命令审批 / ask_user 提问 共用弹窗。"""

    BINDINGS = [("escape", "deny", "拒绝/跳过")]

    def __init__(
        self,
        *,
        command: str,
        level: str,
        reason: str,
        title: str = "⚠ 需要确认",
    ) -> None:
        super().__init__()
        self.command = command
        self.level = level
        self.reason = reason
        self._title = title
        self._is_question = command.startswith("ASK_USER:::")

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Static(self._title, id="modal-title")
            if self._is_question:
                yield Static(
                    f"[bold]问题：[/bold]{self.command[len('ASK_USER:::'):]}",
                    id="modal-question",
                )
                yield Input(placeholder="输入你的回答…", id="modal-answer")
                with Horizontal(id="modal-buttons"):
                    yield Button("⏭ 跳过", id="btn-skip", variant="primary")
                    yield Button("✅ 提交", id="btn-submit", variant="success")
            else:
                level_tag = {
                    "blocked": "[red]🔒 已拦截（危险）[/red]",
                    "confirm": "[yellow]⚠ 危险操作[/yellow]",
                }.get(self.level, "[yellow]⚠[/yellow]")
                yield Static(f"{level_tag}\n[dim]{self.reason}[/dim]", id="modal-reason")
                yield Static("[dim]可在下面编辑命令后再放行：[/dim]", id="modal-hint")
                yield Input(value=self.command, id="modal-command")
                with Horizontal(id="modal-buttons"):
                    yield Button("✖ 拒绝", id="btn-deny", variant="error")
                    yield Button("✔ 允许", id="btn-allow", variant="success")
                    if self.level == "blocked":
                        yield Button("🔥 强制", id="btn-force", variant="warning")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def _finish(self, allow: bool, force: bool = False) -> None:
        if self._is_question:
            answer = self.query_one("#modal-answer", Input).value.strip()
            # 提问模式：提交(allow=True)/跳过与Esc(allow=False) 语义区分
            self.dismiss({
                "allow": allow,
                "edited": answer or ("（用户跳过）" if allow else "（用户未回答）"),
                "force": False,
            })
        else:
            cmd = self.query_one("#modal-command", Input).value.strip() or self.command
            self.dismiss({"allow": allow, "edited": cmd, "force": force})

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "btn-allow":
            self._finish(True)
        elif btn == "btn-force":
            self._finish(True, force=True)
        elif btn == "btn-deny":
            self._finish(False)
        elif btn == "btn-submit":
            self._finish(True)
        elif btn == "btn-skip":
            self._finish(False)

    def action_deny(self) -> None:
        self._finish(False)


# ---------------------------------------------------------------------------
# 会话记录
# ---------------------------------------------------------------------------
class SessionLogger:
    def __init__(self) -> None:
        self.path: Path | None = None

    def start(self) -> None:
        SESSION_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.path = SESSION_DIR / f"session-{ts}.jsonl"
        self.log(type="session_start")

    def log(self, **kw: Any) -> None:
        if self.path is None:
            return
        try:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": time.time(), **kw}, ensure_ascii=False) + "\n")
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 主应用
# ---------------------------------------------------------------------------
class KaliTUIApp(App[None]):
    TITLE = f"{APP_NAME} — AI 驾驭 Kali"
    SUB_TITLE = f"v{__version__} · 危险命令需确认 · Ctrl+C 中断"

    BINDINGS = [
        ("ctrl+c", "interrupt", "中断 agent"),
        ("q", "quit", "退出"),
        ("ctrl+l", "clear_output", "清空输出"),
    ]

    CSS = """
    #chat-panel { width: 3fr; border-right: solid $primary; }
    #tool-panel { width: 2fr; }
    .panel-title { height: 1; background: $panel; color: $text-muted; text-style: bold; padding: 0 1; }
    RichLog { border: none; padding: 0 1; }
    #statusbar { height: 1; background: $surface; color: $text-muted; padding: 0 2; }
    #prompt { dock: bottom; }
    #modal-box {
        width: 65%; min-width: 60; max-width: 84; height: auto; max-height: 60%;
        border: thick $accent; background: $surface;
        padding: 1 2; margin: 2 4;
    }
    #modal-title { text-style: bold; color: $warning; margin-bottom: 1; }
    #modal-reason, #modal-question { margin-bottom: 1; }
    #modal-hint { color: $text-muted; margin-bottom: 1; }
    #modal-command, #modal-answer { margin-bottom: 1; }
    #modal-buttons { height: 3; align: center middle; }
    Button { margin: 0 1; }
    """

    def __init__(self, config: Config) -> None:
        super().__init__()
        self.config = config
        self.executor: Executor | None = None
        self.agent: Agent | DemoAgent | None = None
        self.agent_task: asyncio.Task | None = None
        self.busy = False
        self.logger = SessionLogger()
        self._pending_modal: ApprovalModal | None = None
        self._sysinfo_done = False

    # ---------------- 组合 ----------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="chat-panel"):
                yield Static("💬 对话", classes="panel-title")
                yield RichLog(id="chat", markup=True, wrap=True, highlight=False)
            with Vertical(id="tool-panel"):
                yield Static("🛠 工具执行", classes="panel-title")
                yield RichLog(id="tools", markup=True, wrap=True, highlight=False)
        yield Static("", id="statusbar")
        yield Input(placeholder="> 给 AI 下达任务…（/help 查看命令）", id="prompt")
        yield Footer()

    def on_mount(self) -> None:
        cfg = self.config
        if not cfg.api_key and not cfg.demo:
            cfg.demo = True  # 自动进入 demo 模式
        self.executor = Executor(
            request_approval=self._request_approval,
            danger_policy=cfg.danger_policy,
            max_output_lines=cfg.max_output_lines,
            scope_policy=cfg.scope_policy,
        )
        # 加载历史授权目标（白帽跨会话复用）
        self.executor.scope.load_persisted()
        from .profiles import register_extensions

        register_extensions(self.executor)  # 深度定制工具挂载（demo/真实共用）
        if cfg.demo:
            self.agent = DemoAgent(executor=self.executor, emit=self._on_event)
        else:
            self.agent = Agent(
                api_key=cfg.api_key,
                base_url=cfg.base_url,
                model=cfg.model,
                temperature=cfg.temperature,
                max_tokens=cfg.max_tokens,
                timeout=cfg.timeout,
                workdir=cfg.workdir,
                user=os.environ.get("USER", "root"),
                extra_system_prompt=cfg.extra_system_prompt,
                executor=self.executor,
                emit=self._on_event,
                resume_path=str(SESSION_DIR / "resume.json"),
            )
        self.logger.start()
        chat = self.query_one("#chat", RichLog)
        chat.write(
            f"[bold green]╔══ {APP_NAME} ══╗[/bold green]\n"
            f"[green]让 AI 驾驭你的 Kali[/green]  [dim]v{__version__}[/dim]"
        )
        if cfg.demo:
            chat.write(
                "[yellow]⚠ 未检测到 API key，已进入 [bold]Demo 模式[/bold]"
                "（脚本大脑，仅演示工具链路）[/yellow]\n"
                "[dim]设置 KALITUI_API_KEY=sk-xxx（或编辑 ~/.config/kalitui/config.json）后重启即接入真实 AI。[/dim]"
            )
        chat.write(
            "[dim]试试：『扫描本机』『whoami』『爆破测试』；输入 /help 查看命令。[/dim]\n"
        )
        # 会话恢复提示（白帽跨会话续挖）
        resume_file = SESSION_DIR / "resume.json"
        if not cfg.demo and resume_file.exists():
            try:
                data = json.loads(resume_file.read_text(encoding="utf-8"))
                n = len(data.get("memory", {}).get("evidence", []))
                if n > 0:
                    chat.write(
                        f"[dim][green]📎 发现上次会话（{n} 条证据），输入 /resume 继续。[/green][/dim]"
                    )
            except (json.JSONDecodeError, OSError):
                pass
        self.query_one("#prompt", Input).focus()
        self._update_status()

    # ---------------- 事件通道 ----------------
    async def _on_event(self, event: dict[str, Any]) -> None:
        etype = event["type"]
        chat = self.query_one("#chat", RichLog)
        tools = self.query_one("#tools", RichLog)
        if etype == "thinking":
            self.busy = True
            chat.write("[dim]🤔 agent 思考中…[/dim]")
        elif etype == "tool_start":
            name = event["name"]
            args = event["arguments"]
            arg_str = json.dumps(args, ensure_ascii=False)[:300]
            tools.write(f"[bold yellow]▶ {name}[/bold yellow] [dim]{arg_str}[/dim]")
            chat.write(f"[dim]🛠 调用 [yellow]{name}[/yellow][/dim]")
            self.logger.log(type="tool_start", name=name, arguments=args)
        elif etype == "tool_result":
            name, ok, output = event["name"], event["ok"], event["output"]
            mark = "[green]✔[/green]" if ok else "[red]✘[/red]"
            tools.write(f"{mark} [bold]{name}[/bold] 完成")
            for line in output.splitlines()[:400]:
                tools.write(f"[dim]{line[:500]}[/dim]")
            if len(output.splitlines()) > 400:
                tools.write("[dim]…（输出截断显示）[/dim]")
            self.logger.log(type="tool_result", name=name, ok=ok, output=output[:4000])
        elif etype == "error":
            chat.write(f"[red]⚠ {event['message']}[/red]")
        elif etype == "correction":
            for hint in event.get("hints", []):
                chat.write(f"[dim][yellow]🧭 {hint}[/yellow][/dim]")
        elif etype == "evidence_gate":
            if event.get("verdict") == "reject":
                chat.write(f"[red]🔒 证据闸门拒绝结论：{event.get('reason', '')}[/red]")
            else:
                chat.write("[dim][green]✔ 结论通过证据闸门校验[/green][/dim]")
        elif etype == "report":
            chat.write(f"[green]📄 复盘报告已保存:[/green] [bold]{event.get('path', '')}[/bold]")

    # ---------------- 审批回调（agent 线程 → UI） ----------------
    def _request_approval(self, command: str, level: str, reason: str) -> ApprovalRequest:
        req = ApprovalRequest(command, level, reason)
        is_question = command.startswith("ASK_USER:::")
        title = "❓ 向你提问" if is_question else ("🔒 危险命令拦截" if level == "blocked" else "⚠ 危险操作确认")
        modal = ApprovalModal(command=command, level=level, reason=reason, title=title)
        self._pending_modal = modal

        def on_result(result: dict | None) -> None:
            self._pending_modal = None
            if result is None:  # 被其他途径关闭
                req.resolve(False)
            else:
                req.resolve(
                    allow=bool(result.get("allow")),
                    edited=result.get("edited") or command,
                    force=bool(result.get("force")),
                )

        self.push_screen(modal, on_result)
        return req
    # ---------------- 发送 ----------------
    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        event.input.value = ""
        if text.startswith("/"):
            self._run_slash(text)
            return
        if self.busy:
            self.query_one("#chat", RichLog).write(
                "[yellow]⏳ agent 正在忙，按 Ctrl+C 可中断，稍后再发。[/yellow]"
            )
            event.input.value = text  # 还给你，别丢
            return
        self._send(text)

    def _send(self, text: str) -> None:
        chat = self.query_one("#chat", RichLog)
        chat.write(f"[bold cyan]你[/bold cyan] {text}")
        self.logger.log(role="user", content=text)
        self.busy = True
        self._update_status()
        self.agent_task = asyncio.create_task(self._run_agent(text))

    async def _run_agent(self, text: str) -> None:
        chat = self.query_one("#chat", RichLog)
        try:
            assert self.agent is not None
            reply = await self.agent.chat(text)
            chat.write(f"[bold green]{APP_NAME}[/bold green] {reply}")
            self.logger.log(role="assistant", content=reply)
        except asyncio.CancelledError:
            chat.write("[red]⏹ 已中断（正在执行的命令已被终止）[/red]")
        except LLMError as e:
            chat.write(f"[red]⚠ {e}[/red]")
            chat.write(
                "[dim]检查：KALITUI_API_KEY 是否正确、网络是否可达、模型名是否有效。[/dim]"
            )
        except Exception as e:  # noqa: BLE001
            chat.write(f"[red]⚠ 内部错误: {e}[/red]")
        finally:
            self.busy = False
            pm = self._pending_modal
            self._pending_modal = None
            if pm is not None and self.screen is pm:
                pm.dismiss(None)
            self._update_status()

    # ---------------- 斜杠命令 ----------------
    def _run_slash(self, text: str) -> None:
        chat = self.query_one("#chat", RichLog)
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if cmd == "/help":
            chat.write(
                "[bold]命令[/bold]\n"
                "  /clear      清空聊天与工具输出\n"
                "  /new        重置 agent 会话（清空上下文）\n"
                "  /resume     恢复上次会话（证据记忆 + 对话历史）\n"
                "  /targets    目标工作区：按目标统计证据/发现/事实\n"
                "  /status     会话状态面板（模型/策略/证据/发现/目标）\n"
                "  /danger     查看当前危险命令策略\n"
                "  /danger ask|always_allow|always_block   设置策略\n"
                "  /scope      查看目标授权范围（白帽合规守卫）\n"
                "  /scope add <目标>…   授权目标（本会话不再询问）\n"
                "  /report     基于当前证据手动生成复盘报告（bounty 风格）\n"
                "  /export     导出发现 CSV（按严重度排序，Excel 可直接打开）\n"
                "  /model      显示当前模型\n"
                "  /quit       退出\n"
                "[bold]按键[/bold]  Ctrl+C 中断  ·  q 退出  ·  Ctrl+L 清输出"
            )
        elif cmd == "/clear":
            self.query_one("#chat", RichLog).clear()
            self.query_one("#tools", RichLog).clear()
        elif cmd == "/new":
            if self.agent:
                self.agent.reset()
            # 清掉旧会话状态，避免下次启动误提示"可恢复"
            try:
                (SESSION_DIR / "resume.json").unlink(missing_ok=True)
            except OSError:
                pass
            chat.write("[dim]🔄 会话已重置（旧状态已清除）。[/dim]")
        elif cmd == "/danger":
            if arg in ("ask", "always_allow", "always_block"):
                self.config.danger_policy = arg
                if self.executor:
                    self.executor.danger_policy = arg
                tip = ""
                if arg == "always_allow":
                    tip = "\n[dim]⚠ 注意：目标范围守卫（/scope）仍生效，外部目标依然需要授权确认。[/dim]"
                chat.write(f"[green]✔ 危险命令策略 → {arg}[/green]{tip}")
            else:
                chat.write(
                    f"[dim]当前策略：[/dim][yellow]{self.config.danger_policy}[/yellow]"
                    "\n[dim]  ask=询问  always_allow=自动放行  always_block=全部拒绝[/dim]"
                )
        elif cmd == "/model":
            m = getattr(self.agent, "model", "demo")
            chat.write(f"[dim]当前模型：[/dim][yellow]{m}[/yellow]")
        elif cmd == "/scope":
            if not self.executor:
                return
            if arg == "off":
                self.executor.scope.policy = "off"
                chat.write("[yellow]⚠ 目标范围守卫已关闭（仅建议本机/内网自测时使用）[/yellow]")
            elif arg == "ask":
                self.executor.scope.policy = "ask"
                chat.write("[green]✔ 目标范围守卫已开启（外部目标需授权确认）[/green]")
            elif arg.startswith("add"):
                targets = [t.strip() for t in arg[3:].replace(",", " ").split() if t.strip()]
                if targets:
                    self.executor.scope.authorize_all(targets)
                    chat.write(
                        "[green]✔ 已授权: [/green]"
                        + " ".join(targets)
                        + "\n[dim]支持 IP / 域名 / CIDR 网段（如 203.0.113.0/24），授权后不再询问。[/dim]"
                    )
                    chat.write(
                        f"[green]✔ 已授权目标:[/green] {', '.join(targets)}"
                        "（本会话不再询问，已保存，下次启动自动加载）"
                    )
                else:
                    chat.write("[red]用法: /scope add <目标1> [目标2…][/red]")
            else:
                chat.write(self.executor.scope.summary())
        elif cmd == "/report":
            agent = getattr(self, "agent", None)
            memory = getattr(agent, "memory", None)
            if memory is None or not memory.evidence:
                chat.write("[dim]当前没有可用的工具证据，先让 agent 跑点任务再生成报告。[/dim]")
            else:
                try:
                    path = agent.write_report()
                    chat.write(f"[green]📄 报告已生成:[/green] [bold]{path}[/bold]")
                except Exception as e:  # noqa: BLE001
                    chat.write(f"[red]报告生成失败: {e}[/red]")
        elif cmd == "/resume":
            agent = getattr(self, "agent", None)
            if agent is None or not hasattr(agent, "restore_state"):
                chat.write("[dim]当前模式不支持恢复。[/dim]")
                return
            resume_file = SESSION_DIR / "resume.json"
            if not resume_file.exists():
                chat.write("[dim]没有找到上次会话状态。[/dim]")
                return
            try:
                data = json.loads(resume_file.read_text(encoding="utf-8"))
                agent.restore_state(data)
                n = len(agent.memory.evidence)
                chat.write(
                    f"[green]✔ 已恢复上次会话（{n} 条证据，{len(agent.messages)} 条对话）。[/green]\n"
                    "[dim]可继续下达任务，或 /report 生成当前进展报告。[/dim]"
                )
                self._update_status()
            except (json.JSONDecodeError, OSError) as e:
                chat.write(f"[red]恢复失败: {e}[/red]")
        elif cmd == "/targets":
            memory = getattr(getattr(self, "agent", None), "memory", None)
            if memory is None:
                chat.write("[dim]当前模式没有目标工作区。[/dim]")
            else:
                chat.write(memory.targets_summary())
        elif cmd == "/status":
            agent = getattr(self, "agent", None)
            memory = getattr(agent, "memory", None)
            if agent is None:
                chat.write("[dim]agent 未初始化。[/dim]")
                return
            lines = [f"模型: {getattr(agent, 'model', 'demo')}"]
            lines.append(f"危险策略: {self.config.danger_policy}")
            lines.append(f"范围守卫: {self.executor.scope.policy}")
            if memory is not None:
                lines.append(f"证据: {len(memory.evidence)} 条 · 发现: {len(memory.findings)} 条")
                lines.append(f"高信号事实: {len(memory.pinned_facts)} 条")
                targets = memory.target_stats()
                if targets:
                    lines.append("目标: " + ", ".join(f"{t['target']}({t['evidence']})" for t in targets[:8]))
                gaps = memory.attack_surface_gaps()
                if gaps:
                    lines.append("未探索的高信号方向: " + " / ".join(gaps[:6]))
            lines.append(f"会话消息: {len(agent.messages)} 条")
            lines.append(f"工作目录: {self.config.workdir}")
            chat.write("\n".join(lines))
        elif cmd == "/export":
            agent = getattr(self, "agent", None)
            if agent is None or not hasattr(agent, "export_findings_csv"):
                chat.write("[dim]当前模式不支持导出。[/dim]")
                return
            if not agent.memory.findings:
                chat.write("[dim]还没有发现可导出。[/dim]")
                return
            try:
                path = agent.export_findings_csv()
                chat.write(
                    f"[green]✔ 已导出 {len(agent.memory.findings)} 条发现 → {path}[/green]\n"
                    "[dim]CSV 按严重度排序，utf-8-sig 编码可直接用 Excel/WPS 打开。[/dim]"
                )
            except OSError as e:
                chat.write(f"[red]导出失败: {e}[/red]")
        elif cmd == "/quit":
            self.exit()
        else:
            chat.write(f"[red]未知命令 {cmd}[/red]（/help 查看）")
        self._update_status()

    # ---------------- 按键 ----------------
    def action_interrupt(self) -> None:
        if self.agent_task and not self.agent_task.done():
            self.agent_task.cancel()
        else:
            self.query_one("#chat", RichLog).write("[dim]当前没有正在运行的任务。[/dim]")

    def action_clear_output(self) -> None:
        self.query_one("#tools", RichLog).clear()

    # ---------------- 状态栏 ----------------
    def _update_status(self) -> None:
        cfg = self.config
        state = "⏳ 工作中…" if self.busy else "🟢 就绪"
        model = getattr(self.agent, "model", "demo")
        if self.agent is None:
            model = "—"
        scope_policy = getattr(self.executor, "scope", None)
        scope_str = scope_policy.policy if scope_policy else "?"
        self.query_one("#statusbar", Static).update(
            f" {state}  │  模型: {model}  │  危险策略: {cfg.danger_policy}"
            f"  │  范围守卫: {scope_str}"
            f"  │  cwd: {cfg.workdir}"
        )

    def on_unmount(self) -> None:
        if self.agent_task and not self.agent_task.done():
            self.agent_task.cancel()
        # 保存会话状态（白帽跨会话续挖）
        if self.agent and hasattr(self.agent, "save_state"):
            try:
                self.agent.save_state()
            except Exception:  # noqa: BLE001
                pass
        if self.agent and hasattr(self.agent, "aclose"):
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self.agent.aclose())
            except RuntimeError:
                pass
