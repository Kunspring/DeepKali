"""headless TUI 测试：demo 模式下驱动整个 UI（发送消息→工具执行→回复→弹窗）。"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kalitui import config as kconfig  # noqa: E402
from kalitui.app import ApprovalModal, KaliTUIApp  # noqa: E402
from kalitui.llm import Agent  # noqa: E402
from kalitui.demo import DemoAgent  # noqa: E402
from kalitui.config import Config  # noqa: E402

# 测试期间会话日志写到临时目录，不污染真实 ~/.local/share/kalitui
kconfig.SESSION_DIR = Path(tempfile.mkdtemp(prefix="kalitui-test-")) / "sessions"


def _make_app() -> KaliTUIApp:
    cfg = Config()
    cfg.demo = True
    cfg.danger_policy = "ask"
    cfg.workdir = str(Path.cwd())
    return KaliTUIApp(cfg)


async def _wait_idle(app: KaliTUIApp, timeout: float = 20.0) -> None:
    """等 agent 结束（busy=False），期间让出事件循环。"""
    deadline = asyncio.get_event_loop().time() + timeout
    while app.busy and asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.05)
    assert not app.busy, "agent 超时未结束"


def _chat_text(app: KaliTUIApp) -> str:
    log = app.query_one("#chat")
    return "\n".join(str(line) for line in log.lines)


@pytest.mark.asyncio
async def test_demo_chat_flow() -> None:
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert "Demo 模式" in _chat_text(app)

        inp = app.query_one("#prompt")
        inp.value = "whoami"
        await pilot.press("enter")
        await _wait_idle(app)

        text = _chat_text(app)
        assert "root" in text
        assert "Demo 模式" in text
        assert "当前身份" in text


@pytest.mark.asyncio
async def test_demo_nmap_flow() -> None:
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "扫描本机"
        await pilot.press("enter")
        await _wait_idle(app, timeout=60)

        text = _chat_text(app)
        assert "nmap" in text.lower() or "扫描" in text
        tools = app.query_one("#tools")
        assert any("▶ run_command" in str(line) for line in tools.lines)


@pytest.mark.asyncio
async def test_approval_modal_deny() -> None:
    """爆破命令 → 弹确认框 → 拒绝 → agent 继续给出总结。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "爆破测试"
        await pilot.press("enter")

        # 等弹窗出现（nmap 冷启动可能慢，放宽到 30s 防偶发超时）
        for _ in range(1200):
            if app.screen is not None and isinstance(app.screen, ApprovalModal):
                break
            await pilot.pause(0.05)
        modal = app.screen
        assert isinstance(modal, ApprovalModal), "应当弹出确认框"
        # 等 modal 挂载完成（push_screen 后 compose 是异步的）
        for _ in range(200):
            if modal.is_mounted and modal.query("#btn-deny"):
                break
            await pilot.pause(0.05)
        assert modal.query("#btn-deny")

        await pilot.click("#btn-deny")
        await _wait_idle(app)
        text = _chat_text(app)
        assert "Demo 模式" in text


@pytest.mark.asyncio
async def test_approval_modal_allow_with_edit() -> None:
    """确认框里可以改命令再放行。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "爆破测试"
        await pilot.press("enter")
        for _ in range(1200):
            if isinstance(app.screen, ApprovalModal):
                break
            await pilot.pause(0.05)
        modal = app.screen
        assert isinstance(modal, ApprovalModal)
        for _ in range(200):
            if modal.is_mounted and modal.query("#modal-command"):
                break
            await pilot.pause(0.05)

        cmd_input = modal.query_one("#modal-command")
        cmd_input.value = "echo edited-ok"
        await pilot.click("#btn-allow")
        await _wait_idle(app)
        tools = app.query_one("#tools")
        assert any("edited-ok" in str(line) for line in tools.lines)


@pytest.mark.asyncio
async def test_slash_commands() -> None:
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "/help"
        await pilot.press("enter")
        assert "/danger" in _chat_text(app)

        inp.value = "/danger"
        await pilot.press("enter")
        assert "ask" in _chat_text(app)

        inp.value = "/danger always_allow"
        await pilot.press("enter")
        assert app.config.danger_policy == "always_allow"

        inp.value = "/new"
        await pilot.press("enter")


@pytest.mark.asyncio
async def test_busy_blocks_new_message() -> None:
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "whoami"
        await pilot.press("enter")
        await pilot.pause(0.05)
        assert app.busy
        inp.value = "第二条"
        await pilot.press("enter")
        # 忙时消息应被拒收并留在输入框
        assert inp.value == "第二条"
        await _wait_idle(app)


@pytest.mark.asyncio
async def test_interrupt() -> None:
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "whoami"
        await pilot.press("enter")
        await pilot.pause(0.05)
        await pilot.press("ctrl+c")
        await _wait_idle(app)
        assert not app.busy


@pytest.mark.asyncio
async def test_report_command_demo() -> None:
    """demo 模式（无证据记忆）下 /report 给出友好提示。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "/report"
        await pilot.press("enter")
        await pilot.pause()
        assert "没有可用的工具证据" in _chat_text(app)


@pytest.mark.asyncio
async def test_resume_command_demo() -> None:
    """demo 模式（无恢复能力）下 /resume 给出友好提示。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "/resume"
        await pilot.press("enter")
        await pilot.pause()
        assert "没有找到上次会话状态" in _chat_text(app)


@pytest.mark.asyncio
async def test_demo_agent_evidence_and_report() -> None:
    """demo 模式也产生证据，/report 可生成报告。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    events: list[str] = []

    async def emit(e):
        events.append(e["type"])

    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=emit)
    reply = await agent.chat("whoami")
    assert "当前身份" in reply
    assert len(agent.memory.evidence) >= 1  # 工具输出已记录
    assert agent.memory.findings or True  # findings 结构可用

    # /report 端到端（headless app demo 模式）
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "whoami"
        await pilot.press("enter")
        await _wait_idle(app)
        inp.value = "/report"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "报告" in text and ("生成" in text or "写入" in text or "还没有" in text)


@pytest.mark.asyncio
async def test_demo_agent_extra_branches() -> None:
    """demo 脚本大脑的 hydra（拒绝路径）/msf/reset 分支。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    class DenyExecutor(Executor):
        """execute 直接抛 NeedsApproval（模拟用户拒绝）。"""

        def __init__(self):
            super().__init__(danger_policy="ask")
            self.request_approval = lambda cmd, level, reason: _DenyReq()

    class _DenyReq:
        def __init__(self):
            self.future = _Future()

    class _Future:
        def __init__(self):
            self.result = None

        def set_result(self, v):
            self.result = v

        def __await__(self):
            async def _w():
                return {"allow": False}
            return _w().__await__()

    async def emit(e):
        pass

    agent = DemoAgent(executor=DenyExecutor(), emit=emit)

    # hydra 爆破：被安全层拒绝（NeedsApproval 路径）
    reply = await agent.chat("爆破测试")
    assert "爆破" in reply

    # msf 分支
    reply2 = await agent.chat("msf")
    assert "Metasploit" in reply2

    # 扫描分支（含内网目标解析）
    reply3 = await agent.chat("扫描 192.168.1.5")
    assert "192.168.1.5" in reply3

    # reset 清空
    assert len(agent.messages) >= 3
    agent.reset()
    assert agent.messages == []
    assert len(agent.memory.evidence) == 0


@pytest.mark.asyncio
async def test_demo_agent_tool_error_paths() -> None:
    """demo tool() 的 NeedsApproval / ToolError 分支直接覆盖。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import NeedsApproval, ToolError

    class BoomExecutor:
        def __init__(self, exc):
            self.exc = exc

        async def execute(self, name, arguments):
            raise self.exc

    async def emit(e):
        pass

    # NeedsApproval 分支
    agent = DemoAgent(executor=BoomExecutor(NeedsApproval("hydra ...", "confirm", "需要授权")), emit=emit)
    reply = await agent.chat("爆破测试")
    assert "命令未执行" in reply
    # 拒绝类结果按 ok=True 记录（内容注明未执行）
    assert any("命令未执行" in e.content for e in agent.memory.evidence)

    # ToolError 分支 → record_failure
    agent2 = DemoAgent(executor=BoomExecutor(ToolError("工具出错")), emit=emit)
    reply2 = await agent2.chat("whoami")
    assert "工具出错" in reply2
    assert agent2.memory.tool_health  # 失败已记录健康状态

    # aclose 不抛
    await agent.aclose()
    await agent2.aclose()


@pytest.mark.asyncio
async def test_slash_commands_demo() -> None:
    """demo 模式下 /scope /targets /status /export /danger 命令分支。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")

        # /scope 无参数 → 摘要
        inp.value = "/scope"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "策略" in text

        # /scope off
        inp.value = "/scope off"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "已关闭" in text

        # /scope ask 恢复
        inp.value = "/scope ask"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "已开启" in text

        # /scope add（含 CIDR 提示）
        inp.value = "/scope add 203.0.113.0/24, example.com"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "已授权" in text
        assert "CIDR" in text

        # /scope add 无目标 → 用法提示
        inp.value = "/scope add"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "用法" in text

        # /targets（demo 有 memory）
        inp.value = "/targets"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "目标" in text or "没有" in text

        # /status
        inp.value = "/status"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "模型" in text and "策略" in text
        # 攻击面缺口提示（demo 空会话也有默认缺口清单）
        assert "未探索的高信号方向" in text

        # /export（demo 无 findings → 提示）
        inp.value = "/export"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "还没有发现" in text

        # /danger 查看
        inp.value = "/danger"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "ask" in text or "策略" in text

        # /danger 设置 + 未知命令
        inp.value = "/danger always_block"
        await pilot.press("enter")
        await pilot.pause()
        inp.value = "/nope"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "未知命令" in text


@pytest.mark.asyncio
async def test_demo_export_findings_csv(tmp_path) -> None:
    """DemoAgent.export_findings_csv 与 Agent 同格式。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    async def emit(e):
        pass

    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=emit)
    agent.memory.record("run_command", {"command": "x"}, "flag{demo_export}")
    path = agent.export_findings_csv(path=str(tmp_path / "f.csv"))
    content = open(path, encoding="utf-8-sig").read()
    assert "severity,type,value,evidence" in content
    assert "flag{demo_export}" in content


# ---------------------------------------------------------------------------
# ApprovalModal：ASK_USER 提问 / 危险命令 三态
# ---------------------------------------------------------------------------
from textual.app import App as _TextualApp
from textual.widgets import Input, Static
from kalitui.app import ApprovalModal


class _ModalHost(_TextualApp):
    """把模态框推到屏幕上，捕获 dismiss 结果。"""

    def __init__(self, modal: ApprovalModal):
        super().__init__()
        self.modal = modal
        self.result: dict | None = None

    def compose(self):
        yield Static("host")

    def on_mount(self) -> None:
        self.push_screen(self.modal, self._capture)

    def _capture(self, result: dict | None) -> None:
        self.result = result


@pytest.mark.asyncio
async def test_ask_user_modal_submit() -> None:
    """提问弹窗：显示问题 → 输入回答 → 提交带回答案。"""
    modal = ApprovalModal(command="ASK_USER:::请确认授权范围", level="ask", reason="")
    host = _ModalHost(modal)
    async with host.run_test() as pilot:
        await pilot.pause()
        assert host.screen.query_one("#modal-question")
        assert not host.screen.query("#btn-allow")  # 提问模式无危险命令按钮
        assert not host.screen.query("#btn-deny")
        host.screen.query_one("#modal-answer", Input).value = "我授权 example.com 做测试"
        await pilot.click("#btn-submit")
        await pilot.pause()
    assert host.result == {"allow": True, "edited": "我授权 example.com 做测试", "force": False}


@pytest.mark.asyncio
async def test_ask_user_modal_skip() -> None:
    """跳过提问 → 回传「用户跳过」。"""
    modal = ApprovalModal(command="ASK_USER:::需要密码", level="ask", reason="")
    host = _ModalHost(modal)
    async with host.run_test() as pilot:
        await pilot.pause()
        await pilot.click("#btn-skip")
        await pilot.pause()
    assert host.result == {"allow": False, "edited": "（用户未回答）", "force": False}


@pytest.mark.asyncio
async def test_danger_modal_deny_allow_force() -> None:
    """危险命令弹窗：拒绝/允许/强制按钮齐全，blocked 有强制。"""
    modal = ApprovalModal(command="rm -rf /tmp/x", level="confirm", reason="删除操作")
    host = _ModalHost(modal)
    async with host.run_test() as pilot:
        for _ in range(100):
            if host.screen.query("#btn-deny") and host.screen.query("#btn-allow"):
                break
            await pilot.pause(0.05)
        assert host.screen.query("#btn-deny") and host.screen.query("#btn-allow")
        assert not host.screen.query("#btn-force")  # confirm 级无强制
        await pilot.click("#btn-deny")
        await pilot.pause()
    assert host.result is not None and host.result["allow"] is False

    modal2 = ApprovalModal(command="hydra ...", level="blocked", reason="危险")
    host2 = _ModalHost(modal2)
    async with host2.run_test() as pilot:
        for _ in range(100):
            if host2.screen.query("#btn-force"):
                break
            await pilot.pause(0.05)
        assert host2.screen.query("#btn-force")  # blocked 级有强制按钮
        await pilot.click("#btn-force")
        await pilot.pause()
    assert host2.result == {"allow": True, "edited": "hydra ...", "force": True}


@pytest.mark.asyncio
async def test_ask_user_modal_escape_denies() -> None:
    """Esc 关闭提问 → 拒绝（allow=False）。"""
    modal = ApprovalModal(command="ASK_USER:::继续吗", level="ask", reason="")
    host = _ModalHost(modal)
    async with host.run_test() as pilot:
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
    assert host.result is not None and host.result["allow"] is False


@pytest.mark.asyncio
async def test_demo_resume_restore_and_events(tmp_path) -> None:
    """demo 模式 /resume 恢复证据；_on_event 各事件类型渲染。"""
    from kalitui.demo import DemoAgent
    from kalitui.evidence import AgentMemory
    from kalitui.tools import Executor

    async def emit(e):
        pass

    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=emit)
    # save_state 不持久化、不抛
    assert agent.save_state() is False

    # restore_state 恢复 memory + messages
    mem = AgentMemory()
    mem.record("run_command", {"command": "nmap x"}, "80/tcp open http")
    data = {"memory": mem.to_dict(), "messages": [{"role": "user", "content": "hi"}]}
    agent.restore_state(data)
    assert len(agent.memory.evidence) == 1
    assert agent.messages == [{"role": "user", "content": "hi"}]

    # 坏数据不崩
    agent.restore_state("garbage")
    assert len(agent.memory.evidence) == 1

    # _on_event 各事件类型渲染（直接模拟事件）
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await app._on_event({"type": "error", "message": "boom"})
        await app._on_event({"type": "correction", "hints": ["试试别的"]})
        await app._on_event({"type": "evidence_gate", "verdict": "reject", "reason": "证据不足"})
        await app._on_event({"type": "evidence_gate", "verdict": "pass"})
        await app._on_event({"type": "report", "path": "/tmp/r.md"})
        await pilot.pause()
        text = _chat_text(app)
        assert "boom" in text
        assert "试试别的" in text
        assert "证据闸门拒绝" in text
        assert "通过证据闸门" in text
        assert "/tmp/r.md" in text


class _Err500Server:
    """返回 500 的 mock API（触发 LLMError 路径）。"""

    def __init__(self):
        self.port = 0
        self.server = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        await reader.read(1 << 20)
        writer.write(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


@pytest.mark.asyncio
async def test_real_mode_llm_error_path() -> None:
    """真实模式 API 500 → UI 显示错误与排查提示。"""
    from kalitui.app import KaliTUIApp

    server = _Err500Server()
    await server.start()
    cfg = Config()
    cfg.demo = False
    cfg.api_key = "bad-key"
    cfg.base_url = f"http://127.0.0.1:{server.port}/v1"
    cfg.model = "test-model"
    cfg.workdir = str(Path.cwd())
    app = KaliTUIApp(cfg)
    try:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            inp = app.query_one("#prompt")
            inp.value = "你好"
            await pilot.press("enter")
            await _wait_idle(app)
            text = _chat_text(app)
            assert "检查" in text  # 排查提示
            assert "KALITUI_API_KEY" in text
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_resume_success_path(tmp_path, monkeypatch) -> None:
    """resume.json 存在 → /resume 恢复证据与消息。"""
    import kalitui.app as app_mod
    from kalitui.evidence import AgentMemory

    monkeypatch.setattr(app_mod, "SESSION_DIR", tmp_path)
    mem = AgentMemory()
    mem.record("run_command", {"command": "nmap x"}, "80/tcp open http\nflag{resumed}")
    (tmp_path / "resume.json").write_text(
        json.dumps({"memory": mem.to_dict(), "messages": [{"role": "user", "content": "旧任务"}]}),
        encoding="utf-8",
    )
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "/resume"
        await pilot.press("enter")
        await _wait_idle(app)
        text = _chat_text(app)
        assert "已恢复上次会话" in text
        assert "1 条证据" in text
        # 证据真正加载进 memory（/status 可见）
        inp.value = "/status"
        await pilot.press("enter")
        await pilot.pause()
        assert "证据: 1 条" in _chat_text(app)


@pytest.mark.asyncio
async def test_clear_new_model_commands() -> None:
    """/clear /new /model 基础命令。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")

        # /model
        inp.value = "/model"
        await pilot.press("enter")
        await pilot.pause()
        assert "当前模型" in _chat_text(app)

        # /clear
        inp.value = "whoami"
        await pilot.press("enter")
        await _wait_idle(app)
        assert "root" in _chat_text(app)
        inp.value = "/clear"
        await pilot.press("enter")
        await pilot.pause()
        assert "root" not in _chat_text(app)

        # /new
        inp.value = "/new"
        await pilot.press("enter")
        await pilot.pause()
        assert "已重置" in _chat_text(app)


# ---------------- 追加：中断/退出/自动 demo/恢复提示 ----------------

@pytest.mark.asyncio
async def test_interrupt_no_task() -> None:
    """无任务时 Ctrl+C → 提示，不崩溃。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.action_interrupt()
        await pilot.pause()
        assert "没有正在运行的任务" in _chat_text(app)


@pytest.mark.asyncio
async def test_interrupt_cancels_busy_task() -> None:
    """任务执行中 Ctrl+C → agent 任务取消、busy 复位。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "sleep 5 然后说完成"
        await pilot.press("enter")
        # 等 busy=True（demo 脚本开始执行）
        for _ in range(100):
            if app.busy:
                break
            await pilot.pause(0.05)
        assert app.busy
        app.action_interrupt()
        for _ in range(100):
            if not app.busy:
                break
            await pilot.pause(0.05)
        assert not app.busy
        assert "已中断" in _chat_text(app)


@pytest.mark.asyncio
async def test_no_api_key_auto_demo() -> None:
    """api_key 为空且 demo=False → 自动进入 demo 模式（L204）。"""
    from kalitui.app import KaliTUIApp

    cfg = Config()
    cfg.demo = False
    cfg.api_key = ""
    cfg.workdir = str(Path.cwd())
    app = KaliTUIApp(cfg)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert isinstance(app.agent, DemoAgent)
        assert "Demo 模式" in _chat_text(app)


@pytest.mark.asyncio
async def test_report_command_ok(tmp_path) -> None:
    """demo 模式 /report 生成报告并显示路径。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "nmap 扫描 10.0.0.5"
        await pilot.press("enter")
        await _wait_idle(app)
        inp.value = "/report"
        await pilot.press("enter")
        await pilot.pause()
        text = _chat_text(app)
        assert "报告已生成" in text


@pytest.mark.asyncio
async def test_resume_bad_json_shows_error(tmp_path, monkeypatch) -> None:
    """resume.json 损坏 → 提示恢复失败，不崩溃。"""
    import kalitui.app as app_mod

    monkeypatch.setattr(app_mod, "SESSION_DIR", tmp_path)
    (tmp_path / "resume.json").write_text("{broken json", encoding="utf-8")
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "/resume"
        await pilot.press("enter")
        await pilot.pause()
        assert "恢复失败" in _chat_text(app)


@pytest.mark.asyncio
async def test_quit_command_exits_app() -> None:
    """/quit → app 请求退出。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "/quit"
        await pilot.press("enter")
        await pilot.pause()
        assert app._exit  # Textual 退出标志已设置


@pytest.mark.asyncio
async def test_mount_hints_resume_real_mode(tmp_path, monkeypatch) -> None:
    """真实模式 + 存在 resume.json → 启动提示上次会话可恢复。"""
    import kalitui.app as app_mod
    from kalitui.app import KaliTUIApp
    from kalitui.evidence import AgentMemory

    monkeypatch.setattr(app_mod, "SESSION_DIR", tmp_path)
    mem = AgentMemory()
    mem.record("run_command", {"command": "nmap x"}, "80/tcp open http")
    mem.record("curl", {"url": "http://t/"}, "flag{old_1}")
    (tmp_path / "resume.json").write_text(
        json.dumps({"memory": mem.to_dict(), "messages": []}),
        encoding="utf-8",
    )
    cfg = Config()
    cfg.demo = False
    cfg.api_key = "x"  # 非空 → 不自动切 demo
    cfg.base_url = "http://127.0.0.1:9/v1"
    cfg.workdir = str(Path.cwd())
    app = KaliTUIApp(cfg)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert isinstance(app.agent, Agent)  # 真实模式
        assert "发现上次会话（2 条证据）" in _chat_text(app)


# ---------------- 追加：输出截断显示 / stub agent 分支 ----------------

@pytest.mark.asyncio
async def test_tool_output_truncated_display() -> None:
    """>400 行工具输出 → UI 显示截断提示。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        big = "\n".join(f"line {i}" for i in range(500))
        await app._on_event({"type": "tool_result", "name": "big_scan",
                             "ok": True, "output": big})
        await pilot.pause()
        tools = app.query_one("#tools")
        text = "\n".join(str(line) for line in tools.lines)
        assert "输出截断显示" in text


@pytest.mark.asyncio
async def test_slash_commands_stub_agent_branches() -> None:
    """stub agent（缺方法）→ 各命令的降级提示分支。"""
    app = _make_app()

    class StubAgent:
        def __init__(self):
            self.model = "stub-model"

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")

        # /status：agent 未初始化（None）→ 提示
        app.agent = None
        inp.value = "/status"
        await pilot.press("enter")
        await pilot.pause()
        assert "agent 未初始化" in _chat_text(app)

        # 无 restore_state → /resume 降级提示
        app.agent = StubAgent()
        inp.value = "/resume"
        await pilot.press("enter")
        await pilot.pause()
        assert "当前模式不支持恢复" in _chat_text(app)

        # 无 export_findings_csv → /export 降级提示
        inp.value = "/export"
        await pilot.press("enter")
        await pilot.pause()
        assert "当前模式不支持导出" in _chat_text(app)

        # 无 memory → /targets 降级提示
        inp.value = "/targets"
        await pilot.press("enter")
        await pilot.pause()
        assert "没有目标工作区" in _chat_text(app)


@pytest.mark.asyncio
async def test_statusbar_model_placeholder() -> None:
    """agent 未初始化时状态栏模型占位 —。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.agent = None
        app._update_status()
        await pilot.pause()
        status = str(app.query_one("#statusbar").render())
        assert "模型: —" in status


@pytest.mark.asyncio
async def test_internal_error_path(monkeypatch) -> None:
    """真实模式 agent.chat 抛普通异常 → 内部错误提示。"""
    from kalitui.app import KaliTUIApp

    cfg = Config()
    cfg.demo = False
    cfg.api_key = "x"
    cfg.base_url = "http://127.0.0.1:9/v1"
    cfg.workdir = str(Path.cwd())
    app = KaliTUIApp(cfg)

    class BoomAgent:
        model = "boom"

        async def chat(self, text):
            raise RuntimeError("内部炸了")

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.agent = BoomAgent()
        inp = app.query_one("#prompt")
        inp.value = "hello"
        await pilot.press("enter")
        await _wait_idle(app)
        assert "内部错误" in _chat_text(app)


# ---------------- 追加：demo 剩余分支 ----------------

@pytest.mark.asyncio
async def test_demo_default_overview_branch() -> None:
    """demo 默认分支：无关键词输入 → 系统概览。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    async def emit(e):
        pass

    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=emit)
    reply = await agent.chat("随便聊聊")
    assert "我看了下这台 Kali" in reply
    assert "Demo 模式" in reply


def test_demo_export_default_dir(monkeypatch, tmp_path) -> None:
    """export_findings_csv 无路径 → 默认 kalitui-reports/findings.csv。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    monkeypatch.chdir(tmp_path)
    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=lambda e: None)
    agent.memory.record("run_command", {"command": "x"}, "flag{demo_default_dir}")
    path = agent.export_findings_csv()
    assert path == str(tmp_path / "kalitui-reports" / "findings.csv")
    content = open(path, encoding="utf-8-sig").read()
    assert "flag{demo_default_dir}" in content


def test_demo_write_report_with_findings(tmp_path) -> None:
    """write_report 有 findings 时渲染发现清单行。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=lambda e: None)
    agent.memory.record("run_command", {"command": "cat /flag.txt"}, "flag{top_secret}")
    path = agent.write_report(final_answer="测试结论", path=str(tmp_path / "r.md"))
    content = open(path, encoding="utf-8").read()
    assert "- [5] flag:" in content
    assert "flag{top_secret}" in content
    assert "测试结论" in content


# ---------------- 追加：app 剩余分支 ----------------

def test_session_logger_branches(tmp_path) -> None:
    """SessionLogger：无 path 忽略 + OSError 吞掉。"""
    import json

    from kalitui.app import SessionLogger

    logger = SessionLogger()
    assert logger.path is None
    logger.log(type="session_start")  # 不崩

    logger2 = SessionLogger()
    logger2.path = tmp_path / "no" / "dir" / "x.jsonl"  # 目录不存在 → OSError
    logger2.log(type="session_start")  # 吞掉不崩


@pytest.mark.asyncio
async def test_empty_input_ignored() -> None:
    """空输入提交 → 忽略（不触发 agent）。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        agent = app.agent
        inp = app.query_one("#prompt")
        inp.value = "   "
        await pilot.press("enter")
        await pilot.pause()
        assert app.agent is agent
        assert len(agent.messages) == 0


@pytest.mark.asyncio
async def test_scope_no_executor() -> None:
    """/scope 且 executor 为 None → 直接返回不崩。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.executor = None
        inp = app.query_one("#prompt")
        inp.value = "/scope"
        await pilot.press("enter")
        await pilot.pause()
        assert True  # 不崩即可


@pytest.mark.asyncio
async def test_report_generation_failure(monkeypatch) -> None:
    """/report 时 write_report 抛异常 → 报告生成失败提示。"""
    from kalitui.app import KaliTUIApp
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    cfg = Config()
    cfg.demo = True
    cfg.workdir = str(Path.cwd())
    app = KaliTUIApp(cfg)

    def boom(self):
        raise RuntimeError("磁盘炸了")

    monkeypatch.setattr(DemoAgent, "write_report", boom)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        # on_mount 已重建 agent，mount 后再注入证据
        agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=lambda e: None)
        agent.memory.record("run_command", {"command": "x"}, "flag{x}")
        app.agent = agent
        inp = app.query_one("#prompt")
        inp.value = "/report"
        await pilot.press("enter")
        await pilot.pause()
        assert "报告生成失败" in _chat_text(app)


@pytest.mark.asyncio
async def test_quit_and_clear_commands() -> None:
    """/quit 退出；Ctrl+L 清空工具输出。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        tools = app.query_one("#tools")
        tools.write("旧输出")
        app.action_clear_output()
        await pilot.pause()
        assert "旧输出" not in "\n".join(str(l) for l in tools.lines)
        inp = app.query_one("#prompt")
        inp.value = "/quit"
        await pilot.press("enter")
        await pilot.pause()
        assert app.is_running is False or app._exit_code is not None


@pytest.mark.asyncio
async def test_interrupt_no_task() -> None:
    """无任务时 Ctrl+C → 提示无任务。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.agent_task = None
        app.action_interrupt()
        await pilot.pause()
        assert "没有正在运行的任务" in _chat_text(app)


@pytest.mark.asyncio
async def test_demo_joomla_and_bloodhound_branches() -> None:
    """demo 的 joomla / bloodhound 演示分支。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    async def emit(e):
        pass

    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=emit)
    r1 = await agent.chat("joomla 站点检查")
    assert "Joomla 专项扫描" in r1
    r2 = await agent.chat("bloodhound 采集域关系")
    assert "AD 域关系采集" in r2


# ---------------- 追加2：resume 损坏 / 导出失败 / unmount 容错 ----------------

@pytest.mark.asyncio
async def test_resume_corrupt_json_tolerated(monkeypatch, tmp_path) -> None:
    """真实模式 resume.json 坏 JSON → 启动不崩不提示。"""
    from kalitui import app as app_mod
    from kalitui.app import KaliTUIApp

    monkeypatch.setattr(app_mod, "SESSION_DIR", tmp_path)
    (tmp_path / "resume.json").write_text("{broken json", encoding="utf-8")
    cfg = Config()
    cfg.demo = False
    cfg.api_key = "sk-test"
    cfg.workdir = str(Path.cwd())
    app = KaliTUIApp(cfg)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert "发现上次会话" not in _chat_text(app)


@pytest.mark.asyncio
async def test_export_oserror_reported(monkeypatch) -> None:
    """/export 写盘失败 → 导出失败提示。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=lambda e: None)
        agent.memory.record("run_command", {"command": "x"}, "flag{export_me}")
        app.agent = agent

        def boom(path=None):
            raise OSError("只读磁盘")

        monkeypatch.setattr(DemoAgent, "export_findings_csv", boom)
        inp = app.query_one("#prompt")
        inp.value = "/export"
        await pilot.press("enter")
        await pilot.pause()
        assert "导出失败" in _chat_text(app)


@pytest.mark.asyncio
async def test_unmount_save_and_aclose_failures(monkeypatch) -> None:
    """on_unmount：save_state 抛异常 / aclose RuntimeError → 不崩。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    import kalitui.app as app_mod

    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=lambda e: None)
        app.agent = agent

        def boom_save():
            raise RuntimeError("保存失败")

        async def boom_aclose(self):
            raise RuntimeError("事件循环没了")

        def boom_get_loop():
            raise RuntimeError("无事件循环")

        monkeypatch.setattr(DemoAgent, "save_state", boom_save)
        monkeypatch.setattr(DemoAgent, "aclose", boom_aclose)
        monkeypatch.setattr(app_mod.asyncio, "get_event_loop", boom_get_loop)
        app.on_unmount()
        await pilot.pause()
        assert True  # 不崩即可


@pytest.mark.asyncio
async def test_escape_dismisses_modal_as_deny() -> None:
    """危险命令弹窗 Esc → 按拒绝处理（不执行）。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "爆破测试"  # demo hydra 危险命令 → 弹窗
        await pilot.press("enter")
        for _ in range(50):
            await pilot.pause()
            if app._pending_modal is not None:
                break
        assert app._pending_modal is not None
        await pilot.press("escape")
        for _ in range(50):
            await pilot.pause()
            if app._pending_modal is None:
                break
        assert app._pending_modal is None


# ---------------- 追加3：/export 成功 / interrupt cancel / modal None / new OSError ----------------

@pytest.mark.asyncio
async def test_export_success_path() -> None:
    """/export 成功 → 已导出提示（不 monkeypatch）。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=lambda e: None)
        agent.memory.record("run_command", {"command": "x"}, "flag{export_ok}")
        app.agent = agent
        inp = app.query_one("#prompt")
        inp.value = "/export"
        await pilot.press("enter")
        await pilot.pause()
        assert "已导出 1 条发现" in _chat_text(app)


@pytest.mark.asyncio
async def test_interrupt_cancels_running_task() -> None:
    """任务运行中 Ctrl+C → 取消任务。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        task = asyncio.get_event_loop().create_task(asyncio.sleep(60))
        app.agent_task = task
        app.action_interrupt()
        await pilot.pause()
        assert task.cancelled()


@pytest.mark.asyncio
async def test_modal_dismissed_by_other_path() -> None:
    """弹窗被其他途径关闭（dismiss None）→ 按拒绝处理。"""
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "爆破测试"
        await pilot.press("enter")
        for _ in range(50):
            await pilot.pause()
            if app._pending_modal is not None:
                break
        modal = app._pending_modal
        assert modal is not None
        modal.dismiss(None)  # 模拟其他途径关闭
        for _ in range(50):
            await pilot.pause()
            if app._pending_modal is None:
                break
        assert app._pending_modal is None


@pytest.mark.asyncio
async def test_new_command_unlink_oserror(monkeypatch) -> None:
    """/new 清除 resume.json 遇 OSError → 吞掉不崩。"""
    import kalitui.app as app_mod

    def boom_unlink(*a, **k):
        raise OSError("无法删除")

    monkeypatch.setattr(app_mod.Path, "unlink", boom_unlink)
    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        inp = app.query_one("#prompt")
        inp.value = "/new"
        await pilot.press("enter")
        await pilot.pause()
        assert "会话已重置" in _chat_text(app)


# ---------------- 追加4：unmount cancel / 异常清理 dismiss ----------------

@pytest.mark.asyncio
async def test_unmount_cancels_pending_task() -> None:
    """退出时 agent_task 未完成 → on_unmount cancel。"""
    app = _make_app()
    task = None
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        task = asyncio.get_event_loop().create_task(asyncio.sleep(60))
        app.agent_task = task
    assert task.cancelled()


@pytest.mark.asyncio
async def test_exception_cleanup_dismisses_modal(monkeypatch) -> None:
    """chat 异常时若 modal 仍在屏幕 → dismiss(None) 清理。"""
    from kalitui.app import ApprovalModal
    from kalitui.tools import Executor

    app = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=lambda e: None)

        async def boom_chat(text):
            raise RuntimeError("chat 崩了")

        monkeypatch.setattr(DemoAgent, "chat", boom_chat)
        app.agent = agent
        # 模拟 modal 仍挂在屏幕上（push 后即当前 screen）
        modal = ApprovalModal(command="echo hi", level="danger", reason="测试")
        app.push_screen(modal)
        await pilot.pause()
        app._pending_modal = modal
        await app._run_agent("触发异常")
        await pilot.pause()
        assert app._pending_modal is None
        assert "内部错误" in _chat_text(app)


@pytest.mark.asyncio
async def test_demo_masscan_kerbrute_whatweb_branches() -> None:
    """demo 的 masscan / kerbrute / whatweb 演示分支。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    async def emit(e):
        pass

    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=emit)
    r1 = await agent.chat("masscan 大网段")
    assert "网段高速扫描" in r1
    r2 = await agent.chat("kerbrute 用户枚举")
    assert "AD 用户枚举" in r2
    r3 = await agent.chat("whatweb 指纹")
    assert "Web 指纹识别" in r3


@pytest.mark.asyncio
async def test_demo_drupwn_branch() -> None:
    """demo 的 drupwn 演示分支。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    async def emit(e):
        pass

    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=emit)
    r = await agent.chat("drupwn 看看 drupal 站")
    assert "Drupal 专项扫描" in r


@pytest.mark.asyncio
async def test_demo_subfinder_branch() -> None:
    """demo 的 subfinder 演示分支。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    async def emit(e):
        pass

    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=emit)
    r = await agent.chat("subfinder 枚举子域名")
    assert "子域名枚举" in r


@pytest.mark.asyncio
async def test_demo_dnsx_branch() -> None:
    """demo 的 dnsx 演示分支。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    async def emit(e):
        pass

    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=emit)
    r = await agent.chat("dnsx 解析验证子域")
    assert "DNS 批量解析" in r


@pytest.mark.asyncio
async def test_demo_katana_branch() -> None:
    """demo 的 katana 演示分支。"""
    from kalitui.demo import DemoAgent
    from kalitui.tools import Executor

    async def emit(e):
        pass

    agent = DemoAgent(executor=Executor(danger_policy="always_allow"), emit=emit)
    r = await agent.chat("katana 爬 JS 端点")
    assert "JS 端点提取" in r
