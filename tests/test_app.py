"""headless TUI 测试：demo 模式下驱动整个 UI（发送消息→工具执行→回复→弹窗）。"""

import asyncio
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kalitui import config as kconfig  # noqa: E402
from kalitui.app import ApprovalModal, KaliTUIApp  # noqa: E402
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

        # 等弹窗出现
        for _ in range(200):
            if app.screen is not None and isinstance(app.screen, ApprovalModal):
                break
            await pilot.pause(0.05)
        modal = app.screen
        assert isinstance(modal, ApprovalModal), "应当弹出确认框"
        # 等 modal 挂载完成（push_screen 后 compose 是异步的）
        for _ in range(100):
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
        for _ in range(200):
            if isinstance(app.screen, ApprovalModal):
                break
            await pilot.pause(0.05)
        modal = app.screen
        assert isinstance(modal, ApprovalModal)
        for _ in range(100):
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
