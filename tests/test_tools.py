"""工具执行器测试：真实执行 + 审批链路。"""

import asyncio
import sys

import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from DeepKali.tools import ApprovalRequest, Executor, ToolError  # noqa: E402


def _auto_approve(allow: bool, delay: float = 0.0):
    def cb(command: str, level: str, reason: str) -> ApprovalRequest:
        req = ApprovalRequest(command, level, reason)
        asyncio.get_event_loop().call_later(delay, req.resolve, allow, command, False)
        return req

    return cb


async def test_run_command_safe() -> None:
    ex = Executor()
    out = await ex.execute("run_command", {"command": "echo DeepKali-ok"})
    assert "DeepKali-ok" in out
    assert out.startswith("命令: echo DeepKali-ok")


async def test_run_command_nonzero_shows_code() -> None:
    ex = Executor()
    out = await ex.execute("run_command", {"command": "sh -c 'exit 3'"})
    assert "退出码: 3" in out


async def test_run_command_timeout() -> None:
    ex = Executor()
    out = await ex.execute("run_command", {"command": "sleep 5", "timeout": 1})
    assert "超时" in out


async def test_dangerous_denied() -> None:
    ex = Executor(request_approval=_auto_approve(False))
    out = await ex.execute("run_command", {"command": "rm -rf /tmp/DeepKali-x"})
    assert "被用户拒绝" in out


async def test_dangerous_approved() -> None:
    ex = Executor(request_approval=_auto_approve(True))
    out = await ex.execute("run_command", {"command": "echo approved-ok"})
    assert "approved-ok" in out


async def test_blocked_without_force() -> None:
    ex = Executor(request_approval=_auto_approve(True))
    out = await ex.execute("run_command", {"command": "reboot"})
    assert "被安全策略拦截" in out


async def test_blocked_with_force() -> None:
    calls: list[tuple[str, str, str]] = []

    def cb(command: str, level: str, reason: str) -> ApprovalRequest:
        req = ApprovalRequest(command, level, reason)
        calls.append((command, level, reason))
        asyncio.get_event_loop().call_later(
            0.01, req.resolve, True, "echo forced-ok", True
        )
        return req

    ex = Executor(request_approval=cb)
    out = await ex.execute("run_command", {"command": "reboot"})
    assert calls and calls[0][1] == "blocked"
    assert "forced-ok" in out  # 编辑后的命令被放行


async def test_read_file_and_missing() -> None:
    ex = Executor()
    out = await ex.execute("read_file", {"path": "/etc/hostname"})
    assert out.startswith("/etc/hostname")
    out2 = await ex.execute("read_file", {"path": "/nonexistent-xyz"})
    assert "不存在" in out2


async def test_write_file_confirm() -> None:
    p = Path("/tmp/DeepKali-write-test.txt")
    p.write_text("old")
    ex = Executor(request_approval=_auto_approve(True))
    out = await ex.execute("write_file", {"path": str(p), "content": "new"})
    assert "已覆盖" in out
    assert p.read_text() == "new"


async def test_write_file_denied() -> None:
    p = Path("/tmp/DeepKali-write-test2.txt")
    p.write_text("old")
    ex = Executor(request_approval=_auto_approve(False))
    out = await ex.execute("write_file", {"path": str(p), "content": "new"})
    assert "拒绝覆盖" in out
    assert p.read_text() == "old"
    p.unlink(missing_ok=True)


async def test_ask_user() -> None:
    def cb(command: str, level: str, reason: str) -> ApprovalRequest:
        assert command.startswith("ASK_USER:::")
        req = ApprovalRequest(command, level, reason)
        asyncio.get_event_loop().call_later(0.01, req.resolve, True, "目标是 10.0.0.5", False)
        return req

    ex = Executor(request_approval=cb)
    out = await ex.execute("ask_user", {"question": "目标 IP 是？"})
    assert "10.0.0.5" in out


async def test_get_system_info() -> None:
    ex = Executor()
    out = await ex.execute("get_system_info", {})
    assert "发行版" in out and "内核" in out


async def test_unknown_tool() -> None:
    ex = Executor()
    try:
        await ex.execute("no_such_tool", {})
        assert False, "应当抛错"
    except Exception as e:  # noqa: BLE001
        assert "未知工具" in str(e)


# ---------------- 未覆盖分支 ----------------

async def test_run_command_empty_raises() -> None:
    ex = Executor(danger_policy="always_allow")
    with pytest.raises(ToolError, match="command 为空"):
        await ex.execute("run_command", {"command": "   "})


async def test_edited_command_still_dangerous_blocked() -> None:
    """用户编辑后的命令仍危险（blocked）→ 拦截提示。"""
    seen: list[str] = []

    def cb(command: str, level: str, reason: str) -> ApprovalRequest:
        req = ApprovalRequest(command, level, reason)
        # 把危险命令"编辑"成另一个 blocked 危险命令（模拟用户改写不彻底）
        asyncio.get_event_loop().call_later(0, req.resolve, True, "mkfs.ext4 /dev/sda", False)
        seen.append(command)
        return req

    ex = Executor(danger_policy="ask", request_approval=cb)
    out = await ex.execute("run_command", {"command": "rm -rf /"})
    assert "编辑后的命令仍被判定为危险并已拦截" in out
    assert seen


async def test_output_truncated() -> None:
    ex = Executor(danger_policy="always_allow", max_output_lines=3)
    out = await ex.execute("run_command", {"command": "seq 1 20"})
    assert "已截断" in out
    assert "共 20 行" in out


async def test_read_file_directory_lists_entries(tmp_path) -> None:
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    ex = Executor(danger_policy="always_allow")
    out = await ex.execute("read_file", {"path": str(tmp_path)})
    assert "目录，共 2 项" in out
    assert "a.txt" in out and "b.txt" in out


async def test_ask_user_empty_question() -> None:
    ex = Executor(danger_policy="always_allow")
    out = await ex.execute("ask_user", {"question": "  "})
    assert "问题为空" in out


# ---------------- 追加：_approve 策略 / 异常透传 / 兜底分支 ----------------

async def test_approve_always_allow_and_block() -> None:
    ex_allow = Executor(danger_policy="always_allow")
    r = await ex_allow._approve("rm -rf /", "blocked", "x")
    assert r["allow"] is True and r["force"] is True

    ex_block = Executor(danger_policy="always_block")
    r2 = await ex_block._approve("rm -rf /", "blocked", "x")
    assert r2["allow"] is False and r2["force"] is False


async def test_approve_no_ui_defaults_deny() -> None:
    ex = Executor(danger_policy="ask", request_approval=None)
    r = await ex._approve("rm -rf /", "blocked", "x")
    assert r["allow"] is False


async def test_ask_user_no_ui() -> None:
    ex = Executor(danger_policy="ask", request_approval=None)
    out = await ex._exec_ask_user({"question": "继续吗？"})
    assert "无交互界面" in out


async def test_execute_needs_approval_passthrough() -> None:
    from DeepKali.tools import NeedsApproval

    class BoomExt:
        async def execute(self, name, arguments):
            raise NeedsApproval("需要授权", "confirm", "测试")

    ex = Executor()
    ex.extensions["boom"] = BoomExt().execute
    with pytest.raises(NeedsApproval):
        await ex.execute("boom", {})


async def test_execute_cancelled_passthrough() -> None:
    class BoomExt:
        async def execute(self, name, arguments):
            raise asyncio.CancelledError

    ex = Executor()
    ex.extensions["boom"] = BoomExt().execute
    with pytest.raises(asyncio.CancelledError):
        await ex.execute("boom", {})


def test_format_tool_result_unserializable() -> None:
    from DeepKali.tools import format_tool_result

    out = format_tool_result("probe", {"tags": {"a", "b"}}, "data")
    assert "工具 probe(" in out
    assert "data" in out


async def test_sysinfo_oserror_fallback(monkeypatch) -> None:
    """os.popen 抛 OSError → （无）兜底。"""
    import DeepKali.tools as T

    real_popen = T.os.popen

    def boom(cmd):
        raise OSError("pipe 失败")

    monkeypatch.setattr(T.os, "popen", boom)
    ex = Executor()
    ex._sysinfo_cache = None
    out = await ex._exec_get_system_info({})
    assert "（无）" in out
    monkeypatch.setattr(T.os, "popen", real_popen)


# ---------------- 追加2：取消透传 / kill_group 容错 ----------------

@pytest.mark.asyncio
async def test_execute_cancel_kills_group(monkeypatch):
    """execute 中任务被取消 → kill_group + 透传 CancelledError。"""
    from DeepKali import tools as T

    killed = []

    def fake_kill(self, proc):
        killed.append(proc.pid)

    monkeypatch.setattr(T.Executor, "_kill_group", fake_kill)
    ex = T.Executor(danger_policy="always_allow")
    task = asyncio.ensure_future(ex.execute("run_command", {"command": "sleep 60"}))
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert killed  # kill_group 被调用


@pytest.mark.asyncio
async def test_kill_group_fallback(monkeypatch):
    """killpg 失败 → proc.kill() 兜底；再失败 → 静默。"""
    from DeepKali import tools as T

    class FakeProc:
        def __init__(self):
            self.returncode = None
            self.pid = 99999

        def kill(self):
            raise ProcessLookupError("已退出")

    def boom_killpg(*a, **k):
        raise ProcessLookupError("进程已退出")

    def boom_kill(*a, **k):
        raise ProcessLookupError("已退出")

    monkeypatch.setattr(T.os, "killpg", boom_killpg)
    monkeypatch.setattr(FakeProc, "kill", boom_kill)
    T.Executor._kill_group(FakeProc())  # killpg 失败 → kill 兜底也失败 → 静默

    class FakeProc2:
        def __init__(self):
            self.returncode = None
            self.pid = 1

        def kill(self):
            raise PermissionError

    def boom_killpg2(*a, **k):
        raise PermissionError

    monkeypatch.setattr(T.os, "killpg", boom_killpg2)
    with pytest.raises(PermissionError):
        T.Executor._kill_group(FakeProc2())
