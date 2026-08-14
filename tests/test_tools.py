"""工具执行器测试：真实执行 + 审批链路。"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kalitui.tools import ApprovalRequest, Executor  # noqa: E402


def _auto_approve(allow: bool, delay: float = 0.0):
    def cb(command: str, level: str, reason: str) -> ApprovalRequest:
        req = ApprovalRequest(command, level, reason)
        asyncio.get_event_loop().call_later(delay, req.resolve, allow, command, False)
        return req

    return cb


async def test_run_command_safe() -> None:
    ex = Executor()
    out = await ex.execute("run_command", {"command": "echo kalitui-ok"})
    assert "kalitui-ok" in out
    assert out.startswith("命令: echo kalitui-ok")


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
    out = await ex.execute("run_command", {"command": "rm -rf /tmp/kalitui-x"})
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
    p = Path("/tmp/kalitui-write-test.txt")
    p.write_text("old")
    ex = Executor(request_approval=_auto_approve(True))
    out = await ex.execute("write_file", {"path": str(p), "content": "new"})
    assert "已覆盖" in out
    assert p.read_text() == "new"


async def test_write_file_denied() -> None:
    p = Path("/tmp/kalitui-write-test2.txt")
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
