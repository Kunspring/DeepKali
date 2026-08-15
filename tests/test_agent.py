"""Agent 工具循环端到端测试：本地 mock OpenAI 兼容 API。

模拟 LLM 行为：
  第 1 轮: 返回 tool_call(run_command, "echo hello-agent")
  第 2 轮: 返回 tool_call(get_system_info)
  第 3 轮: 返回最终文本
验证：工具结果正确回填、消息序列正确、最终回复返回。
"""

import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from DeepKali.llm import Agent, LLMError  # noqa: E402
from DeepKali.tools import Executor  # noqa: E402


class MockOpenAI:
    """玩具 OpenAI 兼容服务：按剧本返回 tool_calls / 最终文本。"""

    def __init__(self):
        self.port = 0
        self.requests: list[dict] = []
        self.script: list[dict] = []
        self.server = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        data = await reader.read(1 << 20)
        # 极简 HTTP/1.1 解析
        head, _, body = data.partition(b"\r\n\r\n")
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.strip().lower()] = v.strip()
        body = body[: int(headers.get(b"content-length", b"0") or 0)]
        req = json.loads(body or b"{}")
        self.requests.append(req)
        step = self.script[min(len(self.requests) - 1, len(self.script) - 1)]
        if isinstance(step, dict) and step.get("status") == 500:
            body = b'{"error": "internal error"}'
            status = "500 Internal Server Error"
        else:
            step = {"role": "assistant", **step}
            payload = {"choices": [{"message": step}]}
            body = json.dumps(payload).encode()
            status = "200 OK"
        writer.write(
            f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n".encode()
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


@pytest.mark.asyncio
async def test_agent_tool_loop() -> None:
    mock = MockOpenAI()
    mock.script = [
        {
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "run_command",
                        "arguments": json.dumps({"command": "echo hello-agent"}),
                    },
                }
            ],
        },
        {
            "content": None,
            "tool_calls": [
                {
                    "id": "call_2",
                    "type": "function",
                    "function": {"name": "get_system_info", "arguments": "{}"},
                }
            ],
        },
        {"content": "任务完成，一切正常。", "tool_calls": None},
    ]
    await mock.start()

    events: list[dict] = []
    agent = Agent(
        api_key="test-key",
        base_url=f"http://127.0.0.1:{mock.port}/v1",
        model="mock-model",
        executor=Executor(),
        emit=lambda e: events.append(e) if isinstance(e, dict) else None,
    )
    try:
        reply = await agent.chat("帮我看看这台机器")
        assert "任务完成" in reply
    finally:
        await agent.aclose()
        await mock.stop()

    # 事件流：thinking → tool_start → tool_result(×2) → thinking → done 文本
    types = [e["type"] for e in events]
    assert types.count("tool_start") == 2
    assert types.count("tool_result") == 2
    assert types[0] == "thinking"

    # 请求序列：system + user / +assistant+tool / +assistant+tool
    r0 = mock.requests[0]
    roles0 = [m["role"] for m in r0["messages"]]
    assert roles0 == ["system", "user"]
    assert "tools" in r0 and r0["tools"][0]["function"]["name"] == "run_command"

    r1 = mock.requests[1]
    roles1 = [m["role"] for m in r1["messages"]]
    assert roles1 == ["system", "user", "assistant", "tool"]
    assert "hello-agent" in r1["messages"][-1]["content"]

    r2 = mock.requests[2]
    assert [m["role"] for m in r2["messages"]] == [
        "system", "user", "assistant", "tool", "assistant", "tool",
    ]
    assert "发行版" in r2["messages"][-1]["content"]


@pytest.mark.asyncio
async def test_agent_api_error() -> None:
    """API 返回 500 时 agent 应抛出 LLMError。"""
    mock = MockOpenAI()
    mock.script = [{"status": 500}]
    await mock.start()
    agent = Agent(
        api_key="k",
        base_url=f"http://127.0.0.1:{mock.port}/v1",
        model="m",
        executor=Executor(),
    )
    try:
        with pytest.raises(LLMError, match="500"):
            await agent.chat("你好")
    finally:
        await agent.aclose()
        await mock.stop()


@pytest.mark.asyncio
async def test_agent_connection_error() -> None:
    """API 连不上时 agent 应抛出 LLMError。"""
    agent = Agent(
        api_key="k",
        base_url="http://127.0.0.1:1/v1",  # 端口 1 必然连不上
        model="m",
        executor=Executor(),
    )
    try:
        with pytest.raises(LLMError, match="请求 API 失败"):
            await agent.chat("你好")
    finally:
        await agent.aclose()


@pytest.mark.asyncio
async def test_agent_loop_cap() -> None:
    """工具循环超过上限应报错。"""
    mock = MockOpenAI()
    mock.script = [
        {
            "content": None,
            "tool_calls": [
                {
                    "id": f"call_{i}",
                    "type": "function",
                    "function": {"name": "run_command", "arguments": '{"command": "true"}'},
                }
            ],
        }
        for i in range(30)
    ]
    await mock.start()
    agent = Agent(
        api_key="k",
        base_url=f"http://127.0.0.1:{mock.port}/v1",
        model="m",
        executor=Executor(),
        max_tool_rounds=3,
    )
    try:
        with pytest.raises(LLMError):
            await agent.chat("循环测试")
    finally:
        await agent.aclose()
        await mock.stop()


# ---------------------------------------------------------------------------
# 完整白帽会话：侦察 → 发现 flag → FINAL → 自动报告
# ---------------------------------------------------------------------------
class ReconExecutor:
    """nmap 输出端口，read_file 输出 flag。"""

    def __init__(self) -> None:
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        if name == "run_command":
            return "Nmap scan report for target.com\n80/tcp open http nginx\n443/tcp open https"
        if name == "read_file":
            return "flag{integr_42}"
        return "STUB"


@pytest.mark.asyncio
async def test_full_bounty_session_with_auto_report(tmp_path) -> None:
    """侦察工具 → 读 flag → FINAL 引用证据 → 报告自动生成。"""
    server = MockOpenAI()
    server.script = [
        {
            "content": "",
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {"name": "run_command",
                             "arguments": json.dumps({"command": "nmap -sV target.com"})},
            }],
        },
        {
            "content": "",
            "tool_calls": [{
                "id": "call_2",
                "type": "function",
                "function": {"name": "read_file",
                             "arguments": json.dumps({"path": "/flag.txt"})},
            }],
        },
        {"content": "FINAL: flag{integr_42} [e002] 目标存在源码泄露且获得 flag。"},
    ]
    await server.start()
    agent = Agent(
        api_key="test",
        base_url=f"http://127.0.0.1:{server.port}/v1",
        model="test-model",
        executor=ReconExecutor(),
        auto_report=True,
        workdir=str(tmp_path),
    )
    emitted: list[dict] = []
    agent.emit = lambda e: emitted.append(e)
    try:
        reply = await agent.chat("对 target.com 做侦察并找 flag")
    finally:
        await agent.aclose()
        await server.stop()

    # 1) 最终回复含 flag
    assert "flag{integr_42}" in reply

    # 2) 证据链完整（e001 nmap / e002 flag）
    eids = [e.id for e in agent.memory.evidence]
    assert "e001" in eids and "e002" in eids
    assert any(e.tool == "read_file" for e in agent.memory.evidence)

    # 3) flag 被提取为 finding
    assert any(f["type"] == "flag" and "integr_42" in f["value"] for f in agent.memory.findings)

    # 4) 自动报告已生成（auto_report=True）
    reports = list((tmp_path / "DeepKali-reports").glob("*.md"))
    assert reports, "报告文件未生成"
    content = reports[0].read_text(encoding="utf-8")
    assert "flag{integr_42}" in content
    assert "80/tcp" in content or "http" in content  # 侦察时间线含 nmap 结果

    # 5) FINAL 通过证据闸门（flag 逐字符出现在真实输出中）
    assert not any(e.get("type") == "evidence_gate" and e.get("verdict") == "reject"
                   for e in emitted)
