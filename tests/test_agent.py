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

from kalitui.llm import Agent, LLMError  # noqa: E402
from kalitui.tools import Executor  # noqa: E402


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
