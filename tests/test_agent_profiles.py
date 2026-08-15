"""Agent × 深度定制工具 集成测试：mock API 驱动真实 nmap_scan 调用。"""

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from DeepKali.llm import Agent  # noqa: E402
from DeepKali.tools import Executor  # noqa: E402
from tests.test_agent import MockOpenAI  # noqa: E402


@pytest.mark.asyncio
async def test_agent_calls_custom_tool() -> None:
    """LLM 返回 nmap_scan 调用 → 执行器真实扫描本机 → 结果回填 → LLM 收尾。"""
    mock = MockOpenAI()
    mock.script = [
        {
            "content": None,
            "tool_calls": [
                {
                    "id": "call_nmap",
                    "type": "function",
                    "function": {
                        "name": "nmap_scan",
                        "arguments": json.dumps(
                            {"target": "127.0.0.1", "scan_type": "quick"}
                        ),
                    },
                }
            ],
        },
        {"content": "扫描完成，本机 127.0.0.1 没有发现开放端口。", "tool_calls": None},
    ]
    await mock.start()

    agent = Agent(
        api_key="k",
        base_url=f"http://127.0.0.1:{mock.port}/v1",
        model="m",
        executor=Executor(),
    )
    try:
        reply = await agent.chat("帮我扫描本机")
        assert "扫描完成" in reply
    finally:
        await agent.aclose()
        await mock.stop()

    # 1) schema 已合并进 tools
    r0 = mock.requests[0]
    tool_names = [t["function"]["name"] for t in r0["tools"]]
    assert "nmap_scan" in tool_names
    assert "run_command" in tool_names  # 内置工具仍在

    # 2) 动态 lore 注入：system prompt 应包含 nmap 档案
    sys_msg = r0["messages"][0]["content"]
    assert "nmap 深度使用要点" in sys_msg
    assert "已深度定制的 Kali 工具档案" in sys_msg

    # 3) 工具结果真实回填（真实执行了 nmap）
    r1 = mock.requests[1]
    tool_msg = r1["messages"][-1]
    assert tool_msg["role"] == "tool"
    assert "原始输出" in tool_msg["content"]
    assert "nmap" in tool_msg["content"].lower()


@pytest.mark.asyncio
async def test_agent_lore_only_when_relevant() -> None:
    """无关任务不注入档案 lore（省 token）。"""
    mock = MockOpenAI()
    mock.script = [{"content": "你好，我是助手。", "tool_calls": None}]
    await mock.start()
    agent = Agent(
        api_key="k",
        base_url=f"http://127.0.0.1:{mock.port}/v1",
        model="m",
        executor=Executor(),
    )
    try:
        await agent.chat("你好，帮我算一下 1+1")
    finally:
        await agent.aclose()
        await mock.stop()
    sys_msg = mock.requests[0]["messages"][0]["content"]
    assert "深度使用要点" not in sys_msg
    assert "已深度定制的 Kali 工具档案" in sys_msg  # 工具清单常驻
