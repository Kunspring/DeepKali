"""证据记忆与反幻觉闸门测试（VulnClaw 精华移植部分）。

覆盖：
- AgentMemory：证据记录 / 输出去重 / 搜索 / 查看 / 重复调用提示 / 健康跟踪
- 高信号预览：大输出只回填关键行
- pinned facts：SQL / form / endpoint / flag 提取
- CompletionGate：声称的 flag 必须逐字符出现在真实工具输出中
- ReflexionLadder：连续失败后升级提示
- Agent 端到端：FINAL 编造 flag 被闸门拒绝并回灌继续
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kalitui.evidence import (  # noqa: E402
    AgentMemory,
    extract_flags,
    extract_pinned_facts,
    make_high_signal_preview,
)
from kalitui.llm import Agent, CompletionGate, ReflexionLadder  # noqa: E402
from kalitui.tools import Executor  # noqa: E402


# ---------------------------------------------------------------------------
# 证据记忆
# ---------------------------------------------------------------------------
class TestAgentMemory:
    def test_record_and_evidence_text(self):
        mem = AgentMemory()
        rec = mem.record("run_command", {"command": "echo hi"}, "hello world")
        assert rec.id == "e001"
        assert rec.size == len("hello world")
        assert "hello world" in mem.evidence_text()

    def test_same_output_dedup(self):
        mem = AgentMemory()
        r1 = mem.record("run_command", {"command": "nmap -F x"}, "PORT  STATE")
        r2 = mem.record("run_command", {"command": "nmap -F x"}, "PORT  STATE")
        assert r1.id == r2.id == "e001"
        assert len(mem.evidence) == 1

    def test_search_and_view(self):
        mem = AgentMemory()
        mem.record("run_command", {"command": "grep admin"}, "admin user found: root")
        mem.record("run_command", {"command": "curl"}, "HTTP/1.1 200 OK")
        out = mem.search("admin")
        assert "e001" in out
        assert "未找到" not in out
        out2 = mem.search("notexist")
        assert "未找到" in out2
        view = mem.view("e001")
        assert "admin user found" in view
        assert "无此证据" in mem.view("e999")

    def test_list_summary(self):
        mem = AgentMemory()
        mem.record("get_system_info", {}, "Kali GNU/Linux")
        assert "e001" in mem.list_summary()

    def test_repeat_hint(self):
        mem = AgentMemory()
        args = {"command": "ping -c1 1.1.1.1"}
        mem.record("run_command", args, "1 packets transmitted")
        assert mem.repeat_hint("run_command", args) == ""
        mem.record("run_command", args, "1 packets transmitted")  # 相同输出去重但仍计数
        mem.record("run_command", args, "2 packets transmitted")
        assert "已出现" in mem.repeat_hint("run_command", args)

    def test_health_tracking(self):
        mem = AgentMemory()
        mem.record_failure("run_command", {"command": "x"}, "command not found")
        mem.record_failure("run_command", {"command": "x"}, "command not found")
        mem.record_failure("run_command", {"command": "x"}, "command not found")
        assert "连续失败" in mem.health_hint("run_command")
        mem.record("run_command", {"command": "ok"}, "fine")
        assert mem.health_hint("run_command") == ""

    def test_stall_hint(self):
        mem = AgentMemory()
        assert mem.stall_hint() == ""  # 无证据不提示
        mem.record("run_command", {"command": "a"}, "out1")
        assert mem.stall_hint() == ""  # 有新证据
        assert "stall guard" in mem.stall_hint()  # 无新证据


# ---------------------------------------------------------------------------
# 高信号预览与事实提取
# ---------------------------------------------------------------------------
class TestHighSignal:
    def test_preview_small_output_unchanged(self):
        text = "short output"
        assert make_high_signal_preview(text) == text

    def test_preview_large_output_keeps_key_lines(self):
        big = ("plain filler line\n" * 600) + "admin login found\npassword=secret\n" + ("x" * 300)
        preview = make_high_signal_preview(big)
        assert "high-signal preview" in preview
        assert "admin login found" in preview
        assert "raw_size=" in preview

    def test_extract_flags(self):
        assert extract_flags("here is flag{abc_123} and ctf{x}") == ["flag{abc_123}", "ctf{x}"]
        assert extract_flags("no flags here") == []

    def test_pinned_facts_sql_and_form(self):
        facts = extract_pinned_facts(
            "SELECT user FROM users WHERE id=$_GET['id']\n"
            "<form method=POST action=/login><input name=pass>"
        )
        joined = " ".join(facts)
        assert "Source SQL" in joined
        assert "HTML form" in joined
        assert "HTML input" in joined

    def test_pinned_facts_url_and_flag(self):
        facts = extract_pinned_facts("visit http://target.local/api/flag and got flag{x1}")
        joined = " ".join(facts)
        assert "flag{x1}" in joined
        assert "http://target.local/api/flag" in joined


# ---------------------------------------------------------------------------
# 反幻觉闸门
# ---------------------------------------------------------------------------
class TestCompletionGate:
    def make_memory(self, output: str) -> AgentMemory:
        mem = AgentMemory()
        mem.record("run_command", {"command": "cat flag"}, output)
        return mem

    def test_fake_flag_rejected(self):
        mem = self.make_memory("real content only, no flag")
        gate = CompletionGate(mem, goal="拿到 flag")
        ok, reason = gate.check("FINAL: 我拿到了 flag{fake_claim}")
        assert not ok
        assert "未在真实工具输出中出现" in reason

    def test_grounded_flag_passes(self):
        mem = self.make_memory("result: flag{real_42}")
        gate = CompletionGate(mem, goal="拿到 flag")
        ok, reason = gate.check("FINAL: 拿到了 flag{real_42} [e001]")
        assert ok, reason

    def test_unknown_evidence_id_rejected(self):
        mem = self.make_memory("whatever")
        gate = CompletionGate(mem, goal="")
        ok, reason = gate.check("FINAL: 结论 [e999]")
        assert not ok
        assert "e999" in reason

    def test_no_evidence_rejected(self):
        gate = CompletionGate(AgentMemory(), goal="测试")
        ok, reason = gate.check("FINAL: 完成了")
        assert not ok
        assert "没有任何工具证据" in reason

    def test_citation_passes(self):
        mem = self.make_memory("port 22 open ssh")
        gate = CompletionGate(mem, goal="扫描端口")
        ok, reason = gate.check("FINAL: 22 端口开放 [e001]")
        assert ok, reason

    def test_quoted_evidence_token_passes(self):
        mem = self.make_memory("Apache/2.4.25 (Debian)")
        gate = CompletionGate(mem, goal="指纹识别")
        ok, reason = gate.check("FINAL: 服务器是 Apache/2.4.25")
        assert ok, reason

    def test_fabricated_claim_without_quote_rejected(self):
        mem = self.make_memory("Apache/2.4.25 (Debian)")
        gate = CompletionGate(mem, goal="指纹识别")
        ok, reason = gate.check("FINAL: 服务器是 Nginx/9.9.9")
        assert not ok
        assert "没有引用任何证据" in reason


# ---------------------------------------------------------------------------
# 反思升级
# ---------------------------------------------------------------------------
class TestReflexion:
    def test_no_prompt_before_failures(self):
        ladder = ReflexionLadder()
        assert ladder.prompt_block() == ""

    def test_escalation_levels(self):
        ladder = ReflexionLadder()
        ladder.record_failure("payload1")
        assert ladder.level() == 0
        ladder.record_failure("payload1")
        assert ladder.level() == 1
        block = ladder.prompt_block()
        assert "反思升级" in block
        ladder.record_success()
        assert ladder.prompt_block() == ""


# ---------------------------------------------------------------------------
# Agent 端到端：证据闸门拒绝编造 flag 并回灌继续
# ---------------------------------------------------------------------------
class FakeExecutor:
    """假执行器：read_file 返回真实 flag，供闸门校验。"""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        self.calls.append((name, arguments))
        if name == "read_file":
            return "/tmp/flag 内容: flag{grounded_42}"
        return "unknown tool"


class MockGateServer:
    """剧本：第 1 轮返回工具调用（read_file，输出含真实 flag），
    第 2 轮返回编造 flag 的 FINAL → 应被闸门拒绝并回灌，
    第 3 轮返回引用证据的正确结论。"""

    def __init__(self):
        self.port = 0
        self.requests: list[dict] = []
        self.server = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        data = await reader.read(1 << 20)
        head, _, body = data.partition(b"\r\n\r\n")
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.strip().lower()] = v.strip()
        length = int(headers.get(b"content-length", b"0") or 0)
        while len(body) < length:  # 大请求体可能分多个 TCP 包
            chunk = await reader.read(1 << 20)
            if not chunk:
                break
            body += chunk
        body = body[:length]
        req = json.loads(body or b"{}")
        self.requests.append(req)
        n = len(self.requests)
        # 检查是否已被闸门回灌（第 3 次请求的 messages 应含"证据闸门"）
        if n == 1:
            step = {
                "role": "assistant",
                "content": "先看文件",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": json.dumps({"path": "/tmp/flag"})},
                }],
            }
        elif n == 2:
            step = {"role": "assistant", "content": "FINAL: flag{invented}"}
        else:
            # 被闸门拒绝后：返回引用证据的正确结论
            step = {"role": "assistant", "content": "FINAL: 拿到 flag{grounded_42} [e001]"}
        payload = {"choices": [{"message": step}]}
        writer.write(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n".encode()
            + f"Content-Length: {len(json.dumps(payload).encode())}\r\n\r\n".encode()
            + json.dumps(payload).encode()
        )
        await writer.drain()
        writer.close()

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


@pytest.mark.asyncio
async def test_agent_gate_rejects_fake_flag_and_retries():
    server = MockGateServer()
    await server.start()
    agent = Agent(
        api_key="test",
        base_url=f"http://127.0.0.1:{server.port}/v1",
        model="test-model",
        executor=FakeExecutor(),
        auto_report=False,
    )
    events: list[str] = []
    agent.emit = lambda e: events.append(e["type"])

    try:
        reply = await agent.chat("读一下 /tmp/flag 拿到 flag")
    finally:
        await agent.aclose()
        await server.stop()

    assert "flag{grounded_42}" in reply
    # 闸门拒绝过编造的 flag
    assert "evidence_gate" in events
    # 回灌消息包含"证据闸门"
    assert any("证据闸门" in str(m.get("content", "")) for m in agent.messages)
    # 证据已记录（含真实 flag）
    assert agent.memory.evidence
    assert "flag{grounded_42}" in agent.memory.evidence_text()


@pytest.mark.asyncio
async def test_evidence_tools_work_end_to_end():
    """evidence_list/view/search 工具直接查记忆，不经过 executor。"""
    server = MockGateServer()
    await server.start()
    agent = Agent(
        api_key="test",
        base_url=f"http://127.0.0.1:{server.port}/v1",
        model="test-model",
        executor=Executor(danger_policy="always_allow"),
        auto_report=False,
    )
    try:
        agent.memory.record("run_command", {"command": "ls"}, "flag file: secret.txt")
        out_list, ok1 = await agent._execute_tool("evidence_list", {})
        assert ok1 and "e001" in out_list
        out_view, ok2 = await agent._execute_tool("evidence_view", {"evidence_id": "e001"})
        assert ok2 and "secret.txt" in out_view
        out_search, ok3 = await agent._execute_tool("evidence_search", {"query": "flag"})
        assert ok3 and "e001" in out_search
    finally:
        await agent.aclose()
        await server.stop()


# ---------------------------------------------------------------------------
# 过早 ASK_USER 闸门（VulnClaw ask_user guard 移植）
# ---------------------------------------------------------------------------
class MockAskServer:
    """剧本：第 1 轮 read_file 拿到含表单的高信号证据；
    第 2 轮模型想提前问"要不要继续测？"（非阻塞）→ 应被拒绝并回灌；
    第 3 轮给出最终结论。"""

    def __init__(self):
        self.port = 0
        self.requests: list[dict] = []
        self.server = None
        self.script: list[dict] = []  # 兼容统一 handler

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        data = await reader.read(1 << 20)
        head, _, body = data.partition(b"\r\n\r\n")
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.strip().lower()] = v.strip()
        length = int(headers.get(b"content-length", b"0") or 0)
        while len(body) < length:
            chunk = await reader.read(1 << 20)
            if not chunk:
                break
            body += chunk
        req = json.loads(body[:length] or b"{}")
        self.requests.append(req)
        n = len(self.requests)
        if self.script:
            step = {"role": "assistant", **self.script[min(n - 1, len(self.script) - 1)]}
        elif n == 1:
            step = {
                "role": "assistant",
                "content": "先看页面",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": json.dumps({"path": "/tmp/page.html"})},
                }],
            }
        elif n == 2:
            step = {"role": "assistant", "content": "ASK_USER: 要不要继续测试？"}
        else:
            step = {"role": "assistant", "content": "FINAL: 页面含登录表单 [e001]"}
        payload = {"choices": [{"message": step}]}
        writer.write(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n".encode()
            + f"Content-Length: {len(json.dumps(payload).encode())}\r\n\r\n".encode()
            + json.dumps(payload).encode()
        )
        await writer.drain()
        writer.close()

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class FakePageExecutor:
    """read_file 返回含表单/接口的高信号页面。"""

    def __init__(self) -> None:
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        return (
            "<html><form action=/login method=POST>"
            "<input name=user><input name=pass></form>"
            "<script>fetch('/api/user?id=1')</script></html>"
        )


@pytest.mark.asyncio
async def test_ask_user_gate_rejects_premature_question():
    server = MockAskServer()
    await server.start()
    agent = Agent(
        api_key="test",
        base_url=f"http://127.0.0.1:{server.port}/v1",
        model="test-model",
        executor=FakePageExecutor(),
        auto_report=False,
    )
    events: list[str] = []
    agent.emit = lambda e: events.append(e["type"])

    try:
        reply = await agent.chat("分析一下这个页面")
    finally:
        await agent.aclose()
        await server.stop()

    # 最终返回的是通过闸门的 FINAL 结论（而非过早的提问）
    assert "登录表单" in reply
    # 过早提问被闸门拒绝过
    assert "evidence_gate" in events
    assert any("过早提问闸门" in str(m.get("content", "")) for m in agent.messages)
    # 高信号事实（表单）已固定
    assert any("HTML form" in f for f in agent.memory.pinned_facts)


@pytest.mark.asyncio
async def test_ask_user_real_blocker_passes_through():
    """真阻塞（授权/凭证类）问题不被闸门拦截，剥离标记返回。"""
    from kalitui.llm import Agent as A

    server = MockAskServer()
    await server.start()
    agent = A(
        api_key="test",
        base_url=f"http://127.0.0.1:{server.port}/v1",
        model="test-model",
        executor=FakePageExecutor(),
        auto_report=False,
    )
    # 直接测 _finalize：有证据 + 真阻塞问题
    agent.memory.record("read_file", {"path": "/tmp/x"}, "<form action=/login>")
    reply = await agent._finalize("ASK_USER: 请确认这个目标是否在你的授权范围内？")
    assert "授权范围" in reply
    assert "ASK_USER" not in reply  # 标记已剥离
    await agent.aclose()
    await server.stop()


# ---------------------------------------------------------------------------
# 横向移动 lore
# ---------------------------------------------------------------------------
class TestLateralLore:
    def _lore(self, history: list[dict]) -> str:
        from kalitui.profiles import lore_for

        return lore_for(history)

    def test_trigger_on_lateral(self):
        lore = self._lore([{"role": "user", "content": "拿到 shell 了，帮我横向移动进内网"}])
        assert "内网横向移动路线" in lore
        assert "PTH" in lore
        assert "chisel" in lore

    def test_trigger_on_pth(self):
        lore = self._lore([{"role": "user", "content": "有 hash 了，试试 pass the hash"}])
        assert "内网横向移动路线" in lore

    def test_not_triggered_on_scan(self):
        lore = self._lore([{"role": "user", "content": "扫描端口"}])
        assert "内网横向移动路线" not in lore

    def test_registered_without_tools(self):
        from kalitui.profiles import REGISTRY, all_schemas

        assert "lateral" in {p.name for p in REGISTRY}
        assert all(s["function"]["name"] != "lateral" for s in all_schemas())


# ---------------------------------------------------------------------------
# 上下文预算压缩（长任务防上下文超限）
# ---------------------------------------------------------------------------
class TestContextCompress:
    def _make_agent(self):
        from kalitui.llm import Agent as A

        return A(
            api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
            executor=FakeExecutor(), auto_report=False,
        )

    def _fill_messages(self, agent, rounds: int) -> None:
        """构造 rounds 组 assistant(tool_calls)+tool 消息。"""
        agent.messages.append({"role": "user", "content": "任务目标"})
        for i in range(rounds):
            agent.messages.append({
                "role": "assistant", "content": "",
                "tool_calls": [{
                    "id": f"c{i}", "type": "function",
                    "function": {"name": "read_file", "arguments": "{}"},
                }],
            })
            agent.messages.append({"role": "tool", "tool_call_id": f"c{i}", "content": f"out{i}"})

    def test_compress_keeps_goal_and_pairs(self):
        agent = self._make_agent()
        self._fill_messages(agent, 60)  # 60*2+1 = 121 条
        removed = agent._compress_messages(limit=50)
        assert removed > 0
        assert len(agent.messages) <= 52
        # 首条仍是任务目标
        assert agent.messages[0]["role"] == "user"
        assert agent.messages[0]["content"] == "任务目标"
        # 压缩提示已插入
        assert any("上下文压缩" in str(m.get("content", "")) for m in agent.messages)
        # tool 消息必须紧跟在带 tool_calls 的 assistant 之后（无孤儿）
        expect_tool = False
        for m in agent.messages:
            if m.get("role") == "assistant":
                expect_tool = bool(m.get("tool_calls"))
            elif m.get("role") == "tool":
                assert expect_tool, "孤儿 tool 消息"
                expect_tool = False
        assert not expect_tool

    def test_no_compress_when_under_limit(self):
        agent = self._make_agent()
        self._fill_messages(agent, 10)
        assert agent._compress_messages(limit=50) == 0
        assert len(agent.messages) == 21

    def test_compress_skips_plain_assistant(self):
        """纯文本 assistant 消息（无 tool_calls）不被当作轮次裁剪。"""
        agent = self._make_agent()
        agent.messages = [{"role": "user", "content": "目标"}]
        for i in range(30):
            agent.messages.append({"role": "assistant", "content": f"text{i}"})
            agent.messages.append({"role": "user", "content": f"q{i}"})
        removed = agent._compress_messages(limit=50)
        assert removed == 0
        # 无 tool_calls 的 assistant 不删；但整体仍超限时由后续逻辑兜底
        assert len(agent.messages) > 50


class TestTokenCompress:
    def _make_agent(self):
        from kalitui.llm import Agent as A

        return A(
            api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
            executor=FakeExecutor(), auto_report=False,
        )

    def test_token_estimate(self):
        agent = self._make_agent()
        agent.messages = [{"role": "user", "content": "目标"}]
        assert agent._estimate_tokens() >= 4
        agent.messages.append({"role": "tool", "content": "x" * 2000})
        assert agent._estimate_tokens() >= 1000

    def test_compress_by_tokens_even_under_count_limit(self):
        """条数不超但单条巨大 → token 阈值触发压缩。"""
        agent = self._make_agent()
        agent.messages.append({"role": "user", "content": "目标"})
        # 10 轮，每轮 tool 输出 20k 字符 ≈ 1 万 token
        for i in range(10):
            agent.messages.append({
                "role": "assistant", "content": "",
                "tool_calls": [{"id": f"c{i}", "type": "function",
                                "function": {"name": "run_command", "arguments": "{}"}}],
            })
            agent.messages.append({"role": "tool", "tool_call_id": f"c{i}", "content": "A" * 20000})
        removed = agent._compress_messages(limit=50, token_limit=10000)
        assert removed > 0
        assert agent._estimate_tokens() <= 11000  # 压到阈值附近
        # 配对完整性保持
        expect_tool = False
        for m in agent.messages:
            if m.get("role") == "assistant":
                expect_tool = bool(m.get("tool_calls"))
            elif m.get("role") == "tool":
                assert expect_tool
                expect_tool = False

    def test_small_session_not_compressed(self):
        agent = self._make_agent()
        agent.messages = [{"role": "user", "content": "目标"}]
        assert agent._compress_messages(limit=50, token_limit=60000) == 0

    def test_request_calls_compress_with_default_token_limit(self):
        """_request 自动带默认 token 阈值调用压缩。"""
        agent = self._make_agent()
        agent.messages = [{"role": "user", "content": "目标"}]
        for i in range(30):
            agent.messages.append({
                "role": "assistant", "content": "",
                "tool_calls": [{"id": f"c{i}", "type": "function",
                                "function": {"name": "run_command", "arguments": "{}"}}],
            })
            agent.messages.append({"role": "tool", "tool_call_id": f"c{i}", "content": "B" * 5000})
        # 直接用默认参数（模拟 _request 调用）
        removed = agent._compress_messages()
        assert removed > 0
        assert agent._estimate_tokens() <= 60000 + 4000


# ---------------------------------------------------------------------------
# findings CSV 导出
# ---------------------------------------------------------------------------
class TestFindingsExport:
    def _make_agent(self):
        from kalitui.llm import Agent as A

        return A(
            api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
            executor=FakeExecutor(), auto_report=False,
        )

    def test_export_csv(self, tmp_path):
        agent = self._make_agent()
        agent.memory.record("run_command", {"command": "x"}, "flag{a} CVE-2024-9999")
        agent.memory.record("curl", {"url": "http://t.com/"}, "HTTP/1.1 500 Internal")
        path = agent.export_findings_csv(str(tmp_path / "f.csv"))
        content = open(path, encoding="utf-8-sig").read()
        rows = [r for r in content.splitlines() if r]
        assert rows[0] == "severity,type,value,target,evidence"
        # 严重度降序：flag(5) > cve(4) > http_error(1)
        assert rows[1].startswith("5,flag,")
        assert rows[2].startswith("4,cve,")
        assert rows[3].startswith("1,http_error,")
        # target 列：http_error 来自 url 参数 → 目标 http://t.com/
        assert "http://t.com/" in rows[3]

    def test_export_empty(self, tmp_path):
        agent = self._make_agent()
        path = agent.export_findings_csv(str(tmp_path / "f.csv"))
        content = open(path, encoding="utf-8-sig").read()
        assert content.strip() == "severity,type,value,target,evidence"


# ---------------------------------------------------------------------------
# ASK_USER 空问题剥标记 + 报告后续建议
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ask_user_empty_question_strips_marker() -> None:
    """ASK_USER 后无内容：返回剥离标记的文本，不留前缀。"""
    from kalitui.llm import Agent as A

    agent = A(
        api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
        executor=FakeExecutor(), auto_report=False,
    )
    # 无证据场景：不触发回灌（无需 API），直接剥离标记返回
    reply = await agent._finalize("ASK_USER:")
    assert "ASK_USER" not in reply
    assert reply == ""  # 剥离后为空文本

    # 带文本时返回剥离后的问题
    reply2 = await agent._finalize("ASK_USER: 需要确认目标")
    assert reply2 == "需要确认目标"
    await agent.aclose()


class TestReportGaps:
    def _make_agent(self):
        from kalitui.llm import Agent as A

        return A(
            api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
            executor=FakeExecutor(), auto_report=False,
        )

    def test_report_includes_followup_section(self, tmp_path):
        agent = self._make_agent()
        agent._last_goal = "测试目标"
        agent.memory.record("run_command", {"command": "nmap t.com"}, "80/tcp open http")
        path = agent.write_report("没发现漏洞", path=str(tmp_path / "r.md"))
        content = open(path, encoding="utf-8").read()
        assert "## 后续建议" in content
        assert "sql" in content  # 未探索方向列出

    def test_report_gaps_only_unexplored(self, tmp_path):
        agent = self._make_agent()
        agent.memory.record("read_file", {"path": "/tmp/x"},
                            "<form action=/login><input name=user><script>fetch('/api/x')</script> SQL error")
        path = agent.write_report("done", path=str(tmp_path / "r2.md"))
        content = open(path, encoding="utf-8").read()
        # 已探索方向（sql/form/endpoint/api）不进后续建议；未探索的 admin 会列出
        assert "## 后续建议" in content
        section = content.split("## 后续建议")[1].split("## 工具调用")[0].lower()
        assert "sql" not in section
        assert "admin" in section

    def test_gaps_method(self):
        from kalitui.evidence import AgentMemory

        mem = AgentMemory()
        assert set(mem.attack_surface_gaps()) >= {"sql", "form", "flag"}
        mem.record("read_file", {"path": "/tmp/x"}, "<form action=/login> SQL error")
        assert "sql" not in mem.attack_surface_gaps()
        assert "form" not in mem.attack_surface_gaps()


# ---------------------------------------------------------------------------
# llm.py 覆盖率补测：闸门分支 / 回灌工具循环 / 报告截断 / 异常路径
# ---------------------------------------------------------------------------
class FakeApproveExecutor(FakeExecutor):
    """execute 抛 NeedsApproval（模拟危险命令被安全层拦截）。"""

    async def execute(self, name, arguments):
        if name == "run_command":
            from kalitui.tools import NeedsApproval

            raise NeedsApproval("hydra -l admin -P x 127.0.0.1", "confirm", "危险命令")
        return await super().execute(name, arguments)


@pytest.mark.asyncio
async def test_execute_tool_needs_approval_path():
    """_execute_tool 捕获 NeedsApproval → 返回说明文本。"""
    from kalitui.llm import Agent as A

    agent = A(
        api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
        executor=FakeApproveExecutor(), auto_report=False,
    )
    out, ok = await agent._execute_tool("run_command", {"command": "hydra x"})
    assert ok is True
    assert "需要用户确认" in out or "未执行" in out or "危险" in out
    await agent.aclose()


class MockGateToolLoopServer:
    """剧本：第 1 轮工具调用（run_command）→ 第 2 轮想 FINAL 假 flag → 被拒 →
    回灌（_retry_after_gate）内再做工具调用 → 最终给出引用证据的结论。"""

    def __init__(self):
        self.port = 0
        self.requests: list[dict] = []
        self.server = None
        self.script: list[dict] = []  # 非空时优先于内置剧本

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        data = await reader.read(1 << 20)
        head, _, body = data.partition(b"\r\n\r\n")
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.strip().lower()] = v.strip()
        length = int(headers.get(b"content-length", b"0") or 0)
        while len(body) < length:
            chunk = await reader.read(1 << 20)
            if not chunk:
                break
            body += chunk
        req = json.loads(body[:length] or b"{}")
        self.requests.append(req)
        n = len(self.requests)
        if self.script:
            step = {"role": "assistant", **self.script[min(n - 1, len(self.script) - 1)]}
        elif n == 1:
            step = {
                "role": "assistant", "content": "",
                "tool_calls": [{
                    "id": "call_a",
                    "type": "function",
                    "function": {"name": "run_command", "arguments": json.dumps({"command": "ls /tmp"})},
                }],
            }
        elif n == 2:
            step = {"role": "assistant", "content": "FINAL: flag{fake_gate}"}
        elif n == 3:
            # 回灌后：再做一次工具调用
            step = {
                "role": "assistant", "content": "",
                "tool_calls": [{
                    "id": "call_b",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": json.dumps({"path": "/tmp/target.txt"})},
                }],
            }
        else:
            step = {"role": "assistant", "content": "FINAL: flag{real_one} [e002]"}
        payload = {"choices": [{"message": step}]}
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(json.dumps(payload).encode())}\r\n\r\n".encode()
            + json.dumps(payload).encode()
        )
        await writer.drain()
        writer.close()

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class ToolLoopExecutor:
    """run_command 输出普通文本；read_file 输出真实 flag。"""

    def __init__(self) -> None:
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        if name == "run_command":
            return "普通输出"
        if name == "read_file":
            return "flag{real_one} 在这里"
        return "STUB"


@pytest.mark.asyncio
async def test_retry_gate_tool_loop_and_real_flag():
    """回灌循环内继续工具调用，最终引用证据通过闸门。"""
    server = MockGateToolLoopServer()
    await server.start()
    agent = Agent(
        api_key="test",
        base_url=f"http://127.0.0.1:{server.port}/v1",
        model="test-model",
        executor=ToolLoopExecutor(),
        auto_report=False,
    )
    events: list[str] = []
    agent.emit = lambda e: events.append(e["type"])
    try:
        reply = await agent.chat("帮我拿 flag")
    finally:
        await agent.aclose()
        await server.stop()

    assert "flag{real_one}" in reply
    assert "evidence_gate" in events  # 假 flag 被拒过
    # 回灌内工具调用已执行（read_file 产生 e002）
    assert any(e.id == "e002" and e.tool == "read_file" for e in agent.memory.evidence)


def test_impact_level_vuln_marker():
    from kalitui.llm import Agent as A

    agent = A(
        api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
        executor=FakeExecutor(), auto_report=False,
    )
    agent.memory.record("run_command", {"command": "x"}, "检测到注入特征")
    assert "中" in agent._impact_level()


def test_write_report_truncates_large_evidence(tmp_path):
    """大证据在报告里显示截断提示。"""
    from kalitui.llm import Agent as A

    agent = A(
        api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
        executor=FakeExecutor(), auto_report=False,
    )
    big = "A" * 20000
    agent.memory.record("run_command", {"command": "cat"}, big)
    path = agent.write_report("完成", path=str(tmp_path / "r.md"))
    content = open(path, encoding="utf-8").read()
    assert "已截断" in content


def test_token_estimate_non_text_content():
    """非文本 content（list 等）按保守 200 估算。"""
    from kalitui.llm import Agent as A

    agent = A(
        api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
        executor=FakeExecutor(), auto_report=False,
    )
    agent.messages = [{"role": "user", "content": ["a", "b"]}]
    assert agent._estimate_tokens() >= 200


def test_gate_goal_wants_flag_but_no_flag():
    """目标要求 flag，结论没给 flag → 拒绝。"""
    from kalitui.llm import CompletionGate

    gate = CompletionGate(AgentMemory(), goal="帮我拿 flag")
    ok, reason = gate.check("FINAL: 没找到")
    assert not ok
    assert "flag" in reason.lower()


def test_save_state_oserror_returns_false():
    """resume_path 不可写 → save_state 返回 False 不抛。"""
    from kalitui.llm import Agent as A

    agent = A(
        api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
        executor=FakeExecutor(), auto_report=False,
    )
    agent.resume_path = "/proc/1/nonexistent/resume.json"
    assert agent.save_state() is False


def test_export_default_path(tmp_path):
    """export_findings_csv 默认输出到 workdir/kalitui-reports/findings.csv。"""
    from kalitui.llm import Agent as A

    agent = A(
        api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
        executor=FakeExecutor(), auto_report=False,
        workdir=str(tmp_path),
    )
    agent.memory.record("run_command", {"command": "x"}, "flag{export_one}")
    path = agent.export_findings_csv()
    assert path.endswith("kalitui-reports/findings.csv")
    assert "flag{export_one}" in open(path, encoding="utf-8-sig").read()


class MockEmptyChoicesServer:
    """返回 200 但 choices 为空的畸形响应 → LLMError。"""

    def __init__(self):
        self.port = 0
        self.server = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        await reader.read(1 << 20)
        payload = {"choices": []}
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(json.dumps(payload).encode())}\r\n\r\n".encode()
            + json.dumps(payload).encode()
        )
        await writer.drain()
        writer.close()

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


@pytest.mark.asyncio
async def test_api_empty_choices_raises():
    """API 返回空 choices → LLMError（不再继续）。"""
    from kalitui.llm import Agent as A, LLMError

    server = MockEmptyChoicesServer()
    await server.start()
    agent = A(
        api_key="test",
        base_url=f"http://127.0.0.1:{server.port}/v1",
        model="m",
        executor=FakeExecutor(),
        auto_report=False,
    )
    try:
        with pytest.raises(LLMError):
            await agent.chat("hello")
    finally:
        await agent.aclose()
        await server.stop()


def test_domain_facts_extraction():
    """crt.sh 摘要的裸域名行提取为 Subdomain 事实。"""
    from kalitui.evidence import extract_pinned_facts

    text = (
        "关键结果：\n"
        "📜 证书日志子域 (3 个，来自 crt.sh):\n"
        "  vpn.example.com\n"
        "  admin.Example.COM\n"
        "  staging.example.com\n"
        "下一步：对高价值子域做存活探测。\n"
    )
    facts = extract_pinned_facts(text)
    subs = [f for f in facts if f.startswith("Subdomain:")]
    assert "Subdomain: vpn.example.com" in subs
    assert "Subdomain: admin.example.com" in subs  # 大小写归一
    assert "Subdomain: staging.example.com" in subs
    # 噪音行不提取
    assert not any("下一步" in f for f in subs)


def test_domain_facts_ignores_urls_ips_and_json():
    """URL/IP/JSON 行不误提取为 Subdomain。"""
    from kalitui.evidence import extract_pinned_facts

    text = (
        "https://vpn.example.com [200] [VPN] [nginx]\n"
        "10.0.0.5\n"
        '"name_value": "x.example.com"\n'
        "www.example.com\n"
    )
    facts = extract_pinned_facts(text)
    subs = [f for f in facts if f.startswith("Subdomain:")]
    assert subs == []  # URL 行有 http 前缀；IP 最后段是数字；JSON 行带引号；www 排除


def test_crtsh_output_pins_domains():
    """crt_sh 工具摘要经 memory.record 后域名进 pinned facts。"""
    from kalitui.evidence import AgentMemory

    mem = AgentMemory()
    mem.record(
        "run_command",
        {"command": "curl crt.sh"},
        "关键结果：\n📜 证书日志子域 (2 个):\n  vpn.example.com\n  admin.example.com",
    )
    pinned = mem.pinned_facts
    assert any(f == "Subdomain: vpn.example.com" for f in pinned)
    assert any(f == "Subdomain: admin.example.com" for f in pinned)


def test_impact_level_all_branches():
    """_impact_level 五种发现组合分支。"""
    from kalitui.llm import Agent as A

    agent = A(
        api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
        executor=FakeExecutor(), auto_report=False,
    )
    assert "信息" in agent._impact_level()  # 无发现
    agent.memory.record("run_command", {"command": "x"}, "HTTP/1.1 500 Internal")
    assert "低" in agent._impact_level()    # http_error
    agent.memory.record("run_command", {"command": "x"}, "CVE-2024-9999")
    assert "中-高" in agent._impact_level()  # cve 优先于 http_error
    agent.memory.record("run_command", {"command": "x"}, "检测到注入特征")
    assert "中" in agent._impact_level()    # vuln_marker
    agent.memory.record("run_command", {"command": "x"}, "flag{impact_x}")
    assert "高" in agent._impact_level()    # flag 最高


def test_reproduction_steps_bad_arguments():
    """arguments 不可 JSON 序列化 → 回退 str()。"""
    from kalitui.llm import Agent as A

    agent = A(
        api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
        executor=FakeExecutor(), auto_report=False,
    )
    agent.memory.record("run_command", {"command": object()}, "out")
    steps = agent._reproduction_steps()
    assert len(steps) == 1
    assert "执行 `run_command`" in steps[0]


# ---------------------------------------------------------------------------
# 闸门多次失败停止回灌路径（LLM 连续无证据结论）
# ---------------------------------------------------------------------------
class _StubbornLLMServer:
    """总是返回无证据的 FINAL 结论（闸门必拒）。"""

    def __init__(self):
        self.port = 0
        self.server = None
        self.calls = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        data = await reader.read(1 << 20)
        _head, _, body = data.partition(b"\r\n\r\n")
        self.calls += 1
        if self.calls == 1:
            # 第一轮先执行工具（产生证据），之后每轮都返回无证据 FINAL
            message = {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": "call_stub",
                    "type": "function",
                    "function": {"name": "run_command",
                                 "arguments": json.dumps({"command": "x"})},
                }],
            }
        else:
            message = {"role": "assistant", "content": "FINAL: 完成！"}
        payload = {"choices": [{"message": message}]}
        body = json.dumps(payload).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
        )
        await writer.drain()
        writer.close()

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


@pytest.mark.asyncio
async def test_gate_stops_reinjection_after_two_retries():
    """连续无证据 FINAL 被拒 3 次 → 第 3 次返回停止注释（防递归）。"""
    from kalitui.llm import Agent as A

    server = _StubbornLLMServer()
    await server.start()
    agent = A(
        api_key="x", base_url=f"http://127.0.0.1:{server.port}/v1", model="m",
        executor=ToolLoopExecutor(), auto_report=False,
    )
    emitted: list[dict] = []
    agent.emit = lambda e: emitted.append(e)
    try:
        reply = await agent.chat("测试目标")
    finally:
        await agent.aclose()
        await server.stop()

    assert "已停止回灌" in reply
    assert "未通过证据闸门" in reply
    rejects = [e for e in emitted if e.get("type") == "evidence_gate" and e.get("verdict") == "reject"]
    assert len(rejects) >= 3  # 至少 3 次拒绝后才停止


# ---------------------------------------------------------------------------
# 边界分支：上限截断 / 空提示 / 异常回退
# ---------------------------------------------------------------------------
def test_important_lines_limit_break():
    """高信号行超过 limit → 截断到 limit。"""
    from kalitui.evidence import _important_lines

    raw = "\n".join(f"flag mention line {i}" for i in range(30))
    lines = _important_lines(raw, limit=10)
    assert len(lines) == 10


def test_sql_and_js_endpoint_limits():
    """SQL/JS endpoint 提取上限 break。"""
    from kalitui.evidence import _extract_js_endpoint_facts, _extract_sql_facts

    sql = "\n".join(
        f"SELECT * FROM users WHERE id={i} LIMIT 1" for i in range(10)
    )
    assert len(_extract_sql_facts(sql)) == 4

    js = "\n".join(f"fetch('/api/endpoint{i}?x=1')" for i in range(10))
    assert len(_extract_js_endpoint_facts(js)) == 6


def test_pinned_facts_and_evidence_caps():
    """pinned facts 与 evidence 存储上限截断。"""
    from kalitui.evidence import MAX_PINNED_FACTS, AgentMemory

    mem = AgentMemory()
    # 大量不同 flag 输出 → evidence 超限后保留尾部
    for i in range(250):
        mem.record("run_command", {"command": f"x{i}"}, f"out {i}")
    assert len(mem.evidence) <= 240
    # 大量 SQL 事实 → pinned 截断到上限
    mem2 = AgentMemory()
    for i in range(60):
        mem2.record("curl", {"url": f"http://t/{i}"},
                    f"SELECT * FROM users WHERE id={i} LIMIT 1")
    assert len(mem2.pinned_facts) <= MAX_PINNED_FACTS


def test_list_summary_empty():
    """无证据时 list_summary 占位提示。"""
    from kalitui.evidence import AgentMemory

    mem = AgentMemory()
    assert mem.list_summary() == "（还没有任何证据）"


def test_attack_surface_summary_no_evidence():
    """攻击面快照无证据时走"扩大侦察"建议分支。"""
    from kalitui.evidence import AgentMemory

    mem = AgentMemory()
    s = mem.attack_surface_summary()
    assert "先做侦察" in s


def test_repeat_hint_json_fallback():
    """arguments 不可 JSON 序列化 → 回退 str() 不抛。"""
    from kalitui.evidence import AgentMemory

    mem = AgentMemory()
    mem.record("run_command", {"cmd": object()}, "out1")
    mem._note_call("run_command", {"cmd": object()})
    # 不抛异常即可
    assert isinstance(mem.repeat_hint("run_command", {"cmd": object()}), str)


# ---------------------------------------------------------------------------
# llm.py 剩余分支：坏 JSON 参数 / ToolError / 大输出预览 / 反思升级注入
# ---------------------------------------------------------------------------
class _BranchExecutor:
    """按工具名返回不同行为。"""

    def __init__(self) -> None:
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        if name == "big_out":
            return "x" * 8000
        if name == "boom_tool":
            from kalitui.tools import ToolError

            raise ToolError("内部错误: 测试失败")
        return "普通输出"


@pytest.mark.asyncio
async def test_bad_json_arguments_fallback():
    """tool_call arguments 坏 JSON → 兜底 _raw 不崩。"""
    server = MockGateToolLoopServer()
    server.script = [
        {"content": "", "tool_calls": [{
            "id": "c1", "type": "function",
            "function": {"name": "run_command", "arguments": "{bad json"},
        }]},
        {"content": "FINAL: 完成 [e001]"},
    ]
    await server.start()
    agent = Agent(
        api_key="x", base_url=f"http://127.0.0.1:{server.port}/v1", model="m",
        executor=ToolLoopExecutor(), auto_report=False,
    )
    try:
        reply = await agent.chat("测试")
    finally:
        await agent.aclose()
        await server.stop()
    assert "完成" in reply


@pytest.mark.asyncio
async def test_tool_error_and_big_output_branches():
    """ToolError → 纠偏记录；>6000 字符输出 → 预览回填 + 证据引用。"""
    server = MockGateToolLoopServer()
    server.script = [
        {"content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "boom_tool", "arguments": "{}"}},
            {"id": "c2", "type": "function",
             "function": {"name": "big_out", "arguments": "{}"}},
        ]},
        {"content": "FINAL: 完成 [e001] [e002]"},
    ]
    await server.start()
    agent = Agent(
        api_key="x", base_url=f"http://127.0.0.1:{server.port}/v1", model="m",
        executor=_BranchExecutor(), auto_report=False,
    )
    emitted: list[dict] = []
    agent.emit = lambda e: emitted.append(e)
    try:
        reply = await agent.chat("测试")
    finally:
        await agent.aclose()
        await server.stop()
    # ToolError 分支：执行失败记录且不抛
    fails = [e for e in emitted if e.get("type") == "tool_result" and e.get("ok") is False]
    assert any(e["name"] == "boom_tool" for e in fails)
    # 大输出分支：回填的是预览引用而非 8000 字符
    big = [e for e in emitted if e.get("type") == "tool_result" and e.get("name") == "big_out"]
    assert big and "完整输出" in big[0]["output"] and "已存为证据" in big[0]["output"]
    assert len(big[0]["output"]) < 8000


@pytest.mark.asyncio
async def test_reflexion_block_injected_after_failures():
    """工具连续失败 → 反思升级块注入上下文。"""
    server = MockGateToolLoopServer()
    server.script = [
        {"content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "boom_tool", "arguments": "{}"}},
        ]},
        {"content": "", "tool_calls": [
            {"id": "c2", "type": "function",
             "function": {"name": "boom_tool", "arguments": "{}"}},
        ]},
        {"content": "FINAL: 完成 [e001]"},
    ]
    await server.start()
    agent = Agent(
        api_key="x", base_url=f"http://127.0.0.1:{server.port}/v1", model="m",
        executor=_BranchExecutor(), auto_report=False,
    )
    try:
        reply = await agent.chat("测试")
    finally:
        await agent.aclose()
        await server.stop()
    assert "完成" in reply
    # 至少 3 次请求（第 3 次上下文含反思升级）
    assert len(server.requests) >= 3


# ---------------------------------------------------------------------------
# llm 剩余分支：health_hint / 近成功闸门 / 报告 OSError / severity 低
# ---------------------------------------------------------------------------
class _HealthExecutor:
    """前 3 次失败、之后成功。"""

    def __init__(self):
        self.extensions: dict = {}
        self.calls = 0

    async def execute(self, name: str, arguments: dict) -> str:
        self.calls += 1
        if self.calls <= 3:
            raise ToolError("连接超时")
        return "OK"


@pytest.mark.asyncio
async def test_health_hint_correction_emitted():
    """连续失败 3 次后成功调用 → correction 事件带健康提示。"""
    server = MockGateToolLoopServer()
    server.script = [
        {"content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "flaky", "arguments": "{}"}},
        ]},
        {"content": "", "tool_calls": [
            {"id": "c2", "type": "function",
             "function": {"name": "flaky", "arguments": "{}"}},
        ]},
        {"content": "", "tool_calls": [
            {"id": "c3", "type": "function",
             "function": {"name": "flaky", "arguments": "{}"}},
        ]},
        {"content": "", "tool_calls": [
            {"id": "c4", "type": "function",
             "function": {"name": "flaky", "arguments": "{}"}},
        ]},
        {"content": "FINAL: 完成 [e001]"},
    ]
    await server.start()
    agent = Agent(
        api_key="x", base_url=f"http://127.0.0.1:{server.port}/v1", model="m",
        executor=_HealthExecutor(), auto_report=False,
    )
    emitted: list[dict] = []
    agent.emit = lambda e: emitted.append(e)
    try:
        reply = await agent.chat("测试")
    finally:
        await agent.aclose()
        await server.stop()
    assert "完成" in reply
    corrections = [e for e in emitted if e.get("type") == "correction"]
    assert corrections and any("连续失败" in h for e in corrections for h in e.get("hints", []))


@pytest.mark.asyncio
async def test_report_oserror_emits_error(monkeypatch):
    """auto_report 时报告写入 OSError → error 事件不崩。"""
    server = MockGateToolLoopServer()
    server.script = [
        {"content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "run_command", "arguments": "{\"command\": \"echo hi\"}"}},
        ]},
        {"content": "FINAL: flag{report_ok} [e001]"},
    ]
    await server.start()

    class FlagExecutor:
        extensions: dict = {}

        async def execute(self, name: str, arguments: dict) -> str:
            return "flag{report_ok}"

    def boom(self, cleaned):
        raise OSError("磁盘满了")

    monkeypatch.setattr(Agent, "write_report", boom)
    agent = Agent(
        api_key="x", base_url=f"http://127.0.0.1:{server.port}/v1", model="m",
        executor=FlagExecutor(), auto_report=True,
    )
    emitted: list[dict] = []
    agent.emit = lambda e: emitted.append(e)
    try:
        reply = await agent.chat("测试")
    finally:
        await agent.aclose()
        await server.stop()
    assert "flag{report_ok}" in reply
    errors = [e for e in emitted if e.get("type") == "error"]
    assert any("报告写入失败" in e["message"] for e in errors)


def test_severity_low_branch():
    from kalitui.evidence import severity_of

    assert severity_of({"type": "http_error"}) == 1


# ---------------------------------------------------------------------------
# llm 近成功闸门：NO_PATH 提前判死拒绝 / 穷尽理由放行
# ---------------------------------------------------------------------------
class _NearMissExecutor:
    """输出含 SQL 高信号锚点（pinned facts 命中 _NEAR_MISS_MARKERS）。"""

    def __init__(self):
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        return "检测到 SQL 注入参数: id（SELECT * FROM users WHERE）"


@pytest.mark.asyncio
async def test_near_miss_gate_rejects_premature_no_path():
    """高信号证据未耗尽时 NO_PATH（带"无回显"理由）→ reject + 回灌。"""
    server = MockGateToolLoopServer()
    server.script = [
        {"content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "sql_probe", "arguments": "{}"}},
        ]},
        {"content": "FINAL: NO_PATH: 无回显，疑似注入不成立"},
        {"content": "FINAL: NO_PATH: 无回显，疑似注入不成立"},
        {"content": "FINAL: NO_PATH: 无回显，疑似注入不成立"},
    ]
    await server.start()
    agent = Agent(
        api_key="x", base_url=f"http://127.0.0.1:{server.port}/v1", model="m",
        executor=_NearMissExecutor(), auto_report=False,
    )
    emitted: list[dict] = []
    agent.emit = lambda e: emitted.append(e)
    try:
        reply = await agent.chat("测试")
    finally:
        await agent.aclose()
        await server.stop()
    rejects = [e for e in emitted if e.get("type") == "evidence_gate" and e.get("verdict") == "reject"]
    assert len(rejects) >= 1
    assert "已停止" in reply or "回灌" in reply


@pytest.mark.asyncio
async def test_near_miss_gate_allows_exhaustive_no_path():
    """理由含"已验证"穷尽关键词 → 放行（不拒绝）。"""
    server = MockGateToolLoopServer()
    server.script = [
        {"content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "sql_probe", "arguments": "{}"}},
        ]},
        {"content": "NO_PATH: 已验证全部参数与端点，确认无注入"},
    ]
    await server.start()
    agent = Agent(
        api_key="x", base_url=f"http://127.0.0.1:{server.port}/v1", model="m",
        executor=_NearMissExecutor(), auto_report=False,
    )
    emitted: list[dict] = []
    agent.emit = lambda e: emitted.append(e)
    try:
        reply = await agent.chat("测试")
    finally:
        await agent.aclose()
        await server.stop()
    rejects = [e for e in emitted if e.get("type") == "evidence_gate" and e.get("verdict") == "reject"]
    assert rejects == []
    assert "已验证全部参数" in reply


# ---------------------------------------------------------------------------
# llm 单元级分支：耗时纠偏 / 时间线容错 / findings.json 容错 / 导出目标
# ---------------------------------------------------------------------------
def _unit_agent() -> "Agent":
    return Agent(api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
                 executor=_BranchExecutor(), auto_report=False)


def test_looks_exhaustive_branches():
    from kalitui.llm import _looks_exhaustive

    assert _looks_exhaustive("已验证全部端点") is True
    assert _looks_exhaustive("已验证端点但无回显") is False  # premature 覆盖
    assert _looks_exhaustive("没有可继续验证的路径") is False


def test_finding_target_empty_and_missing():
    agent = _unit_agent()
    assert agent._finding_target({"evidence": ""}) == ""
    assert agent._finding_target({"evidence": "nope"}) == ""
    agent.memory.record("run_command", {"command": "x"}, "flag{target_test}")
    rec = agent.memory.evidence[-1]
    rec.arguments = {"target": "10.0.0.9"}
    assert agent._finding_target({"evidence": rec.id}) == "10.0.0.9"


def test_timeline_ts_error_and_brief_truncate(tmp_path):
    agent = _unit_agent()
    agent.memory.record("run_command", {"command": "x"}, "flag{timeline}")
    rec = agent.memory.evidence[-1]
    rec.ts = "not-a-number"  # fromtimestamp 抛 ValueError → "?"
    rec.arguments = {"command": "nmap " + "a" * 100}
    path = agent.write_report(final_answer="结论", path=str(tmp_path / "r.md"))
    content = open(path, encoding="utf-8").read()
    assert "`?`" in content
    assert "…" in content  # brief 截断


def test_write_report_findings_json_oserror(tmp_path, monkeypatch):
    """findings.json 写入失败不影响主报告。"""
    import kalitui.llm as L

    def boom(*a, **k):
        raise OSError("磁盘满")

    monkeypatch.setattr(L.json, "dump", boom)
    agent = _unit_agent()
    agent.memory.record("run_command", {"command": "x"}, "flag{json_ok}")
    path = agent.write_report(final_answer="结论", path=str(tmp_path / "r.md"))
    assert open(path, encoding="utf-8").read()  # 主报告仍在


def test_maybe_save_state_with_resume_path(tmp_path):
    agent = Agent(
        api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
        executor=_BranchExecutor(), auto_report=False,
        resume_path=str(tmp_path / "resume.json"),
    )
    agent._maybe_save_state()
    assert (tmp_path / "resume.json").exists()


def test_reproduction_steps_and_impact_level():
    agent = _unit_agent()
    agent.memory.record("run_command", {"command": "curl /admin"}, "200 OK admin login")
    steps = agent._reproduction_steps()
    assert isinstance(steps, list) and len(steps) >= 1
    # impact：http_error 低
    agent.memory.record("run_command", {"command": "x"}, "HTTP 500 内部错误")
    agent.memory.record("run_command", {"command": "y"}, "flag{impact}")
    assert "高" in agent._impact_level()


# ---------------------------------------------------------------------------
# llm 单元级补充：reset / after_marker / 耗时纠偏 / 序列化兜底
# ---------------------------------------------------------------------------
def test_after_marker_no_match():
    from kalitui.llm import _after_marker, _has_marker

    assert _after_marker("没有标记的文本", ("NO_PATH:",)) == ""
    assert _has_marker("FINAL: done", ("FINAL:",)) is True
    assert _has_marker("done", ("FINAL:",)) is False


def test_reset_clears_everything():
    agent = _unit_agent()
    agent.memory.record("run_command", {"command": "x"}, "flag{reset_me}")
    agent._last_goal = "旧目标"
    agent.reset()
    assert agent.messages == []
    assert agent.memory.evidence == []
    assert agent._last_goal == ""
    assert agent._stall_rounds == 0


def test_write_report_unserializable_arguments(tmp_path):
    agent = _unit_agent()
    agent.memory.record("run_command", {"command": "x"}, "flag{unser}")
    rec = agent.memory.evidence[-1]
    rec.arguments = {"tags": {"a", "b"}}  # set 不可 JSON 序列化
    path = agent.write_report(final_answer="结论", path=str(tmp_path / "r.md"))
    content = open(path, encoding="utf-8").read()
    assert "tags" in content  # str 兜底渲染


class _SlowFailExecutor:
    """抛 ToolError 且模拟耗时 20s。"""

    def __init__(self):
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        from kalitui.tools import ToolError

        raise ToolError("慢失败")


@pytest.mark.asyncio
async def test_slow_failure_duration_hint(monkeypatch):
    """失败且耗时 ≥15s → 纠偏提示。"""
    import itertools

    import kalitui.llm as L

    counter = itertools.count(0, 20.0)
    monkeypatch.setattr(L.time, "monotonic", lambda: next(counter))
    agent = _unit_agent()
    agent.executor = _SlowFailExecutor()
    out, ok = await agent._execute_tool("boom_tool", {})
    assert ok is False
    assert "纠偏" in out and "20000ms" in out


class _CancelExecutor:
    def __init__(self):
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        raise asyncio.CancelledError


@pytest.mark.asyncio
async def test_cancelled_error_passthrough():
    """_execute_tool 的 CancelledError 透传（不包装）。"""
    server = MockGateToolLoopServer()
    server.script = [
        {"content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "boom_tool", "arguments": "{}"}},
        ]},
        {"content": "FINAL: 完成 [e001]"},
    ]
    await server.start()
    agent = Agent(
        api_key="x", base_url=f"http://127.0.0.1:{server.port}/v1", model="m",
        executor=_CancelExecutor(), auto_report=False,
    )
    try:
        with pytest.raises(asyncio.CancelledError):
            await agent.chat("测试")
    finally:
        await agent.aclose()
        await server.stop()


# ---------------------------------------------------------------------------
# llm 深路径：大输出+hints 组合 / retry 坏 JSON / gate 循环耗尽
# ---------------------------------------------------------------------------
class _HealthBigExecutor:
    """前 3 次失败（触发健康提示），第 4 次成功返回超大输出。"""

    def __init__(self):
        self.extensions: dict = {}
        self.calls = 0

    async def execute(self, name: str, arguments: dict) -> str:
        self.calls += 1
        if self.calls <= 3:
            from kalitui.tools import ToolError

            raise ToolError("超时")
        return "高信号行: admin login\n" + "x" * 8000


@pytest.mark.asyncio
async def test_big_output_with_health_hints():
    """健康提示 + 大输出同时出现 → 预览拼接 hints 回填。"""
    server = MockGateToolLoopServer()
    server.script = [
        {"content": "", "tool_calls": [
            {"id": f"c{i}", "type": "function",
             "function": {"name": "flaky", "arguments": "{}"}} for i in range(1, 5)
        ]},
        {"content": "FINAL: 完成 [e004]"},
    ]
    await server.start()
    agent = Agent(
        api_key="x", base_url=f"http://127.0.0.1:{server.port}/v1", model="m",
        executor=_HealthBigExecutor(), auto_report=False,
    )
    emitted: list[dict] = []
    agent.emit = lambda e: emitted.append(e)
    try:
        await agent.chat("测试")
    finally:
        await agent.aclose()
        await server.stop()
    big = [e for e in emitted if e.get("type") == "tool_result" and e.get("name") == "flaky"]
    assert any("完整输出" in e["output"] for e in big)
    assert any("连续失败" in e["output"] for e in big)  # hints 拼进预览


@pytest.mark.asyncio
async def test_retry_bad_json_and_loop_exhausted():
    """回灌内坏 JSON 参数兜底；4 轮取证后仍未通过 → 停止提示。"""
    server = MockGateToolLoopServer()
    server.script = [
        {"content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "run_command", "arguments": '{"command": "echo hi"}'}},
        ]},
        {"content": "FINAL: flag{fake1} [e001]"},  # 拒 → 回灌
        {"content": "", "tool_calls": [
            {"id": "c2", "type": "function",
             "function": {"name": "run_command", "arguments": "{bad json"}},
        ]},
        {"content": "", "tool_calls": [
            {"id": "c3", "type": "function",
             "function": {"name": "run_command", "arguments": "{}"}},
        ]},
        {"content": "", "tool_calls": [
            {"id": "c4", "type": "function",
             "function": {"name": "run_command", "arguments": "{}"}},
        ]},
        {"content": "", "tool_calls": [
            {"id": "c5", "type": "function",
             "function": {"name": "run_command", "arguments": "{}"}},
        ]},
    ]
    await server.start()
    agent = Agent(
        api_key="x", base_url=f"http://127.0.0.1:{server.port}/v1", model="m",
        executor=ToolLoopExecutor(), auto_report=False,
    )
    emitted: list[dict] = []
    agent.emit = lambda e: emitted.append(e)
    try:
        reply = await agent.chat("测试")
    finally:
        await agent.aclose()
        await server.stop()
    assert "多次尝试后仍未通过证据闸门" in reply
    # 坏 JSON 兜底执行了（_raw 参数）
    starts = [e for e in emitted if e.get("type") == "tool_start"]
    assert any(e["arguments"].get("_raw") is not None for e in starts)


# ---------------------------------------------------------------------------
# unauthorized 独立发现类（SRC 未授权访问/信息泄露）
# ---------------------------------------------------------------------------
def test_extract_unauthorized_finding():
    from kalitui.evidence import extract_findings

    fs = extract_findings("检测到 actuator 端点未授权访问，/env 可读", "e9")
    types = [f["type"] for f in fs]
    assert "unauthorized" in types
    assert "vuln_marker" not in types  # 未授权优先，不重复标记
    assert fs[0]["evidence"] == "e9"


def test_unauthorized_severity_and_sort():
    from kalitui.evidence import severity_of, sort_findings

    assert severity_of({"type": "unauthorized"}) == 4
    fs = sort_findings([
        {"type": "vuln_marker", "value": "x"},
        {"type": "unauthorized", "value": "y"},
        {"type": "http_error", "value": "500"},
    ])
    assert [f["type"] for f in fs] == ["unauthorized", "vuln_marker", "http_error"]


def test_impact_level_unauthorized():
    agent = _unit_agent()
    agent.memory.record("run_command", {"command": "x"}, "actuator 未授权访问 /env")
    assert "中-高" in agent._impact_level()


# ---------------------------------------------------------------------------
# evidence 剩余分支：满员拒绝 / 空行预览 / 攻击面分支 / 快照恢复容错
# ---------------------------------------------------------------------------
def test_preview_blank_lines_skipped():
    from kalitui.evidence import make_high_signal_preview

    # 全空行大输出：走截断路径，无高信号行但保留 header+省略标记
    pv = make_high_signal_preview("\n" * 9000)
    assert "high-signal preview" in pv and "raw omitted" in pv


def test_findings_capacity_break():
    """发现满 60 条后不再接纳新发现。"""
    agent = _unit_agent()
    for i in range(65):
        agent.memory.record("run_command", {"command": f"x{i}"}, f"flag{{f{i}}}")
    assert len(agent.memory.findings) <= 60


def test_attack_surface_suggest_expand_recon():
    """无端口无 Web 无发现 → 建议扩大侦察。"""
    agent = _unit_agent()
    agent.memory.record("run_command", {"command": "x"}, "普通输出无端口无URL")
    snap = agent.memory.attack_surface_summary()
    assert "先扩大侦察" in snap
    assert "开放端口/服务: （证据中未解析到 nmap 风格端口输出）" in snap


def test_attack_surface_hot_points():
    """pinned 高信号事实（SQL/表单/接口）→ 潜在攻击点清单。"""
    agent = _unit_agent()
    agent.memory.record("run_command", {"command": "x"}, "SELECT * FROM users WHERE id=1")
    snap = agent.memory.attack_surface_summary()
    assert "潜在攻击点" in snap


def test_load_state_bad_record_skipped():
    """快照恢复时非法 evidence 记录跳过不崩。"""
    import tempfile
    from pathlib import Path

    agent = _unit_agent()
    agent.memory.record("run_command", {"command": "x"}, "flag{state_ok}")
    agent2 = _unit_agent()
    agent2.memory.record("run_command", {"command": "y"}, "flag{state_good}")
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "s.json"
        agent2.resume_path = str(path)
        agent2.save_state()
        data = json.loads(path.read_text(encoding="utf-8"))
        data["memory"]["evidence"] = [
            "not-a-dict",  # 坏记录（非 dict → TypeError）
            {"summary": "x"},  # 坏记录（缺 id → KeyError）
            data["memory"]["evidence"][0],
        ]
        data["memory"]["pinned_facts"] = ["good", 42]  # 混入非字符串
        path.write_text(json.dumps(data), encoding="utf-8")
        agent3 = _unit_agent()
        agent3.restore_state(data)
        assert agent3.memory.evidence  # 好记录仍在
        assert all(isinstance(f, str) for f in agent3.memory.pinned_facts)


def test_targets_summary_with_stats():
    """/targets 有证据时的摘要。"""
    agent = _unit_agent()
    agent.memory.record("run_command", {"url": "http://10.0.0.9/x"}, "200 OK")
    s = agent.memory.targets_summary()
    assert "目标工作区" in s
    assert "10.0.0.9" in s
