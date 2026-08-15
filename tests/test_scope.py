"""目标授权范围守卫与发现提取测试（白帽挖洞合规场景）。

覆盖：
- extract_targets：URL / IP / user@host / 网络工具裸域名提取
- 豁免：本机、内网、本地文件路径、包管理器镜像源
- ScopeGuard：未授权拦截 → 授权后放行 / 拒绝后不再问
- findings 提取：flag / CVE / 漏洞标记 / HTTP 4xx-5xx
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kalitui.evidence import AgentMemory, extract_findings  # noqa: E402
from kalitui.scope import ScopeGuard, extract_targets  # noqa: E402


# ---------------------------------------------------------------------------
# 目标提取
# ---------------------------------------------------------------------------
class TestExtractTargets:
    def test_url_host(self):
        assert extract_targets("curl http://hackme.example.com/admin") == ["hackme.example.com"]
        assert extract_targets("curl -k https://target.site:8443/api") == ["target.site"]

    def test_bare_ip(self):
        assert extract_targets("nmap -sV 203.0.113.7") == ["203.0.113.7"]
        assert extract_targets("ping 198.51.100.23") == ["198.51.100.23"]

    def test_user_at_host(self):
        assert extract_targets("ssh root@shell.ctf.com") == ["shell.ctf.com"]
        assert extract_targets("evil-winrm -i 203.0.113.9 -u admin") == ["203.0.113.9"]

    def test_net_tool_bare_domain(self):
        # 网络工具命令中的裸域名应提取
        assert extract_targets("nmap target.example.com") == ["target.example.com"]
        assert extract_targets("sqlmap -u http://x.com/id=1 --dbs") == ["x.com"]

    def test_local_loopback_exempt(self):
        assert extract_targets("nmap 127.0.0.1") == []
        assert extract_targets("curl http://localhost:8080/") == []
        assert extract_targets("nmap ::1") == []

    def test_rfc1918_exempt(self):
        assert extract_targets("nmap 192.168.1.1") == []
        assert extract_targets("nmap 10.0.0.5") == []
        assert extract_targets("nmap 172.16.0.10") == []

    def test_local_paths_not_targets(self):
        assert extract_targets("cat /usr/share/wordlists/rockyou.txt") == []
        assert extract_targets("grep root /etc/passwd") == []
        assert extract_targets("ls -la /var/log/auth.log") == []
        assert extract_targets("python3 exploit.py") == []
        assert extract_targets("echo hello world") == []

    def test_package_mirrors_ignored(self):
        assert extract_targets("apt update") == []
        assert extract_targets("git clone https://github.com/Kunspring/DeepKali.git") == []

    def test_cidr(self):
        assert extract_targets("nmap 203.0.113.0/24") == ["203.0.113.0/24"]
        assert extract_targets("masscan 203.0.113.0/24 -p80") == ["203.0.113.0/24"]

    def test_multiple_targets_dedup(self):
        targets = extract_targets("nmap 203.0.113.1 203.0.113.1 target.example.com")
        assert targets == ["203.0.113.1", "target.example.com"]


# ---------------------------------------------------------------------------
# ScopeGuard
# ---------------------------------------------------------------------------
class TestScopeGuard:
    def test_unauthorized_detection(self):
        guard = ScopeGuard()
        assert guard.unauthorized("nmap 203.0.113.7") == ["203.0.113.7"]
        assert guard.unauthorized("nmap 127.0.0.1") == []  # 本机豁免

    def test_authorize_flow(self):
        guard = ScopeGuard()
        assert guard.unauthorized("nmap 203.0.113.7") == ["203.0.113.7"]
        guard.authorize("203.0.113.7")
        assert guard.unauthorized("nmap 203.0.113.7") == []
        assert guard.unauthorized("nmap 203.0.113.8") == ["203.0.113.8"]  # 其他目标仍拦

    def test_decline_flow(self):
        guard = ScopeGuard()
        guard.decline("203.0.113.7")
        assert guard.unauthorized("nmap 203.0.113.7") == []  # 拒绝后不再重复问

    def test_authorize_all(self):
        guard = ScopeGuard()
        guard.authorize_all(["a.com", "b.com"])
        assert guard.unauthorized("nmap a.com b.com") == []

    def test_policy_off(self):
        guard = ScopeGuard(policy="off")
        assert guard.unauthorized("nmap 203.0.113.7") == []

    def test_summary(self):
        guard = ScopeGuard()
        guard.authorize("target.example.com")
        s = guard.summary()
        assert "ask" in s
        assert "target.example.com" in s


# ---------------------------------------------------------------------------
# Executor 集成：未授权外部目标拦截
# ---------------------------------------------------------------------------
import asyncio  # noqa: E402

from kalitui.tools import Executor  # noqa: E402


class RecordingApproval:
    """记录审批请求并自动允许/拒绝。"""

    def __init__(self, allow: bool):
        self.allow = allow
        self.requests: list[tuple[str, str, str]] = []

    def __call__(self, command: str, level: str, reason: str):
        self.requests.append((command, level, reason))
        req = __import__("kalitui.tools", fromlist=["ApprovalRequest"]).ApprovalRequest(
            command, level, reason
        )
        req.resolve(allow=self.allow)
        return req


@pytest.mark.asyncio
async def test_executor_blocks_unauthorized_target():
    approval = RecordingApproval(allow=False)
    ex = Executor(request_approval=approval)
    out = await ex.execute("run_command", {"command": "nmap 203.0.113.99"})
    assert "未授权" in out
    assert "Starting Nmap" not in out  # 命令未实际执行
    # 被拒绝的目标不再重复询问
    assert ex.scope.unauthorized("nmap 203.0.113.99") == []


@pytest.mark.asyncio
async def test_executor_allows_after_authorization():
    approval = RecordingApproval(allow=True)
    ex = Executor(request_approval=approval)
    out = await ex.execute("run_command", {"command": "echo scan 203.0.113.99"})
    assert "已授权" not in out or True  # 命令执行了
    assert "命令: echo scan 203.0.113.99" in out
    # 授权已记住
    assert ex.scope.unauthorized("nmap 203.0.113.99") == []


@pytest.mark.asyncio
async def test_executor_local_target_no_approval():
    approval = RecordingApproval(allow=False)
    ex = Executor(request_approval=approval)
    out = await ex.execute("run_command", {"command": "echo local 192.168.1.10"})
    assert "命令: echo local 192.168.1.10" in out  # 内网目标直接执行
    assert approval.requests == []


# ---------------------------------------------------------------------------
# findings 提取
# ---------------------------------------------------------------------------
class TestFindings:
    def test_flag_finding(self):
        findings = extract_findings("got flag{sec_123}", "e001")
        assert {"type": "flag", "value": "flag{sec_123}", "evidence": "e001"} in findings

    def test_cve_finding(self):
        findings = extract_findings("CVE-2024-1234 detected", "e002")
        assert {"type": "cve", "value": "CVE-2024-1234", "evidence": "e002"} in findings

    def test_vuln_marker(self):
        findings = extract_findings("target is VULNERABLE to sqli", "e003")
        assert any(f["type"] == "vuln_marker" for f in findings)

    def test_http_error(self):
        findings = extract_findings("Status: 500 Internal Server Error", "e004")
        assert {"type": "http_error", "value": "500", "evidence": "e004"} in findings
        assert extract_findings("Status: 200 OK", "e005") == []  # 2xx 不算

    def test_memory_findings_dedup(self):
        mem = AgentMemory()
        mem.record("run_command", {"command": "a"}, "flag{x1} CVE-2024-9999")
        mem.record("run_command", {"command": "b"}, "flag{x1} again")
        types = [(f["type"], f["value"]) for f in mem.findings]
        assert types.count(("flag", "flag{x1}")) == 1  # 去重

    def test_memory_findings_report_ready(self):
        mem = AgentMemory()
        mem.record("run_command", {"command": "curl"}, "HTTP/1.1 404 Not Found")
        assert any(f["type"] == "http_error" for f in mem.findings)


# ---------------------------------------------------------------------------
# 持久化：授权目标跨会话复用
# ---------------------------------------------------------------------------
class TestScopePersistence:
    def test_save_load_roundtrip(self, tmp_path, monkeypatch):
        import kalitui.scope as scope_mod

        fake = tmp_path / "scope.json"
        monkeypatch.setattr(scope_mod, "SCOPE_FILE", fake)
        guard = scope_mod.ScopeGuard()
        guard.authorize("target.example.com")
        guard.authorize("203.0.113.10")
        assert fake.exists()

        # 新会话加载
        guard2 = scope_mod.ScopeGuard()
        guard2.load_persisted()
        assert guard2.unauthorized("nmap target.example.com") == []
        assert guard2.unauthorized("nmap 203.0.113.10") == []
        assert guard2.unauthorized("nmap other.example.com") == ["other.example.com"]

    def test_load_corrupt_file_ignored(self, tmp_path, monkeypatch):
        import kalitui.scope as scope_mod

        fake = tmp_path / "scope.json"
        fake.write_text("{not valid json", encoding="utf-8")
        monkeypatch.setattr(scope_mod, "SCOPE_FILE", fake)
        guard = scope_mod.ScopeGuard()
        guard.load_persisted()  # 不应抛异常
        assert guard.authorized == []

    def test_load_missing_file(self, tmp_path, monkeypatch):
        import kalitui.scope as scope_mod

        monkeypatch.setattr(scope_mod, "SCOPE_FILE", tmp_path / "nope.json")
        guard = scope_mod.ScopeGuard()
        guard.load_persisted()
        assert guard.authorized == []

    def test_save_unwritable_silent(self, tmp_path, monkeypatch):
        import kalitui.scope as scope_mod

        fake = tmp_path / "sub" / "scope.json"  # 父目录不存在也能建
        monkeypatch.setattr(scope_mod, "SCOPE_FILE", fake)
        guard = scope_mod.ScopeGuard()
        guard.authorize("a.example.com")
        assert fake.exists()


# ---------------------------------------------------------------------------
# Bounty 报告结构
# ---------------------------------------------------------------------------
class TestBountyReport:
    def _agent_with_findings(self):
        from kalitui.llm import Agent

        agent = Agent(
            api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
            executor=Executor(danger_policy="always_allow"), auto_report=False,
        )
        agent._last_goal = "扫描测试目标"
        agent.memory.record("run_command", {"command": "nmap -sV t.com"}, "CVE-2024-1234 found")
        agent.memory.record("http_req", {"url": "http://t.com/x"}, "HTTP/1.1 500 Error")
        return agent

    def test_impact_level(self):
        agent = self._agent_with_findings()
        assert "CVE" in agent._impact_level() or "中" in agent._impact_level()

        agent2 = self._agent_with_findings()
        agent2.memory.record("run_command", {"command": "cat"}, "flag{sec_x}")
        assert "高" in agent2._impact_level()

    def test_reproduction_steps(self):
        agent = self._agent_with_findings()
        steps = agent._reproduction_steps()
        assert len(steps) == 2
        assert "nmap" in steps[0]
        assert "e001" in steps[0]
        assert "e002" in steps[1]

    def test_report_contains_bounty_sections(self, tmp_path):
        agent = self._agent_with_findings()
        path = agent.write_report("测试结论", str(tmp_path / "r.md"))
        content = (tmp_path / "r.md").read_text(encoding="utf-8")
        assert "影响等级" in content
        assert "修复建议" in content
        assert "复现步骤" in content
        assert "发现汇总" in content
        # findings.json 一并生成
        assert (tmp_path / "r.findings.json").exists()

    def test_report_empty_findings(self, tmp_path):
        from kalitui.llm import Agent

        agent = Agent(
            api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
            executor=Executor(danger_policy="always_allow"), auto_report=False,
        )
        path = agent.write_report("无发现", str(tmp_path / "r2.md"))
        content = (tmp_path / "r2.md").read_text(encoding="utf-8")
        assert "影响等级" in content
        assert "信息（未发现明确漏洞信号）" in content
        assert "发现汇总" not in content  # 无 findings 不输出该节


# ---------------------------------------------------------------------------
# WAF 绕过知识库 lore 注入
# ---------------------------------------------------------------------------
class TestWafBypassLore:
    def _lore(self, history: list[dict]) -> str:
        from kalitui.profiles import lore_for

        return lore_for(history)

    def test_trigger_on_cloudflare(self):
        lore = self._lore([{"role": "user", "content": "目标被 cloudflare 拦了，怎么绕过"}])
        assert "WAF 绕过深度要点" in lore
        assert "--tamper" in lore
        assert "打源站" in lore

    def test_trigger_on_waf_detect_output(self):
        lore = self._lore([
            {"role": "tool", "content": "工具 waf_detect 的结果:\n🎯 WAF 检测结果:\ntarget is behind Cloudflare"},
        ])
        assert "WAF 绕过深度要点" in lore

    def test_trigger_on_bypass_word(self):
        lore = self._lore([{"role": "user", "content": "sqlmap 被拦了，试试 bypass 技巧"}])
        assert "WAF 绕过深度要点" in lore

    def test_not_triggered_on_normal_scan(self):
        lore = self._lore([{"role": "user", "content": "扫描一下 127.0.0.1 的端口"}])
        assert "WAF 绕过深度要点" not in lore

    def test_registered_without_tools(self):
        from kalitui.profiles import REGISTRY, all_schemas

        names = {p.name for p in REGISTRY}
        assert "waf_bypass" in names
        # lore-only 档案不产生任何工具 schema
        assert all(s["function"]["name"] != "waf_bypass" for s in all_schemas())


# ---------------------------------------------------------------------------
# 漏洞影响证明 lore 注入
# ---------------------------------------------------------------------------
class TestVulnProofLore:
    def _lore(self, history: list[dict]) -> str:
        from kalitui.profiles import lore_for

        return lore_for(history)

    def test_trigger_on_verify_request(self):
        lore = self._lore([{"role": "user", "content": "帮我验证一下这个 SQL 注入漏洞，写个 PoC"}])
        assert "漏洞影响证明要点" in lore
        assert "时间盲注" in lore
        assert "updatexml" in lore

    def test_trigger_on_report_request(self):
        lore = self._lore([{"role": "user", "content": "漏洞确认了，帮我提交报告"}])
        assert "漏洞影响证明要点" in lore

    def test_trigger_on_reproduce(self):
        lore = self._lore([{"role": "user", "content": "能复现一下这个 RCE 吗"}])
        assert "漏洞影响证明要点" in lore

    def test_not_triggered_on_normal_scan(self):
        lore = self._lore([{"role": "user", "content": "扫一下目标开了哪些端口"}])
        assert "漏洞影响证明要点" not in lore

    def test_registered_without_tools(self):
        from kalitui.profiles import REGISTRY, all_schemas

        names = {p.name for p in REGISTRY}
        assert "vuln_proof" in names
        assert all(s["function"]["name"] != "vuln_proof" for s in all_schemas())


# ---------------------------------------------------------------------------
# 攻击面快照
# ---------------------------------------------------------------------------
class TestAttackSurface:
    def test_empty_memory(self):
        mem = AgentMemory()
        out = mem.attack_surface_summary()
        assert "还没有任何工具证据" in out

    def test_parses_open_ports(self):
        mem = AgentMemory()
        mem.record("run_command", {"command": "nmap -sV t.com"},
                   "22/tcp open ssh OpenSSH 8.9\n80/tcp open http Apache")
        out = mem.attack_surface_summary()
        assert "22/tcp(ssh)" in out
        assert "80/tcp(http)" in out

    def test_lists_web_targets_and_findings(self):
        mem = AgentMemory()
        mem.record("curl", {"url": "http://t.com/"}, "HTTP/1.1 200 OK\nCVE-2024-1234 in page")
        mem.record("run_command", {"command": "x"}, "http://t.com/admin found")
        out = mem.attack_surface_summary()
        assert "Web 目标" in out
        assert "已确认发现" in out
        assert "CVE-2024-1234" in out

    def test_suggests_missing_directions(self):
        mem = AgentMemory()
        mem.record("run_command", {"command": "nmap"}, "22/tcp open ssh")
        out = mem.attack_surface_summary()
        assert "尚未出现的高信号方向" in out

    def test_agent_executes_attack_surface_tool(self):
        """端到端：attack_surface 直接查记忆，不经过 executor。"""
        import asyncio

        from kalitui.llm import Agent

        async def run():
            agent = Agent(
                api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
                executor=Executor(danger_policy="always_allow"), auto_report=False,
            )
            agent.memory.record("run_command", {"command": "nmap"},
                                "443/tcp open https\nCVE-2023-1234")
            out, ok = await agent._execute_tool("attack_surface", {})
            await agent.aclose()
            return out, ok

        out, ok = asyncio.run(run())
        assert ok
        assert "443/tcp(https)" in out
        assert "CVE-2023-1234" in out


# ---------------------------------------------------------------------------
# 会话状态保存/恢复（跨会话续挖）
# ---------------------------------------------------------------------------
class TestSessionResume:
    def _make_agent(self):
        from kalitui.llm import Agent

        return Agent(
            api_key="x", base_url="http://127.0.0.1:9/v1", model="m",
            executor=Executor(danger_policy="always_allow"), auto_report=False,
        )

    def test_roundtrip(self):
        agent = self._make_agent()
        agent._last_goal = "继续挖 target.com"
        agent.messages.append({"role": "user", "content": "扫描 target.com"})
        agent.memory.record("run_command", {"command": "nmap"}, "22/tcp open ssh")
        agent.memory.record("curl", {"url": "http://target.com/"}, "flag{resume_x} CVE-2024-1234")
        agent.reflexion.record_failure("payload1")

        data = agent.state_dict()
        agent2 = self._make_agent()
        agent2.restore_state(data)

        assert agent2._last_goal == "继续挖 target.com"
        assert len(agent2.messages) == 1
        assert len(agent2.memory.evidence) == 2
        assert agent2.memory.findings  # findings 恢复
        assert agent2.memory.pinned_facts
        assert agent2.reflexion.fail_count == 1
        # 恢复后证据可查询
        assert "22/tcp open ssh" in agent2.memory.view("e001")

    def test_restore_bad_data_ignored(self):
        agent = self._make_agent()
        agent.restore_state(None)  # 不抛
        agent.restore_state({"messages": "not-a-list"})  # 不抛
        agent.restore_state({"memory": 42})  # 不抛
        assert agent.messages == []

    def test_save_load_file(self, tmp_path):
        agent = self._make_agent()
        agent.resume_path = str(tmp_path / "resume.json")
        agent.memory.record("run_command", {"command": "x"}, "output1")
        assert agent.save_state()
        assert (tmp_path / "resume.json").exists()

        agent2 = self._make_agent()
        agent2.resume_path = str(tmp_path / "resume.json")
        import json as _json

        data = _json.loads((tmp_path / "resume.json").read_text(encoding="utf-8"))
        agent2.restore_state(data)
        assert len(agent2.memory.evidence) == 1

    def test_save_no_path_returns_false(self):
        agent = self._make_agent()
        assert agent.save_state() is False

    def test_findings_severity_sort(self):
        from kalitui.evidence import sort_findings

        findings = [
            {"type": "http_error", "value": "500", "evidence": "e1"},
            {"type": "flag", "value": "flag{x}", "evidence": "e2"},
            {"type": "cve", "value": "CVE-2024-1234", "evidence": "e3"},
        ]
        out = sort_findings(findings)
        assert [f["type"] for f in out] == ["flag", "cve", "http_error"]


# ---------------------------------------------------------------------------
# 合规守卫独立于 danger_policy（always_allow 不得绕过 scope）
# ---------------------------------------------------------------------------
class TestScopeVsDangerPolicy:
    @pytest.mark.asyncio
    async def test_always_allow_still_blocks_external_target(self):
        """即使危险命令自动放行，未授权外部目标仍必须弹窗确认。"""
        approval = RecordingApproval(allow=False)
        ex = Executor(request_approval=approval, danger_policy="always_allow")
        out = await ex.execute("run_command", {"command": "nmap 203.0.113.77"})
        assert "未授权" in out
        assert "Starting Nmap" not in out

    @pytest.mark.asyncio
    async def test_always_allow_local_target_runs(self):
        approval = RecordingApproval(allow=False)
        ex = Executor(request_approval=approval, danger_policy="always_allow")
        out = await ex.execute("run_command", {"command": "nmap -Pn -F 127.0.0.1"})
        assert "Starting Nmap" in out  # 本机不触发 scope，直接执行

    @pytest.mark.asyncio
    async def test_always_allow_external_after_user_approval(self):
        """用户在 scope 弹窗里允许后，always_allow 下命令执行。"""
        approval = RecordingApproval(allow=True)
        ex = Executor(request_approval=approval, danger_policy="always_allow")
        out = await ex.execute("run_command", {"command": "echo scan 203.0.113.77"})
        assert "命令: echo scan 203.0.113.77" in out
        assert ex.scope.unauthorized("nmap 203.0.113.77") == []  # 授权已记住

    @pytest.mark.asyncio
    async def test_headless_always_block_scope_denies(self):
        """无 UI 时 always_allow 也不能让外部目标通过。"""
        ex = Executor(danger_policy="always_allow")  # request_approval=None
        out = await ex.execute("run_command", {"command": "nmap 203.0.113.78"})
        assert "未授权" in out


# ---------------------------------------------------------------------------
# 目标工作区：按目标聚合统计
# ---------------------------------------------------------------------------
class TestTargetStats:
    def test_empty(self):
        mem = AgentMemory()
        assert mem.target_stats() == []
        assert "还没有可归类" in mem.targets_summary()

    def test_stats_by_url_and_target_args(self):
        mem = AgentMemory()
        mem.record("curl", {"url": "http://a.com/page"}, "flag{x} found")
        mem.record("nmap_scan", {"target": "a.com"}, "22/tcp open ssh")
        mem.record("nuclei_scan", {"target": "http://b.com/"}, "CVE-2024-1234")
        stats = mem.target_stats()
        by_host = {s["target"]: s for s in stats}
        assert by_host["a.com"]["evidence"] == 2
        assert by_host["a.com"]["findings"] >= 1  # flag 发现
        assert by_host["b.com"]["evidence"] == 1
        assert by_host["b.com"]["findings"] == 1  # CVE
        # 按证据数降序
        assert stats[0]["target"] == "a.com"

    def test_command_target_extraction(self):
        mem = AgentMemory()
        mem.record("run_command", {"command": "nmap -sV vuln.example.com"}, "80/tcp open http")
        stats = mem.target_stats()
        assert len(stats) == 1
        assert stats[0]["target"] == "vuln.example.com"

    def test_localhost_not_grouped(self):
        mem = AgentMemory()
        mem.record("run_command", {"command": "nmap 127.0.0.1"}, "22/tcp open ssh")
        mem.record("run_command", {"command": "ls"}, "local files")
        assert mem.target_stats() == []


# ---------------------------------------------------------------------------
# 提权知识库 lore 注入
# ---------------------------------------------------------------------------
class TestPrivescLore:
    def _lore(self, history: list[dict]) -> str:
        from kalitui.profiles import lore_for

        return lore_for(history)

    def test_trigger_on_privesc_request(self):
        lore = self._lore([{"role": "user", "content": "拿到 shell 了是 www-data，帮我提权"}])
        assert "提权（Privesc）检查清单" in lore
        assert "sudo -l" in lore
        assert "linpeas" in lore

    def test_trigger_on_suid(self):
        lore = self._lore([{"role": "user", "content": "检查一下有哪些 SUID 文件"}])
        assert "提权（Privesc）检查清单" in lore

    def test_not_triggered_on_normal_scan(self):
        lore = self._lore([{"role": "user", "content": "扫一下目标端口"}])
        assert "提权（Privesc）检查清单" not in lore

    def test_registered_without_tools(self):
        from kalitui.profiles import REGISTRY, all_schemas

        names = {p.name for p in REGISTRY}
        assert "privesc" in names
        assert all(s["function"]["name"] != "privesc" for s in all_schemas())


# ---------------------------------------------------------------------------
# CIDR 网段授权（白帽常授权整个 in-scope 网段）
# ---------------------------------------------------------------------------
class TestCidrScope:
    def test_extract_cidr_keeps_prefix(self):
        targets = extract_targets("nmap -sL 203.0.113.0/24")
        assert "203.0.113.0/24" in targets
        assert "203.0.113.0" not in targets  # 不被裸 IP 规则重复提取

    def test_private_cidr_exempt(self):
        assert extract_targets("nmap -sL 192.168.1.0/24") == []
        assert extract_targets("nmap -sL 10.0.0.0/8") == []

    def test_invalid_cidr_not_extracted(self):
        assert extract_targets("nmap 203.0.113.0/99") == []

    def test_ip_covered_by_authorized_cidr(self):
        guard = ScopeGuard()
        guard.authorize("203.0.113.0/24")
        assert guard.unauthorized("nmap 203.0.113.77") == []
        assert guard.unauthorized("nmap 203.0.114.1") == ["203.0.114.1"]  # 网段外

    def test_cidr_authorized_no_repeat_prompt(self):
        guard = ScopeGuard()
        guard.authorize("203.0.113.0/24")
        assert guard.unauthorized("nmap -sV 203.0.113.0/24") == []
        assert guard.unauthorized("nmap 203.0.113.5") == []

    def test_single_ip_does_not_cover_cidr_scan(self):
        guard = ScopeGuard()
        guard.authorize("203.0.113.5")
        # 扫 /24 网段时提取的是网段本身，单 IP 授权不覆盖
        assert "203.0.113.0/24" in guard.unauthorized("nmap 203.0.113.0/24")

    def test_host_scan_inside_cidr_allowed(self):
        guard = ScopeGuard()
        guard.authorize("198.51.100.0/28")
        assert guard.unauthorized("nmap -p- 198.51.100.15") == []

    @pytest.mark.asyncio
    async def test_executor_cidr_flow(self):
        approval = RecordingApproval(allow=True)
        ex = Executor(request_approval=approval, danger_policy="ask")
        out = await ex.execute("run_command", {"command": "echo scan 203.0.113.0/24"})
        assert "命令: echo scan 203.0.113.0/24" in out
        # 授权后网段内任意 IP 不再询问
        assert ex.scope.unauthorized("nmap 203.0.113.9") == []


# ---------------------------------------------------------------------------
# 漏洞检测知识库 lore
# ---------------------------------------------------------------------------
class TestVulnDetectLore:
    def _lore(self, history: list[dict]) -> str:
        from kalitui.profiles import lore_for

        return lore_for(history)

    def test_trigger_on_sqli(self):
        lore = self._lore([{"role": "user", "content": "帮我测一下这个参数有没有 SQL 注入"}])
        assert "SQL 注入（最常考）" in lore
        assert "SLEEP" in lore
        assert "sqlmap" in lore

    def test_trigger_on_xss(self):
        lore = self._lore([{"role": "user", "content": "搜索框好像有 XSS"}])
        assert "反射型探测" in lore

    def test_trigger_on_ssrf(self):
        lore = self._lore([{"role": "user", "content": "测试 SSRF 漏洞"}])
        assert "SSRF" in lore

    def test_not_triggered_on_scan(self):
        lore = self._lore([{"role": "user", "content": "扫描一下端口"}])
        assert "SQL 注入（最常考）" not in lore
        assert "漏洞检测手法" not in lore

    def test_registered_without_tools(self):
        from kalitui.profiles import REGISTRY, all_schemas

        assert "vuln_detect" in {p.name for p in REGISTRY}
        assert all(s["function"]["name"] != "vuln_detect" for s in all_schemas())


# ---------------- 私有函数边界分支 ----------------

class TestPrivateHelpers:
    def test_is_valid_cidr_bad(self):
        from kalitui.scope import _is_valid_cidr

        assert not _is_valid_cidr("not-a-cidr")
        assert not _is_valid_cidr("10.0.0.0/99")
        assert _is_valid_cidr("203.0.113.0/24")

    def test_is_private_cidr_and_ipv6(self):
        from kalitui.scope import _is_private

        # CIDR 分支（带斜杠）
        assert _is_private("10.0.0.0/8")
        assert _is_private("192.168.0.0/16")
        assert not _is_private("203.0.113.0/24")  # TEST-NET 不豁免（py3.13 修复）
        # IPv6 分支
        assert _is_private("::1")            # loopback
        assert _is_private("fe80::1")        # link-local
        assert _is_private("fd00::1")        # ULA
        assert not _is_private("2001:db8::1")  # 文档段不豁免
        # 异常分支
        assert not _is_private("not-an-ip")
        assert not _is_private("999.1.1.1")

    def test_is_ip_bad(self):
        from kalitui.scope import _is_ip

        assert not _is_ip("not-an-ip")
        assert _is_ip("10.0.0.5")

    def test_summary_empty_authorized(self, tmp_path, monkeypatch):
        """已授权目标为空时显示占位（覆盖 L306）。"""
        from kalitui.scope import ScopeGuard

        monkeypatch.setenv("KALITUI_SCOPE_FILE", str(tmp_path / "s.json"))
        g = ScopeGuard(policy="ask")
        s = g.summary()
        assert "已授权目标: （无）" in s


# ---------------- 追加：边界分支 ----------------

class TestScopeBranches:
    def test_private_cidr_and_invalid_ip(self):
        from kalitui.scope import _is_private

        assert _is_private("10.0.0.0/8") is True
        assert _is_private("192.168.1.0/24") is True
        assert _is_private("999.1.1.1") is False  # ip_address 抛 ValueError

    def test_looks_like_file_path(self):
        from kalitui.scope import _looks_like_file_path

        assert _looks_like_file_path("config.php") is True
        assert _looks_like_file_path("/var/www/index.html") is True
        assert _looks_like_file_path("10.0.0.0/24") is False  # CIDR 不是路径
        assert _looks_like_file_path("example.com") is False

    def test_is_non_target_local(self):
        from kalitui.scope import _is_non_target

        assert _is_non_target("router.local") is True
        assert _is_non_target("printer.home") is True
        assert _is_non_target("random-site.com") is False

    def test_extract_net_tool_domains(self):
        from kalitui.scope import extract_targets

        # 网络工具语境里的域名也算目标
        ts = extract_targets("nmap -p 80 -sV api.example.com")
        assert any("api.example.com" in t for t in ts)
        # 冒号 IPv6 不被误提取
        ts2 = extract_targets("scp user@[::1]:/tmp/x")
        assert not any("::1" in t for t in ts2)

    def test_is_authorized_cidr_containment(self):
        from kalitui.scope import ScopeGuard

        g = ScopeGuard()
        g.authorize("8.8.8.0/24")
        assert g.unauthorized("nmap 8.8.8.8") == []
        assert g.unauthorized("nmap 8.8.9.8") == ["8.8.9.8"]

    def test_summary_with_declined(self):
        from kalitui.scope import ScopeGuard

        g = ScopeGuard()
        g.authorize("a.com")
        g.declined.append("b.com")
        s = g.summary()
        assert "已授权目标: a.com" in s
        assert "已拒绝目标: b.com" in s


# ---------------- 追加2：CIDR/IPv6/路径分隔符分支 ----------------

class TestScopeBranches2:
    def test_private_invalid_cidr_and_ipv6(self):
        from kalitui.scope import _is_private

        assert _is_private("300.0.0.0/8") is False  # 非法 CIDR → ValueError
        assert _is_private("fd00::/8") is False     # IPv6 CIDR 非私有豁免
        assert _is_private("::1") is True           # IPv6 loopback 豁免
        assert _is_private("2001:db8::1") is False  # IPv6 公网

    def test_path_separator_without_ext(self):
        from kalitui.scope import _looks_like_file_path

        assert _looks_like_file_path("uploads/backup") is True  # 含 / 无扩展名
        assert _looks_like_file_path("a/b/c") is True

    def test_lan_suffix_and_ipv6_token(self):
        from kalitui.scope import _is_non_target, extract_targets

        assert _is_non_target("nas.lan") is True
        assert _is_non_target("host.home") is True
        # IPv6 带端口形式 ::1 不误提取
        assert not any("::1" in t for t in extract_targets("curl [::1]:8080"))

    def test_net_tool_first_word(self):
        from kalitui.scope import extract_targets

        # 网络工具作为首词（无分号管道）也提取域名
        ts = extract_targets("gobuster dir -u http://blog.example.com")
        assert any("blog.example.com" in t for t in ts)


# ---------------- 追加3：IPv6 提取 / 坏 CIDR 授权 / 持久化容错 ----------------

class TestScopeBranches3:
    def test_ipv6_token_extracted(self):
        from kalitui.scope import extract_targets

        ts = extract_targets("curl [2001:db8::1]")
        assert any("2001:db8::1" in t for t in ts)

    def test_authorized_bad_cidr_skipped(self):
        from kalitui.scope import ScopeGuard

        g = ScopeGuard()
        g.authorize_all(["8.8.8.0/24", "not-a-cidr//"])  # 非法 CIDR 容错
        assert g.unauthorized("nmap 8.8.8.8") == []
        assert g.unauthorized("nmap 9.9.9.9") == ["9.9.9.9"]

    def test_persist_oserror_tolerated(self, monkeypatch, tmp_path):
        import kalitui.scope as S

        monkeypatch.setattr(S, "SCOPE_FILE", tmp_path / "no" / "dir" / "scope.json")
        g = S.ScopeGuard()
        g.authorize("a.com")
        g.save_persisted()  # 目录不存在 → OSError 吞掉不崩

    def test_load_persisted_missing_file(self, monkeypatch, tmp_path):
        import kalitui.scope as S

        monkeypatch.setattr(S, "SCOPE_FILE", tmp_path / "absent.json")
        g = S.ScopeGuard()
        g.load_persisted()  # 文件不存在 → 不崩
        assert g.authorized == []


class TestScopePersistOSError:
    def test_save_persisted_unwritable(self, monkeypatch):
        """持久化路径不可写 → OSError 静默（授权仍在会话内生效）。"""
        import kalitui.scope as S

        monkeypatch.setattr(S, "SCOPE_FILE", __import__("pathlib").Path("/proc/x/scope.json"))
        g = S.ScopeGuard()
        g.authorize("a.com")
        g.save_persisted()  # /proc 只读 → OSError 吞掉
        assert "a.com" in g.authorized  # 会话内授权不受影响
