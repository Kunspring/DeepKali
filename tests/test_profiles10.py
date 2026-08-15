"""第十批（收官）测试：playbook 联动流水线。"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kalitui.profiles import REGISTRY, all_schemas, lore_for, register_extensions  # noqa: E402
from kalitui.profiles.playbook import (  # noqa: E402
    _build_cmd, _parse_ports, _suggest, _summarize, _SERVICE_PLAYBOOK,
)

# ---------------- 命令构造与校验 ----------------


def test_playbook_cmd() -> None:
    cmd, timeout = _build_cmd({"target": "10.0.0.5"})
    assert cmd == "nmap -sV -T4 --top-ports 200 10.0.0.5"
    assert timeout == 300
    cmd2, _ = _build_cmd({"target": "10.0.0.5", "ports": "22,80,18080"})
    assert cmd2 == "nmap -sV -T4 -p22,80,18080 10.0.0.5"
    with pytest.raises(ValueError):
        _build_cmd({"target": "10.0.0.5;ls"})
    with pytest.raises(ValueError):
        _build_cmd({"target": "10.0.0.5", "ports": "22;rm"})


# ---------------- 端口解析 ----------------


def test_parse_ports() -> None:
    raw = """Nmap scan report for 10.0.0.5
Host is up (0.01s latency).
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu
80/tcp   open  http     nginx 1.18.0
443/tcp  open  ssl/http Apache
445/tcp  open  microsoft-ds Samba smbd 4.15
9999/tcp open  unknown
Nmap done: 1 IP address (1 host up)"""
    ports = _parse_ports(raw)
    assert ports == [
        (22, "ssh", "OpenSSH 8.9p1 Ubuntu"),
        (80, "http", "nginx 1.18.0"),
        (443, "ssl/http", "Apache"),
        (445, "microsoft-ds", "Samba smbd 4.15"),
        (9999, "unknown", ""),
    ]
    assert _parse_ports("no ports here") == []


# ---------------- 建议生成 ----------------


def test_suggest() -> None:
    assert "hydra_brute" in " ".join(_suggest(22, "ssh"))
    assert "smb_enum" in " ".join(_suggest(445, "microsoft-ds"))
    assert "ftp_check" in " ".join(_suggest(21, "ftp"))
    assert "redis_check" in " ".join(_suggest(6379, "redis"))
    assert "ldap_enum" in " ".join(_suggest(389, "ldap"))
    assert "winrm_exec" in " ".join(_suggest(5985, "winrm"))
    assert "dns_recon" in " ".join(_suggest(53, "domain"))
    assert "kerberoast" in " ".join(_suggest(88, "kerberos-sec"))
    # Web 端口建议含核心链
    web = " ".join(_suggest(8080, "http"))
    for t in ("http_req", "nikto_scan", "dir_brute", "waf_detect"):
        assert t in web
    # 未知名单回退提示
    assert "sploit_search" in " ".join(_suggest(9999, "custom-thing"))
    # 端口回退：无服务名但端口知名
    assert "ftp_check" in " ".join(_suggest(21, "unknown"))


def test_summarize() -> None:
    raw = """Nmap scan report for 10.0.0.5
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
Nmap done"""
    out = _summarize(raw)
    assert "存活主机: 1 台" in out
    assert "开放端口 (2)" in out
    assert "22/tcp ssh" in out
    assert "工具链建议" in out
    assert "hydra_brute" in out and "nikto_scan" in out
    empty = _summarize("Nmap scan report for 10.0.0.5\nAll 1000 scanned ports are filtered")
    assert "未发现开放端口" in empty


# ---------------- registry / lore ----------------


def test_registry_playbook() -> None:
    names = [s["function"]["name"] for s in all_schemas()]
    assert "recon_pipeline" in names
    assert "playbook" in [p.name for p in REGISTRY]
    assert len(REGISTRY) >= 45


def test_lore_playbook() -> None:
    assert "playbook" in lore_for([{"role": "user", "content": "对 10.0.0.5 跑一遍完整侦察流程"}])
    assert "playbook" in lore_for([{"role": "user", "content": "一键组合扫描目标"}])


# ---------------------------------------------------------------------------
# bounty_recon：一键白帽侦察执行链
# ---------------------------------------------------------------------------
class ReconStub:
    """记录命令并返回带 Web 服务的 nmap 输出。"""

    def __init__(self, nmap_out: str | None = None):
        self.calls: list[tuple[str, dict]] = []
        self.danger_policy = "ask"
        self.extensions: dict = {}
        self.nmap_out = nmap_out or (
            "Starting Nmap\nNmap scan report for target.lab\n"
            "22/tcp open ssh OpenSSH 8.9\n80/tcp open http Apache 2.4\n"
        )

    async def execute(self, name: str, arguments: dict) -> str:
        self.calls.append((name, arguments))
        cmd = arguments.get("command", "")
        if "nmap" in cmd:
            return self.nmap_out
        if "wafw00f" in cmd:
            return "target.lab is behind Cloudflare"
        if "gobuster" in cmd:
            return "/admin (Status: 200)\n/secret (Status: 404)\n/api (Status: 301)"
        return "STUB"


@pytest.mark.asyncio
async def test_bounty_recon_full_chain() -> None:
    from kalitui.profiles import register_extensions

    stub = ReconStub()
    register_extensions(stub)  # type: ignore[arg-type]

    out = await stub.extensions["bounty_recon"](stub, {"target": "target.lab"})
    assert "存活主机" in out
    assert "80/tcp http" in out
    # Web 深化自动触发：wafw00f + gobuster 都被调用
    cmds = [a["command"] for _n, a in stub.calls]
    assert any("wafw00f" in c for c in cmds)
    assert any("gobuster dir" in c for c in cmds)
    # 汇总包含 WAF 与目录发现
    assert "Cloudflare" in out or "WAF: 检测到防护" in out
    assert "/admin(200)" in out
    assert "/secret" not in out  # 404 被过滤


@pytest.mark.asyncio
async def test_bounty_recon_skip_web_check() -> None:
    from kalitui.profiles import register_extensions

    stub = ReconStub()
    register_extensions(stub)  # type: ignore[arg-type]

    out = await stub.extensions["bounty_recon"](stub, {"target": "target.lab", "web_check": False})
    assert "开放端口" in out
    cmds = [a["command"] for _n, a in stub.calls]
    assert not any("wafw00f" in c for c in cmds)
    assert not any("gobuster" in c for c in cmds)


@pytest.mark.asyncio
async def test_bounty_recon_no_web_ports() -> None:
    from kalitui.profiles import register_extensions

    stub = ReconStub(nmap_out="Starting Nmap\n22/tcp open ssh OpenSSH 8.9\n")
    register_extensions(stub)  # type: ignore[arg-type]

    out = await stub.extensions["bounty_recon"](stub, {"target": "target.lab"})
    assert "开放端口 (1)" in out
    cmds = [a["command"] for _n, a in stub.calls]
    assert not any("wafw00f" in c for c in cmds)


@pytest.mark.asyncio
async def test_bounty_recon_injection_rejected() -> None:
    from kalitui.profiles import register_extensions

    stub = ReconStub()
    register_extensions(stub)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        await stub.extensions["bounty_recon"](stub, {"target": "1.2.3.4;rm -rf /"})


# ---------------------------------------------------------------------------
# bounty_recon 安装检查
# ---------------------------------------------------------------------------
class NoToolReconStub:
    """wafw00f/gobuster 未安装时的 stub。"""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.danger_policy = "ask"
        self.extensions: dict = {}
        self.installed: set[str] = {"nmap"}

    async def execute(self, name: str, arguments: dict) -> str:
        self.calls.append((name, arguments))
        if "nmap" in arguments.get("command", ""):
            return "Nmap scan report for t\n80/tcp open http"
        return "STUB"


@pytest.mark.asyncio
async def test_bounty_recon_skips_missing_tools(monkeypatch) -> None:
    from kalitui import profiles as P

    stub = NoToolReconStub()
    monkeypatch.setattr(P.playbook, "check_installed", lambda t: t in stub.installed)
    P.register_extensions(stub)  # type: ignore[arg-type]

    out = await stub.extensions["bounty_recon"](
        stub, {"target": "203.0.113.9", "web_check": True}
    )
    # 跳过说明而非报错；nmap 命令照常执行
    assert "wafw00f/gobuster" in out
    assert any("nmap" in a["command"] for _n, a in stub.calls)
    assert not any("wafw00f" in c for _n, a in stub.calls for c in [a["command"]])


# ---------------------------------------------------------------------------
# http_req max_bytes 截断生效（死参数修复回归）
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_http_req_max_bytes_truncates() -> None:
    from kalitui.profiles import register_extensions

    class CurlStub:
        def __init__(self):
            self.calls: list[tuple[str, dict]] = []
            self.danger_policy = "ask"
            self.extensions: dict = {}

        async def execute(self, name: str, arguments: dict) -> str:
            self.calls.append((name, arguments))
            return "A" * 3000 + "\n200 3000"

    stub = CurlStub()
    register_extensions(stub)  # type: ignore[arg-type]

    out = await stub.extensions["http_req"](stub, {"url": "http://t.com/", "max_bytes": 500})
    assert "截断至 500 bytes" in out
    assert "HTTP 200" in out

    # 默认 4000：3000 字节 body 不截断内容（但仍有截断说明）
    out2 = await stub.extensions["http_req"](stub, {"url": "http://t.com/"})
    assert "HTTP 200" in out2

    # max_bytes 超下界被钳制到 500（sanitize_int 默认 clamp 行为）
    out3 = await stub.extensions["http_req"](stub, {"url": "http://t.com/", "max_bytes": 10})
    assert "截断至 500 bytes" in out3


# ---------------------------------------------------------------------------
# bounty_recon 多目标 + nuclei
# ---------------------------------------------------------------------------
class MultiReconStub:
    def __init__(self, installed: set[str] | None = None):
        self.calls: list[tuple[str, dict]] = []
        self.danger_policy = "ask"
        self.extensions: dict = {}
        self.installed = installed or {"nmap", "wafw00f", "gobuster", "nuclei"}

    async def execute(self, name: str, arguments: dict) -> str:
        self.calls.append((name, arguments))
        cmd = arguments.get("command", "")
        if "nmap" in cmd:
            return "Nmap scan report for t\n80/tcp open http\n443/tcp open https"
        if "wafw00f" in cmd:
            return "No WAF detected"
        if "gobuster" in cmd:
            return "/admin (Status: 200)"
        if "nuclei" in cmd:
            return "[critical] https://t: CVE-2023-9999 [http]\n[info] https://t: tech-detect [http]"
        return "STUB"


@pytest.mark.asyncio
async def test_bounty_recon_multi_target(monkeypatch) -> None:
    from kalitui import profiles as P

    stub = MultiReconStub()
    monkeypatch.setattr(P.playbook, "check_installed", lambda t: t in stub.installed)
    P.register_extensions(stub)  # type: ignore[arg-type]

    out = await stub.extensions["bounty_recon"](stub, {"target": "a.com, b.com"})
    assert "bounty_recon 完成（2 个目标）" in out
    assert "===== a.com =====" in out
    assert "===== b.com =====" in out
    # 每个目标都跑了 nmap
    nmap_cmds = [a["command"] for _n, a in stub.calls if "nmap" in a["command"]]
    assert len(nmap_cmds) == 2


@pytest.mark.asyncio
async def test_bounty_recon_nuclei_scan(monkeypatch) -> None:
    from kalitui import profiles as P

    stub = MultiReconStub()
    monkeypatch.setattr(P.playbook, "check_installed", lambda t: t in stub.installed)
    P.register_extensions(stub)  # type: ignore[arg-type]

    out = await stub.extensions["bounty_recon"](
        stub, {"target": "a.com", "vuln_scan": True}
    )
    assert "CVE-2023-9999" in out  # nuclei 命中行
    assert "tech-detect" not in out  # info 级 tech-detect 不解析？——看解析规则
    assert any("nuclei -u" in a["command"] for _n, a in stub.calls)


@pytest.mark.asyncio
async def test_bounty_recon_nuclei_skipped_when_off(monkeypatch) -> None:
    from kalitui import profiles as P

    stub = MultiReconStub()
    monkeypatch.setattr(P.playbook, "check_installed", lambda t: t in stub.installed)
    P.register_extensions(stub)  # type: ignore[arg-type]

    out = await stub.extensions["bounty_recon"](stub, {"target": "a.com"})
    assert not any("nuclei" in a["command"] for _n, a in stub.calls)


@pytest.mark.asyncio
async def test_bounty_recon_too_many_targets(monkeypatch) -> None:
    from kalitui import profiles as P

    stub = MultiReconStub()
    monkeypatch.setattr(P.playbook, "check_installed", lambda t: t in stub.installed)
    P.register_extensions(stub)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        await stub.extensions["bounty_recon"](
            stub, {"target": ",".join(f"t{i}.com" for i in range(11))}
        )


# ---------------------------------------------------------------------------
# 低覆盖率模块补测：airmon / cewl / aircrack / dnsrecon
# ---------------------------------------------------------------------------
class TestAirmon:
    def test_status_default(self):
        from kalitui.profiles.airmon import _build_cmd

        cmd, t = _build_cmd({})
        assert cmd == "airmon-ng"
        assert t == 30

    def test_start_requires_interface(self):
        from kalitui.profiles.airmon import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"action": "start"})

    def test_start_stop(self):
        from kalitui.profiles.airmon import _build_cmd

        cmd, t = _build_cmd({"action": "start", "interface": "wlan0"})
        assert cmd == "airmon-ng start wlan0"
        cmd2, _ = _build_cmd({"action": "stop", "interface": "wlan0mon"})
        assert cmd2 == "airmon-ng stop wlan0mon"

    def test_invalid_action_and_interface(self):
        from kalitui.profiles.airmon import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"action": "hack"})
        with pytest.raises(ValueError):
            _build_cmd({"action": "start", "interface": "wlan0;rm -rf /"})

    @pytest.mark.asyncio
    async def test_exec_summary(self):
        from kalitui.profiles import register_extensions

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "phy0  wlan0  ... (monitor mode enabled)\nphy1  wlan1"

        stub = Stub()
        register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["wifi_monitor"](stub, {"action": "status"})
        assert "网卡状态" in out


class TestCewl:
    def test_build_cmd(self):
        from kalitui.profiles.cewl import _build_cmd

        cmd, t = _build_cmd({"url": "http://t.com/", "email": True, "output": "/tmp/w.txt"})
        assert "cewl http://t.com/" in cmd
        assert "-e" in cmd
        assert "-w /tmp/w.txt" in cmd
        assert t == 180

    def test_invalid_url_and_output(self):
        from kalitui.profiles.cewl import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"url": "ftp://t.com"})
        with pytest.raises(ValueError):
            _build_cmd({"url": "http://t.com/", "output": "/etc/passwd"})

    @pytest.mark.asyncio
    async def test_exec_counts_words(self, tmp_path):
        from kalitui.profiles import register_extensions

        words = tmp_path / "w.txt"
        words.write_text("kali\nadmin\n", encoding="utf-8")

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "cewl done"

        stub = Stub()
        register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["cewl_words"](stub, {"url": "http://t.com/", "output": str(words)})
        assert "词表已生成" in out
        assert "2 词" in out


class TestAircrack:
    def test_build_cmd_with_bssid(self, tmp_path):
        from kalitui.profiles.aircrack import _build_cmd

        cap = tmp_path / "h.cap"
        cap.write_bytes(b"\x00")
        cmd, t = _build_cmd({"capture": str(cap), "bssid": "AA:BB:CC:DD:EE:FF"})
        assert "aircrack-ng -w" in cmd
        assert "-b AA:BB:CC:DD:EE:FF" in cmd
        assert t == 900

    def test_missing_cap_rejected(self, tmp_path):
        from kalitui.profiles.aircrack import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"capture": str(tmp_path / "nope.cap")})

    def test_bad_bssid_rejected(self, tmp_path):
        from kalitui.profiles.aircrack import _build_cmd

        cap = tmp_path / "h.cap"
        cap.write_bytes(b"\x00")
        with pytest.raises(ValueError):
            _build_cmd({"capture": str(cap), "bssid": "not-a-mac"})

    @pytest.mark.asyncio
    async def test_exec_key_found(self, tmp_path):
        from kalitui.profiles import register_extensions

        cap = tmp_path / "h.cap"
        cap.write_bytes(b"\x00")

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "KEY FOUND! [ wifi12345 ]"

        stub = Stub()
        register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["wifi_crack"](stub, {"capture": str(cap)})
        assert "wifi12345" in out


class TestDnsrecon:
    def test_modes(self):
        from kalitui.profiles.dnsrecon import _build_cmd

        cmd, _ = _build_cmd({"target": "example.com"})
        assert "dnsrecon -d example.com -t std" in cmd
        cmd2, _ = _build_cmd({"target": "example.com", "mode": "brt"})
        assert "-t brt" in cmd2
        cmd3, _ = _build_cmd({"target": "example.com", "mode": "axfr", "server": "8.8.8.8"})
        assert "-t axfr -n 8.8.8.8" in cmd3

    def test_invalid_mode_server(self):
        from kalitui.profiles.dnsrecon import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"target": "example.com", "mode": "weird"})
        with pytest.raises(ValueError):
            _build_cmd({"target": "example.com", "server": "bad server"})

    def test_summarize_new_and_old_format(self):
        from kalitui.profiles.dnsrecon import _summarize

        raw = (
            "2026-08-14T21:57:11.8 INFO \t A example.com 1.2.3.4\n"
            "[MX] example.com mail.example.com\n"
            "[MX] example.com mail.example.com\n"  # 去重
            "Zone Transfer: successful\n"
        )
        out = _summarize(raw)
        assert "解析记录 (2)" in out
        assert "A example.com 1.2.3.4" in out
        assert "区域传送成功" in out

    def test_summarize_noise_filtered(self):
        from kalitui.profiles.dnsrecon import _summarize

        out = _summarize("Enumerating subdomains...\nWildcard detected\n")
        assert "未发现解析记录" in out


# ---------------------------------------------------------------------------
# crack：离线 hash 破解全分支
# ---------------------------------------------------------------------------
class TestCrack:
    @pytest.mark.asyncio
    async def test_hashcat_hit(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "e10adc3949ba59abbe56e057f20f883e:123456"

        stub = Stub()
        monkeypatch.setattr(P.crack, "check_installed", lambda t: t == "hashcat")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["crack_hash"](
            stub, {"hash": "e10adc3949ba59abbe56e057f20f883e", "hash_type": "md5"}
        )
        assert "破解成功" in out
        assert "123456" in out

    @pytest.mark.asyncio
    async def test_hashcat_miss_falls_back_john(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if cmd.startswith("hashcat"):
                    return "no match"
                return "password123 (user)"

        stub = Stub()
        monkeypatch.setattr(P.crack, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["crack_hash"](
            stub, {"hash": "abc123", "hash_type": "ntlm"}
        )
        assert "john 破解结果" in out

    @pytest.mark.asyncio
    async def test_both_miss_and_rules(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if cmd.startswith("hashcat"):
                    assert "--rules" in cmd  # rules 参数生效
                    return "no match"
                return "no match"

        stub = Stub()
        monkeypatch.setattr(P.crack, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["crack_hash"](
            stub, {"hash": "abc123", "hash_type": "md5", "rules": True}
        )
        assert "未破解成功" in out

    @pytest.mark.asyncio
    async def test_no_tool_installed(self, monkeypatch):
        from kalitui import profiles as P

        stub = type("S", (), {"danger_policy": "ask", "extensions": {}})()
        monkeypatch.setattr(P.crack, "check_installed", lambda t: False)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["crack_hash"](stub, {"hash": "abc123"})
        assert "未安装" in out

    @pytest.mark.asyncio
    async def test_invalid_hash_and_type(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "x"

        stub = Stub()
        monkeypatch.setattr(P.crack, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["crack_hash"](stub, {"hash": "bad hash!@#", "hash_type": "md5"})
        with pytest.raises(ValueError):
            await stub.extensions["crack_hash"](stub, {"hash": "abc", "hash_type": "wpa2"})


# ---------------------------------------------------------------------------
# crt.sh：证书透明度子域枚举
# ---------------------------------------------------------------------------
class TestCrtsh:
    def test_build_cmd_escapes(self):
        from kalitui.profiles.crtsh import _build_cmd

        cmd = _build_cmd("example.com")
        assert "crt.sh/?q=%25example.com" in cmd
        assert cmd.startswith("curl -sS --max-time 60")

    def test_parse_dedup_sort(self):
        from kalitui.profiles.crtsh import _parse

        raw = json.dumps([
            {"name_value": "www.example.com\napi.example.com"},
            {"name_value": "api.example.com"},          # 重复
            {"name_value": "*.wild.example.com"},       # 通配排除
            {"name_value": "MAIL.Example.COM"},         # 大小写归一
            "not-a-dict",                               # 脏数据
        ])
        out = _parse(raw, limit=60)
        assert out == ["api.example.com", "mail.example.com", "www.example.com"]

    def test_parse_bad_json(self):
        from kalitui.profiles.crtsh import _parse

        assert _parse("{broken", 60) == []
        assert _parse("[]", 60) == []

    def test_parse_limit(self):
        from kalitui.profiles.crtsh import _parse

        raw = json.dumps([{"name_value": f"h{i}.example.com"} for i in range(10)])
        assert len(_parse(raw, limit=3)) == 3

    @pytest.mark.asyncio
    async def test_exec_parse_and_fallback(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self, output):
                self.danger_policy = "ask"
                self.extensions = {}
                self.output = output

            async def execute(self, name, arguments):
                return self.output

        monkeypatch.setattr(P.crtsh, "check_installed", lambda t: t == "curl")

        # 命中
        stub = Stub(json.dumps([{"name_value": "vpn.example.com\nadmin.example.com"}]))
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["crt_sh"](stub, {"target": "example.com"})
        assert "证书日志子域 (2 个" in out
        assert "vpn.example.com" in out

        # 空结果 → 提示 dnsrecon 兜底
        stub2 = Stub("[]")
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["crt_sh"](stub2, {"target": "example.com"})
        assert "dnsrecon" in out2

    @pytest.mark.asyncio
    async def test_exec_bad_domain(self, monkeypatch):
        from kalitui import profiles as P

        stub = type("S", (), {"danger_policy": "ask", "extensions": {}})()
        monkeypatch.setattr(P.crtsh, "check_installed", lambda t: t == "curl")
        P.register_extensions(stub)  # type: ignore[arg-type]
        # sanitize_target 直接拒绝注入型域名
        with pytest.raises(ValueError):
            await stub.extensions["crt_sh"](stub, {"target": "bad domain;rm -rf /"})


# ---------------------------------------------------------------------------
# httpx：批量存活探测
# ---------------------------------------------------------------------------
class TestHttpxProbe:
    def test_split_targets(self):
        from kalitui.profiles.httpx import _split_targets

        assert _split_targets("a.com, b.com,a.com") == ["a.com", "b.com"]
        with pytest.raises(ValueError):
            _split_targets(",".join(f"h{i}.com" for i in range(21)))

    def test_build_cmd_pipes_stdin(self):
        from kalitui.profiles.httpx import _build_cmd

        cmd = _build_cmd(["vpn.example.com", "10.0.0.5"])
        assert cmd.startswith("printf '%s\\n' vpn.example.com 10.0.0.5 | httpx")
        assert "-status-code -title -tech-detect" in cmd

    def test_parse_rows(self):
        from kalitui.profiles.httpx import _parse

        raw = (
            "https://vpn.example.com [200] [VPN 入口] [nginx]\n"
            "http://admin.example.com [403] [] [Apache]\n"
            "https://api.example.com [301] [Moved]\n"
            "not-an-httpx-line\n"
        )
        rows = _parse(raw)
        assert len(rows) == 3
        assert rows[0]["status"] == "200"
        assert rows[0]["title"] == "VPN 入口"
        assert rows[0]["tech"] == "nginx"
        assert rows[1]["tech"] == "Apache"
        assert rows[2]["status"] == "301"

    @pytest.mark.asyncio
    async def test_exec_summary(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "https://vpn.example.com [200] [VPN] [nginx]"

        stub = Stub()
        monkeypatch.setattr(P.httpx, "check_installed", lambda t: t == "httpx")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["httpx_probe"](
            stub, {"targets": "vpn.example.com,dead.example.com"}
        )
        assert "HTTP 存活目标 (1/2)" in out
        assert "vpn.example.com" in out

    @pytest.mark.asyncio
    async def test_exec_no_alive_and_bad_input(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.httpx, "check_installed", lambda t: t == "httpx")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["httpx_probe"](stub, {"targets": "dead.example.com"})
        assert "未探测到存活" in out
        assert "nmap" in out

        # 空目标
        out2 = await stub.extensions["httpx_probe"](stub, {"targets": ""})
        assert "不能为空" in out2

        # 注入型目标被拒绝
        out3 = await stub.extensions["httpx_probe"](
            stub, {"targets": "evil.com;rm -rf /"}
        )
        assert "格式非法" in out3

    @pytest.mark.asyncio
    async def test_exec_not_installed(self, monkeypatch):
        from kalitui import profiles as P

        stub = type("S", (), {"danger_policy": "ask", "extensions": {}})()
        monkeypatch.setattr(P.httpx, "check_installed", lambda t: False)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["httpx_probe"](stub, {"targets": "a.com"})
        assert "未安装" in out


# ---------------------------------------------------------------------------
# http_req cookie jar 会话保持
# ---------------------------------------------------------------------------
class TestCookieJar:
    def test_jar_modes(self):
        from kalitui.profiles.curl import JAR_PATH, _build_cmd

        # save：登录后保存
        cmd, _ = _build_cmd({"url": "http://t.com/login", "method": "POST",
                             "data": "user=admin&pass=x", "cookie_jar": "save"})
        assert f"-c {JAR_PATH}" in cmd
        assert f"-b {JAR_PATH}" not in cmd

        # use：带登录态
        cmd2, _ = _build_cmd({"url": "http://t.com/dashboard", "cookie_jar": "use"})
        assert f"-b {JAR_PATH}" in cmd2
        assert f"-c {JAR_PATH}" not in cmd2

        # session：先带再存
        cmd3, _ = _build_cmd({"url": "http://t.com/x", "cookie_jar": "session"})
        assert f"-b {JAR_PATH}" in cmd3
        assert f"-c {JAR_PATH}" in cmd3

    def test_jar_invalid(self):
        from kalitui.profiles.curl import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"url": "http://t.com/", "cookie_jar": "hack"})


# ---------------------------------------------------------------------------
# 全 profile 批量"未安装"分支（覆盖低覆盖 profile 的提示路径）
# ---------------------------------------------------------------------------
def test_all_profiles_not_installed_branch(monkeypatch):
    """每个 profile 的每个 exec：工具未安装时返回"未安装"提示。"""
    import asyncio
    import importlib
    from types import SimpleNamespace

    from kalitui import profiles as P

    stub = SimpleNamespace(danger_policy="ask", extensions={})
    checked = 0
    skipped = 0
    for prof in P.REGISTRY:
        mod = importlib.import_module(prof.__class__.__module__)
        for m in [x for x in dir(prof) if x.startswith("exec_")]:
            fn = getattr(prof, m)
            if not hasattr(mod, "check_installed"):
                continue  # 纯本地生成工具（如 report_gen）无需外部依赖
            monkeypatch.setattr(mod, "check_installed", lambda t: False)
            try:
                out = asyncio.run(fn(stub, {}))
            except (TypeError, ValueError):
                skipped += 1  # 参数校验在未安装检查之前（如缺必填参数）
                continue
            assert "未安装" in out, f"{prof.name}.{m}: {out!r}"
            checked += 1
    assert checked >= 20, f"只覆盖了 {checked} 个 exec（跳过 {skipped}）"


def test_all_profiles_not_installed_playbook(monkeypatch):
    """playbook 的未安装分支（bounty_recon/recon_pipeline 参数校验在前）。"""
    import asyncio
    from types import SimpleNamespace

    from kalitui import profiles as P

    stub = SimpleNamespace(danger_policy="ask", extensions={})
    monkeypatch.setattr(P.playbook, "check_installed", lambda t: False)
    prof = P.playbook.PlaybookProfile()
    # 全未安装：nmap 检查最先返回
    out = asyncio.run(prof.exec_bounty_recon(stub, {"target": "example.com"}))
    assert "未安装" in out
    out2 = asyncio.run(prof.exec_recon_pipeline(stub, {}))
    assert "未安装" in out2


# ---------------------------------------------------------------------------
# 正常执行分支补测：ftp / wafw00f / wfuzz / theharvester / sslscan
# ---------------------------------------------------------------------------
def _stub_ext(monkeypatch, mod, installed=("curl",), output="STUB"):
    from types import SimpleNamespace

    class Stub:
        def __init__(self):
            self.danger_policy = "ask"
            self.extensions = {}

        async def execute(self, name, arguments):
            return output

    stub = Stub()
    monkeypatch.setattr(mod, "check_installed", lambda t: t in installed)
    return stub


@pytest.mark.asyncio
async def test_ftp_exec_listing(monkeypatch):
    from kalitui import profiles as P

    stub = _stub_ext(monkeypatch, P.ftp, output="index.html\nbackup.zip\nreadme.txt")
    P.register_extensions(stub)  # type: ignore[arg-type]
    out = await stub.extensions["ftp_check"](stub, {"host": "10.0.0.5"})
    assert "FTP 根目录 (3 项)" in out
    assert "backup.zip" in out

    # 空列表 → 不可达提示
    stub2 = _stub_ext(monkeypatch, P.ftp, output="")
    P.register_extensions(stub2)  # type: ignore[arg-type]
    out2 = await stub2.extensions["ftp_check"](stub2, {"host": "10.0.0.5"})
    assert "无法列出目录" in out2


@pytest.mark.asyncio
async def test_wafw00f_exec_branches(monkeypatch):
    from kalitui import profiles as P

    # 检测到 WAF
    stub = _stub_ext(monkeypatch, P.wafw00f, installed=("wafw00f",), output="The site example.com is behind Cloudflare\nWAF: cloudflare")
    P.register_extensions(stub)  # type: ignore[arg-type]
    out = await stub.extensions["waf_detect"](stub, {"url": "http://example.com"})
    assert "WAF 检测结果" in out

    # 无 WAF
    stub2 = _stub_ext(monkeypatch, P.wafw00f, installed=("wafw00f",), output="No WAF detected")
    P.register_extensions(stub2)  # type: ignore[arg-type]
    out2 = await stub2.extensions["waf_detect"](stub2, {"url": "http://example.com"})
    assert "未检测到 WAF" in out2

    # 无结果
    stub3 = _stub_ext(monkeypatch, P.wafw00f, installed=("wafw00f",), output="timeout")
    P.register_extensions(stub3)  # type: ignore[arg-type]
    out3 = await stub3.extensions["waf_detect"](stub3, {"url": "http://example.com"})
    assert "检测无结果" in out3


@pytest.mark.asyncio
async def test_wfuzz_exec_filter(monkeypatch):
    from kalitui import profiles as P

    out_raw = (
        "000000123:   200        12 L    30 W     301 Ch \"http://t/FUZZ\"\n"
        "000000456:   404        9 L     15 W     120 Ch \"http://t/nope\"\n"
        "000000789:   301        7 L     11 W     90 Ch  \"http://t/old\"\n"
    )
    stub = _stub_ext(monkeypatch, P.wfuzz, installed=("wfuzz",), output=out_raw)
    P.register_extensions(stub)  # type: ignore[arg-type]
    out = await stub.extensions["wfuzz_fuzz"](stub, {"url": "http://t/FUZZ"})
    section = out.split("关键结果")[1].split("原始输出")[0]
    assert "000000123" in section and "000000789" in section  # 200/301 保留
    assert "404" not in section  # 默认隐藏 404

    # 只匹配 200
    stub2 = _stub_ext(monkeypatch, P.wfuzz, installed=("wfuzz",), output=out_raw)
    P.register_extensions(stub2)  # type: ignore[arg-type]
    out2 = await stub2.extensions["wfuzz_fuzz"](
        stub2, {"url": "http://t/FUZZ", "match_codes": "200"}
    )
    section2 = out2.split("关键结果")[1].split("原始输出")[0]
    assert "000000123" in section2
    assert "000000456" not in section2  # 只匹配 200


# ---------------------------------------------------------------------------
# linpeas：提权枚举
# ---------------------------------------------------------------------------
class TestLinpeas:
    def test_parse_hits_and_warns(self):
        from kalitui.profiles.linpeas import _parse

        raw = (
            "[+] /usr/bin/python3 - SUID\n"
            "[!] /etc/shadow is readable\n"
            "[i] basic info line\n"
            "\x1b[1;33m[+] sudo -l: NOPASSWD /bin/bash\x1b[0m\n"
            "noise line\n"
        )
        hits, warns = _parse(raw)
        assert any("python3 - SUID" in h for h in hits)
        assert any("sudo -l: NOPASSWD /bin/bash" in h for h in hits)  # ANSI 剥离
        assert any("shadow" in w for w in warns)
        assert not any("basic info" in h for h in hits)  # [i] 不提取

    @pytest.mark.asyncio
    async def test_exec_summary(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "[+] /usr/bin/find - SUID\n[!] weak perms\n"

        stub = Stub()
        monkeypatch.setattr(P.linpeas, "check_installed", lambda t: t == "linpeas")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["linpeas"](stub, {})
        assert "提权线索 (1 条)" in out
        assert "find - SUID" in out
        assert "警告 (1 条)" in out

    @pytest.mark.asyncio
    async def test_exec_no_hits_and_not_installed(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert "linpeas -q" in arguments["command"]  # quick 默认
                return "[i] nothing interesting\n"

        stub = Stub()
        monkeypatch.setattr(P.linpeas, "check_installed", lambda t: t == "linpeas")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["linpeas"](stub, {})
        assert "未发现明显提权线索" in out

        stub2 = type("S", (), {"danger_policy": "ask", "extensions": {}})()
        monkeypatch.setattr(P.linpeas, "check_installed", lambda t: False)
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["linpeas"](stub2, {})
        assert "未安装" in out2

    @pytest.mark.asyncio
    async def test_exec_full_mode(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert arguments["command"] == "linpeas"  # quick=False 无 -q
                return ""

        stub = Stub()
        monkeypatch.setattr(P.linpeas, "check_installed", lambda t: t == "linpeas")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["linpeas"](stub, {"quick": False})
        assert "未发现明显提权线索" in out


# ---------------------------------------------------------------------------
# bounty_recon sub_enum 子域发现步骤
# ---------------------------------------------------------------------------
class TestBountyReconSubEnum:
    @pytest.mark.asyncio
    async def test_sub_enum_domain_target(self, monkeypatch):
        import json as _json

        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "crt.sh" in cmd:
                    return _json.dumps([{"name_value": "vpn.example.com\nadmin.example.com"}])
                if cmd.startswith("printf") or "httpx" in cmd:
                    return "https://vpn.example.com [200] [VPN] [nginx]"
                if cmd.startswith("nmap"):
                    return "Nmap scan report for example.com\n80/tcp open http nginx"
                return "STUB"

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed",
                            lambda t: t in ("nmap", "curl", "httpx"))
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["bounty_recon"](
            stub, {"target": "example.com", "sub_enum": True, "web_check": False}
        )
        assert "子域发现 (2 个)" in out
        assert "vpn.example.com" in out
        assert "存活子域" in out  # httpx 批量探测衔接
        assert "https://vpn.example.com [200]" in out
        assert "===== example.com =====" in out
        assert "80/tcp http nginx" in out

    @pytest.mark.asyncio
    async def test_sub_enum_skipped_for_ip(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if cmd.startswith("nmap"):
                    return "Nmap scan report for 10.0.0.5\n22/tcp open ssh"
                return "STUB"

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed",
                            lambda t: t in ("nmap", "curl"))
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["bounty_recon"](
            stub, {"target": "10.0.0.5", "sub_enum": True, "web_check": False}
        )
        assert "跳过子域发现" in out
        assert "22/tcp ssh" in out

    @pytest.mark.asyncio
    async def test_sub_enum_failure_tolerated(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "crt.sh" in cmd:
                    raise RuntimeError("network down")
                if cmd.startswith("nmap"):
                    return "Nmap scan report for example.com\n80/tcp open http"
                return "STUB"

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed",
                            lambda t: t in ("nmap", "curl"))
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["bounty_recon"](
            stub, {"target": "example.com", "sub_enum": True, "web_check": False}
        )
        assert "查询失败（跳过）" in out
        assert "80/tcp http" in out  # 主流程不受影响

    def test_looks_like_domain(self):
        from kalitui.profiles.playbook import _looks_like_domain

        assert _looks_like_domain("example.com")
        assert _looks_like_domain("vpn.example.com")
        assert not _looks_like_domain("10.0.0.5")
        assert not _looks_like_domain("203.0.113.0/24")
        assert not _looks_like_domain("http://example.com")


# ---------------------------------------------------------------------------
# git_leak：.git 源码泄露检测
# ---------------------------------------------------------------------------
class TestGitLeak:
    def test_build_cmd_probes(self):
        from kalitui.profiles.gitleak import _build_cmd

        cmd = _build_cmd("http://target.com/app/")
        assert "target.com/app/.git/config" in cmd
        assert "target.com/app/.git/HEAD" in cmd
        assert "http_code" in cmd

    def test_parse_codes(self):
        from kalitui.profiles.gitleak import _parse

        assert _parse("200\n404\n") == ("200", "404")
        assert _parse("404") == ("404", "000")
        assert _parse("") == ("000", "000")

    @pytest.mark.asyncio
    async def test_exec_leaked(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "200\n200\n"

        stub = Stub()
        monkeypatch.setattr(P.gitleak, "check_installed", lambda t: t == "curl")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["git_leak"](stub, {"url": "http://target.com/"})
        assert ".git 目录泄露确认" in out
        assert "git-dumper" in out

    @pytest.mark.asyncio
    async def test_exec_clean_and_bad_url(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "404\n404\n"

        stub = Stub()
        monkeypatch.setattr(P.gitleak, "check_installed", lambda t: t == "curl")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["git_leak"](stub, {"url": "http://target.com/"})
        assert "未发现 .git 泄露" in out
        assert ".gitignore" in out

        out2 = await stub.extensions["git_leak"](stub, {"url": "ftp://x"})
        assert "格式非法" in out2


# ---------------------------------------------------------------------------
# snmp_enum：公共团体串枚举
# ---------------------------------------------------------------------------
class TestSnmpEnum:
    def test_build_cmd(self):
        from kalitui.profiles.snmp import _build_cmd

        cmd = _build_cmd("10.0.0.5", "public")
        assert "snmpwalk -v2c -c public -t 5 10.0.0.5 1.3.6.1.2.1.1" in cmd
        assert "head -40" in cmd

    def test_parse_values(self):
        from kalitui.profiles.snmp import _parse

        raw = (
            ".1.3.6.1.2.1.1.1.0 = STRING: \"Linux test-box 6.1.0\"\n"
            ".1.3.6.1.2.1.1.5.0 = STRING: \"test-box\"\n"
            ".1.3.6.1.2.1.1.3.0 = Timeticks: (12345) 0:02:03.45\n"
            "Timeout: No Response from 10.0.0.5\n"
        )
        rows = _parse(raw)
        assert any("Linux test-box 6.1.0" in r for r in rows)
        assert any('= test-box' in r for r in rows)
        assert not any("Timeticks" in r for r in rows)  # 非关键 OID 不提取
        assert not any("Timeout" in r for r in rows)

    @pytest.mark.asyncio
    async def test_exec_hit(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return '.1.3.6.1.2.1.1.1.0 = STRING: "Linux web1 6.1"\n.1.3.6.1.2.1.1.5.0 = STRING: "web1"\n'

        stub = Stub()
        monkeypatch.setattr(P.snmp, "check_installed", lambda t: t == "snmpwalk")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["snmp_enum"](stub, {"target": "10.0.0.5"})
        assert "团体串 'public' 有效" in out
        assert "Linux web1 6.1" in out

    @pytest.mark.asyncio
    async def test_exec_miss_and_bad_input(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "Timeout: No Response from 10.0.0.5\n"

        stub = Stub()
        monkeypatch.setattr(P.snmp, "check_installed", lambda t: t == "snmpwalk")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["snmp_enum"](stub, {"target": "10.0.0.5"})
        assert "未读取到信息" in out
        assert "nmap -sU -p 161" in out

        out2 = await stub.extensions["snmp_enum"](stub, {"target": "10.0.0.5", "community": "bad community!"})
        assert "非法字符" in out2


# ---------------------------------------------------------------------------
# nfs_enum：共享枚举
# ---------------------------------------------------------------------------
class TestNfsEnum:
    def test_build_cmd(self):
        from kalitui.profiles.nfs import _build_cmd

        assert _build_cmd("10.0.0.5") == "showmount -e 10.0.0.5 2>&1"

    def test_parse(self):
        from kalitui.profiles.nfs import _parse

        raw = (
            "Export list for 10.0.0.5:\n"
            "/home 10.0.0.0/24\n"
            "/backup (everyone)\n"
            "clnt_create: RPC: Port mapper failure\n"
        )
        shares = _parse(raw)
        assert "/home" in shares[0]
        assert "/backup" in shares[1]
        assert not any("clnt_create" in s for s in shares)

    @pytest.mark.asyncio
    async def test_exec_hit(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "Export list for 10.0.0.5:\n/home 10.0.0.0/24\n/backup (everyone)\n"

        stub = Stub()
        monkeypatch.setattr(P.nfs, "check_installed", lambda t: t == "showmount")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["nfs_enum"](stub, {"target": "10.0.0.5"})
        assert "NFS 导出 (2 个共享)" in out
        assert "/home" in out
        assert "no_root_squash" in out

    @pytest.mark.asyncio
    async def test_exec_miss(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "clnt_create: RPC: Port mapper failure\n"

        stub = Stub()
        monkeypatch.setattr(P.nfs, "check_installed", lambda t: t == "showmount")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["nfs_enum"](stub, {"target": "10.0.0.5"})
        assert "未发现可枚举的 NFS 共享" in out
        assert "2049" in out


# ---------------------------------------------------------------------------
# secret_scan：前端密钥扫描
# ---------------------------------------------------------------------------
class TestSecretScan:
    def test_scan_patterns(self):
        from kalitui.profiles.secret_scan import _scan

        raw = (
            "var aws = 'AKIAIOSFODNN7EXAMPLE';\n"
            "const gh = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef';\n"
            "api_key = \"sk_live_abcdefgh12345678\";\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "let jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';\n"
        )
        hits = _scan(raw)
        names = [h[0] for h in hits]
        assert "AWS Access Key" in names
        assert "GitHub Token" in names
        assert "Generic API Key" in names
        assert "Private Key" in names
        assert "JWT Token" in names
        # 脱敏：不出现完整值
        assert all("…" in h[1] or len(h[1]) <= 8 for h in hits)

    def test_scan_clean(self):
        from kalitui.profiles.secret_scan import _scan

        assert _scan("var x = 42; console.log('hello');") == []

    @pytest.mark.asyncio
    async def test_exec_hit(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "const key = 'AKIAIOSFODNN7EXAMPLE';"

        stub = Stub()
        monkeypatch.setattr(P.secret_scan, "check_installed", lambda t: t == "curl")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["secret_scan"](stub, {"url": "http://t.com/app.js"})
        assert "发现硬编码密钥 (1 处)" in out
        assert "AWS Access Key" in out

    @pytest.mark.asyncio
    async def test_exec_clean_and_bad_url(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "console.log('clean');"

        stub = Stub()
        monkeypatch.setattr(P.secret_scan, "check_installed", lambda t: t == "curl")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["secret_scan"](stub, {"url": "http://t.com/app.js"})
        assert "未发现硬编码密钥" in out
        assert "git_leak" in out

        out2 = await stub.extensions["secret_scan"](stub, {"url": "javascript:alert(1)"})
        assert "格式非法" in out2


def test_port_fallback_completeness():
    """端口回退表覆盖所有已定制 profile 的常见端口。"""
    from kalitui.profiles.playbook import _PORT_FALLBACK, _suggest

    # 关键端口都有建议（不落回"服务未知"通用提示）
    for port, svc in ((161, "snmp"), (2049, "nfs"), (1521, "oracle"),
                      (5900, "vnc"), (69, "tftp"), (445, "microsoft-ds"),
                      (3389, "ms-wbt-server"), (5985, "winrm")):
        suggest = _suggest(port, svc)
        assert suggest, (port, svc)
        assert "暂无专用档案" not in suggest[0], (port, svc)

    # 1521 已修正为 oracle（不再误报 mssql）
    assert _PORT_FALLBACK[1521] == "oracle"
    assert _PORT_FALLBACK[2049] == "nfs"
    assert "nfs_enum" in " ".join(_suggest(2049, "nfs"))
    assert "hydra_brute" in " ".join(_suggest(1521, "oracle"))


class TestLinpeasWindows:
    @pytest.mark.asyncio
    async def test_windows_uses_winpeas(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert arguments["command"] == "winpeas -q"
                return "[+] SeImpersonatePrivilege token enabled\n[!] weak ACL\n"

        stub = Stub()
        monkeypatch.setattr(P.linpeas, "check_installed",
                            lambda t: t == "winpeas")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["linpeas"](
            stub, {"os": "windows", "quick": True}
        )
        assert "winpeas 提权线索 (1 条)" in out
        assert "SeImpersonatePrivilege" in out

    @pytest.mark.asyncio
    async def test_windows_not_installed(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.linpeas, "check_installed", lambda t: False)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["linpeas"](stub, {"os": "windows"})
        assert "winpeas 未安装" in out


# ---------------------------------------------------------------------------
# rsync_enum：无认证模块枚举
# ---------------------------------------------------------------------------
class TestRsyncEnum:
    def test_build_cmd(self):
        from kalitui.profiles.rsync import _build_cmd

        assert "rsync --list-only --timeout=10 rsync://10.0.0.5/" in _build_cmd("10.0.0.5")

    def test_parse(self):
        from kalitui.profiles.rsync import _parse

        raw = (
            "backup          Backup data dir\n"
            "www             Web root\n"
            "@ERROR: auth failed on module backup\n"
            "rsync: connection unexpectedly closed\n"
        )
        mods = _parse(raw)
        assert any(m.startswith("backup") for m in mods)
        assert any(m.startswith("www") for m in mods)
        assert not any("auth failed" in m for m in mods)

    @pytest.mark.asyncio
    async def test_exec_hit(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "backup  Backup data\nwww  Web root\n"

        stub = Stub()
        monkeypatch.setattr(P.rsync, "check_installed", lambda t: t == "rsync")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["rsync_enum"](stub, {"target": "10.0.0.5"})
        assert "rsync 模块 (2 个" in out
        assert "backup" in out
        assert "read only" in out

    @pytest.mark.asyncio
    async def test_exec_miss(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "rsync: connection refused\n"

        stub = Stub()
        monkeypatch.setattr(P.rsync, "check_installed", lambda t: t == "rsync")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["rsync_enum"](stub, {"target": "10.0.0.5"})
        assert "未发现可枚举的 rsync 模块" in out
        assert "873" in out


# ---------------------------------------------------------------------------
# sslscan / theharvester / netdiscover 边界分支
# ---------------------------------------------------------------------------
class TestSslscanExtra:
    def test_build_cmd_sni_and_invalid(self):
        from kalitui.profiles.sslscan import _build_cmd

        cmd, t = _build_cmd({"host": "example.com", "port": 993, "sni": "mail.example.com"})
        assert "--sni-name mail.example.com" in cmd and "example.com:993" in cmd
        with pytest.raises(ValueError):
            _build_cmd({"host": "example.com", "sni": "bad sni!"})

    def test_summarize_branches(self):
        from kalitui.profiles.sslscan import _summarize

        raw = (
            "Accepted  TLSv1.2  256 bits  AES256-GCM-SHA384\n"
            "Accepted  TLSv1.0  128 bits  RC4-SHA\n"
            "  Subject:  example.com\n"
            "  Not valid before: 2024-01-01\n"
        )
        s = _summarize(raw)
        assert "支持的协议/套件" in s
        assert "RC4" in s  # 弱点提取
        assert "证书" in s

        s2 = _summarize("Connection refused\n")
        assert "扫描无结果" in s2


class TestTheHarvesterExtra:
    def test_summarize_empty_and_hosts(self):
        from kalitui.profiles.theharvester import _summarize

        s = _summarize("no results here\n")
        assert "未收集到结果" in s

        raw = "vpn.example.com\nmail.example.com:10.0.0.5\nadmin@example.com\n"
        s2 = _summarize(raw)
        assert "子域/主机 (2)" in s2
        assert "vpn.example.com" in s2
        assert "admin@example.com" in s2


class TestNetdiscoverExtra:
    def test_summarize_empty(self):
        from kalitui.profiles.netdiscover import _summarize

        s = _summarize("nothing\n")
        assert "未发现" in s or "无" in s


# ---------------------------------------------------------------------------
# hping3 / redis / netcat 边界分支
# ---------------------------------------------------------------------------
class TestHping3Extra:
    def test_summarize_no_reply(self):
        from kalitui.profiles.hping3 import _summarize

        assert "无响应" in _summarize("no packets\n")
        s = _summarize("len=46 ip=10.0.0.5 flags=SA\n")
        assert "响应包（前 15 条）" in s

    @pytest.mark.asyncio
    async def test_exec_not_installed(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.hping3, "check_installed", lambda t: False)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["hping_probe"](stub, {"target": "10.0.0.5"})
        assert "未安装" in out


class TestRedisExtra:
    @pytest.mark.asyncio
    async def test_exec_noauth_and_unreachable(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "NOAUTH" in cmd:
                    return "NOAUTH Authentication required."
                return "Connection refused"

        stub = Stub()
        monkeypatch.setattr(P.redis, "check_installed", lambda t: t == "redis-cli")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["redis_check"](stub, {"host": "10.0.0.5", "password": "NOAUTH"})
        assert "需要密码" in out
        out2 = await stub.extensions["redis_check"](stub, {"host": "10.0.0.5"})
        assert "无法连接" in out2


class TestNetcatExtra:
    @pytest.mark.asyncio
    async def test_exec_connect_data_and_empty(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                if "printf" in arguments["command"]:
                    return "220 FTP ready"
                return ""

        stub = Stub()
        monkeypatch.setattr(P.netcat, "_nc_bin", lambda: "nc")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["nc_connect"](
            stub, {"host": "10.0.0.5", "port": 21, "data": "HELP"})
        assert "220 FTP ready" in out
        out2 = await stub.extensions["nc_connect"](stub, {"host": "10.0.0.5", "port": 22})
        assert "无响应" in out2


# ---------------------------------------------------------------------------
# tshark / secretsdump / smtpenum / hashid / getnpusers / testssl 边界
# ---------------------------------------------------------------------------
class TestTsharkExtra:
    def test_summarize_rows_and_empty(self):
        from kalitui.profiles.tshark import _summarize

        s = _summarize("1\t00:00\t10.0.0.1\t10.0.0.5\tTCP\tSYN\n")
        assert "抓包明细（前 30 条）" in s
        assert "未抓到包" in _summarize("no packets\n")

    def test_build_cmd_filter_and_display(self):
        from kalitui.profiles.tshark import _build_cmd

        cmd, t = _build_cmd({"filter": "port 80", "display": "http.request", "seconds": 5, "interface": "eth0"})
        assert "-f 'port 80'" in cmd and "-Y http.request" in cmd and "-i eth0" in cmd


class TestSecretsdumpExtra:
    @pytest.mark.asyncio
    async def test_exec_hashes_and_none(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                if "10.0.0.5" in arguments["command"]:
                    return "DOMAIN\\admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
                return "[-] no hashes\n"

        stub = Stub()
        monkeypatch.setattr(P.secretsdump, "_bin", lambda: "secretsdump")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["secrets_dump"](stub, {"host": "10.0.0.5", "username": "admin", "password": "x"})
        assert "提取到凭据 (1)" in out
        out2 = await stub.extensions["secrets_dump"](stub, {"host": "10.0.0.6", "username": "admin", "password": "x"})
        assert "未提取到 hash" in out2


class TestSmtpenumExtra:
    @pytest.mark.asyncio
    async def test_exec_valid_and_none(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                if "10.0.0.5" in arguments["command"]:
                    return "admin@example.com is a valid user\n"
                return "no valid users\n"

        stub = Stub()
        monkeypatch.setattr(P.smtpenum, "check_installed", lambda t: t == "smtp-user-enum")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["smtp_enum"](stub, {"host": "10.0.0.5"})
        assert "有效用户 (1)" in out
        out2 = await stub.extensions["smtp_enum"](stub, {"host": "10.0.0.6"})
        assert "未枚举到有效用户" in out2


class TestHashidExtra:
    @pytest.mark.asyncio
    async def test_exec_lines_and_empty(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                if "crackme" in arguments["command"]:
                    return "[MD5] [MD5(Unix)]\n"
                return "Analyzing 'abc'\n"

        stub = Stub()
        monkeypatch.setattr(P.hashid, "check_installed", lambda t: t == "hashid")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["hash_id"](stub, {"hash": "crackme"})
        assert "hash 类型候选 (1)" in out
        assert "crack_hash" in out
        out2 = await stub.extensions["hash_id"](stub, {"hash": "d" * 64})
        assert "未能识别" in out2


class TestGetnpusersExtra:
    @pytest.mark.asyncio
    async def test_exec_hashes_and_none(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}
                self.calls = 0

            async def execute(self, name, arguments):
                self.calls += 1
                if self.calls == 1:
                    return "$krb5asrep$23$user@DOMAIN:abc123\n"
                return "no hashes\n"

        stub = Stub()
        monkeypatch.setattr(P.getnpusers, "_bin", lambda: "GetNPUsers")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["asrep_roast"](stub, {"domain": "DOMAIN", "host": "dc"})
        assert "AS-REP hash (1)" in out
        out2 = await stub.extensions["asrep_roast"](stub, {"domain": "DOMAIN", "host": "dc2"})
        assert "未获取到 AS-REP hash" in out2


class TestTestsslExtra:
    def test_summarize_results_weak_empty(self):
        from kalitui.profiles.testssl import _summarize

        raw = "Testing protocols via sockets\nSSLv3  offered\nOK  TLS1.2\nHeartbleed  vulnerable\n"
        s = _summarize(raw)
        assert "TLS 检测结果" in s
        assert "弱点项" in s
        assert "检测无结果" in _summarize("connection refused\n")


# ---------------------------------------------------------------------------
# getuserspns / impexec / macchanger / nuclei / socat / msfvenom 边界
# ---------------------------------------------------------------------------
class TestGetuserspnsExtra:
    @pytest.mark.asyncio
    async def test_exec_hashes_and_none(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}
                self.calls = 0

            async def execute(self, name, arguments):
                self.calls += 1
                if self.calls == 1:
                    return "$krb5tgs$23$svc@DOMAIN:hash123\n"
                return "no hashes\n"

        stub = Stub()
        monkeypatch.setattr(P.getuserspns, "_bin", lambda: "GetUserSPNs")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["kerberoast"](stub, {"domain": "DOMAIN", "host": "dc", "username": "user", "password": "pass"})
        assert "TGS hash (1)" in out
        out2 = await stub.extensions["kerberoast"](stub, {"domain": "DOMAIN", "host": "dc", "username": "user", "password": "pass"})
        assert "未获取到 TGS hash" in out2


class TestImpexecExtra:
    @pytest.mark.asyncio
    async def test_exec_methods(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}
                self.calls = 0

            async def execute(self, name, arguments):
                self.calls += 1
                if self.calls == 1:
                    return "C:\\Windows\\system32> whoami\n"
                return "[-] Error\n"

        stub = Stub()
        monkeypatch.setattr(P.impexec, "_bin", lambda mode: "impacket-wmiexec")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["imp_exec"](stub, {"host": "10.0.0.5", "username": "a", "password": "x"})
        assert "whoami" in out or "命令" in out
        out2 = await stub.extensions["imp_exec"](stub, {"host": "10.0.0.6", "username": "a", "password": "x"})
        assert "[-] Error" in out2


class TestMacchangerExtra:
    @pytest.mark.asyncio
    async def test_exec_set_and_none(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}
                self.calls = 0

            async def execute(self, name, arguments):
                self.calls += 1
                if self.calls == 1:
                    return "Current MAC: aa:bb:cc:dd:ee:ff\nPermanent MAC: aa:bb:cc:dd:ee:ff\n"
                return "ERROR: Can't change MAC\n"

        stub = Stub()
        monkeypatch.setattr(P.macchanger, "check_installed", lambda t: t == "macchanger")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["mac_change"](stub, {"interface": "eth0", "action": "set", "mac": "aa:bb:cc:dd:ee:ff"})
        assert "Current MAC" in out
        out2 = await stub.extensions["mac_change"](stub, {"interface": "eth0", "action": "set", "mac": "aa:bb:cc:dd:ee:ff"})
        assert "ERROR" in out2


class TestNucleiExtra:
    def test_summarize_empty_and_template(self):
        from kalitui.profiles.nuclei import _summarize

        s = _summarize("")
        assert "未命中" in s or "无" in s
        s2 = _summarize("[foo] [http] [info] title: admin\n")
        assert "title: admin" in s2

    @pytest.mark.asyncio
    async def test_exec_no_hits(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "[INF] No results\n"

        stub = Stub()
        monkeypatch.setattr(P.nuclei, "check_installed", lambda t: t == "nuclei")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["nuclei_scan"](stub, {"target": "http://t.com"})
        assert "未命中" in out


class TestSocatExtra:
    @pytest.mark.asyncio
    async def test_exec_listen_and_connect(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}
                self.calls = 0

            async def execute(self, name, arguments):
                self.calls += 1
                if self.calls == 1:
                    return "listening...\n"
                return "connected\n"

        stub = Stub()
        monkeypatch.setattr(P.socat, "check_installed", lambda t: t == "socat")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["socat_tunnel"](stub, {"mode": "listen", "listen_port": 4444, "target_host": "10.0.0.6", "target_port": 80})
        assert "监听" in out or "listening" in out
        out2 = await stub.extensions["socat_tunnel"](stub, {"mode": "connect", "listen_port": 4444, "target_host": "10.0.0.6", "target_port": 80})
        assert "connected" in out2 or "连接" in out2


class TestMsfvenomExtra:
    def test_build_cmd_payload(self):
        from kalitui.profiles.msfvenom import _build_cmd

        cmd, _t = _build_cmd({"payload": "linux/x64/shell/reverse_tcp",
                              "lhost": "10.0.0.5", "lport": 4444,
                              "format": "elf", "outfile": "/tmp/p.elf"})
        assert "linux/x64/shell/reverse_tcp" in cmd and "LHOST=10.0.0.5" in cmd
        assert "-f elf" in cmd and "-o /tmp/p.elf" in cmd


# ---------------------------------------------------------------------------
# joomla_scan：Joomla 专项扫描
# ---------------------------------------------------------------------------
class TestJoomlaScan:
    def test_build_cmd_and_parse(self):
        from kalitui.profiles.joomscan import _build_cmd, _parse

        cmd = _build_cmd("http://t.com/", True)
        assert "joomscan -u 'http://t.com' --enumerate-components" in cmd
        assert "head -80" in cmd
        cmd2 = _build_cmd("http://t.com/", False)
        assert "--enumerate-components" not in cmd2

        raw = (
            "[+] Joomla! version 3.9.24\n"
            "[+] SQL injection in component com_jce\n"
            "[+] CVE-2019-12345\n"
            "[+] Not vulnerable to X\n"
        )
        version, vulns = _parse(raw)
        assert version == "3.9.24"
        assert any("com_jce" in v for v in vulns)
        assert any("CVE-2019-12345" in v for v in vulns)
        assert not any("Not vulnerable" in v for v in vulns)

    @pytest.mark.asyncio
    async def test_exec_hit(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert "--enumerate-components" in arguments["command"]
                return "[+] Joomla! version 3.10.5\n[+] component com_jce vulnerable\n"

        stub = Stub()
        monkeypatch.setattr(P.joomscan, "check_installed", lambda t: t == "joomscan")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["joomla_scan"](stub, {"url": "http://t.com/"})
        assert "Joomla 版本: 3.10.5" in out
        assert "漏洞信号" in out

    @pytest.mark.asyncio
    async def test_exec_not_joomla_and_bad_url(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "[-] Target not Joomla\n"

        stub = Stub()
        monkeypatch.setattr(P.joomscan, "check_installed", lambda t: t == "joomscan")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["joomla_scan"](stub, {"url": "http://t.com/", "enumerate": False})
        assert "未识别到 Joomla" in out
        out2 = await stub.extensions["joomla_scan"](stub, {"url": "ftp://x"})
        assert "格式非法" in out2


# ---------------------------------------------------------------------------
# playbook：解析函数 + bounty_recon 容错分支
# ---------------------------------------------------------------------------
class TestPlaybookParsers:
    def test_parse_dir_results(self):
        from kalitui.profiles.playbook import _parse_dir_results

        out = _parse_dir_results(
            "/admin            (Status: 200)\n/api             (Status: 301)\n"
            "/missing         (Status: 404)\n"
        )
        assert "/admin(200)" in out and "/api(301)" in out
        assert not any("404" in r for r in out)

    def test_parse_nuclei_dedup(self):
        from kalitui.profiles.playbook import _parse_nuclei

        hits = _parse_nuclei(
            "[critical] CVE-2024-1234 RCE\n[low] CVE-2024-1234 RCE\n"
            "[info] nothing\n[CVE-2024-5678] XSS\n"
        )
        assert len(hits) == 3

    def test_suggest_fallback_branches(self):
        from kalitui.profiles.playbook import _suggest

        # 直接命中 / 子串命中
        assert _suggest(22, "ssh") == ["hydra_brute（ssh 弱口令）"]
        assert any("hydra" in s for s in _suggest(22, "ssh-2.0"))
        # 端口回退（未知服务但端口有名）
        assert any("rsync" in s for s in _suggest(873, "unknown"))
        # 完全未知
        assert "暂无专用档案" in _suggest(12345, "weirdsvc")[0]


class TestBountyReconExtra:
    @pytest.mark.asyncio
    async def test_bounty_ip_target_skips_subenum(self, monkeypatch):
        """IP 目标：跳过子域发现；web 深化未装工具时给出跳过提示。"""
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "nmap" in cmd and "-sn" not in cmd:
                    return "Nmap scan report for 10.0.0.5\n80/tcp open  http\n443/tcp open  https\n"
                return "Nmap scan report for 10.0.0.5\n"

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed", lambda t: t == "nmap")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["bounty_recon"](
            stub, {"target": "10.0.0.5", "sub_enum": True})
        assert "跳过子域发现" in out
        assert "Web 深化] 跳过" in out

    @pytest.mark.asyncio
    async def test_bounty_subenum_fail_and_httpx(self, monkeypatch):
        """域名目标：crtsh 查到子域 + httpx 存活探测；waf 检测失败容错。"""
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}
                self.calls = 0

            async def execute(self, name, arguments):
                self.calls += 1
                cmd = arguments["command"]
                if "curl" in cmd and "crt.sh" in cmd:
                    return '[{"name_value": "vpn.example.com"}, {"name_value": "mail.example.com"}]\n' 
                if "httpx" in cmd:
                    return "http://vpn.example.com [200]\nhttp://mail.example.com [301]\n"
                if "wafw00f" in cmd:
                    raise RuntimeError("boom")
                if "nmap" in cmd and "-sn" not in cmd:
                    return "Nmap scan report for example.com\n80/tcp open  http\n"
                return "Nmap scan report for example.com\n"

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed", lambda t: t in ("nmap", "curl", "httpx", "wafw00f", "gobuster", "nuclei"))
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["bounty_recon"](
            stub, {"target": "example.com", "sub_enum": True, "web_check": True, "vuln_scan": True})
        assert "子域发现" in out and "vpn.example.com" in out
        assert "存活子域" in out
        assert "WAF: 检测失败（跳过）" in out
        assert "nuclei" in out  # 模板扫描小节存在


# ---------------------------------------------------------------------------
# ldapsearch / msf / netdiscover / msfvenom 边界
# ---------------------------------------------------------------------------
class TestLdapsearchExtra:
    @pytest.mark.asyncio
    async def test_exec_entries_and_empty(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}
                self.calls = 0

            async def execute(self, name, arguments):
                self.calls += 1
                if self.calls == 1:
                    return "dn: CN=admin,DC=corp\nsAMAccountName: admin\n"
                return "no results\n"

        stub = Stub()
        monkeypatch.setattr(P.ldapsearch, "check_installed", lambda t: t == "ldapsearch")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["ldap_enum"](
            stub, {"host": "10.0.0.5", "base": "DC=corp", "filter": "(objectClass=*)"})
        assert "LDAP 条目 (1)" in out
        out2 = await stub.extensions["ldap_enum"](
            stub, {"host": "10.0.0.5", "base": "DC=corp"})
        assert "无结果" in out2

    def test_build_cmd_creds(self):
        from kalitui.profiles.ldapsearch import _build_cmd

        cmd, _t = _build_cmd({"host": "10.0.0.5", "base": "DC=corp",
                              "username": "admin", "password": "x"})
        assert "-D admin" in cmd and "-w x" in cmd


class TestMsfExtra:
    @pytest.mark.asyncio
    async def test_exec_msf_run_empty(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "some plain output\n"

        stub = Stub()
        monkeypatch.setattr(P.msf, "check_installed", lambda t: t == "msfconsole")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["msf_run"](stub, {"module": "auxiliary/scanner/ssh/ssh_version"})
        assert "无关键事件行" in out

    def test_build_script_options_validation(self):
        from kalitui.profiles.msf import _build_script

        with pytest.raises(ValueError):
            _build_script({"options": "not-a-dict"}, search=False)
        with pytest.raises(ValueError):
            _build_script({"options": {"bad name!": "x"}}, search=False)


class TestNetdiscoverExtra:
    @pytest.mark.asyncio
    async def test_exec_active_and_passive(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}
                self.calls = 0

            async def execute(self, name, arguments):
                self.calls += 1
                if "passive" in arguments["command"] or "-p" in arguments["command"]:
                    return "nothing\n"
                return "1 10.0.0.1 00:11:22:33:44:55 vendor\n"

        stub = Stub()
        monkeypatch.setattr(P.netdiscover, "check_installed", lambda t: t == "netdiscover")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["net_discover"](
            stub, {"range": "10.0.0.0/24", "mode": "active"})
        assert "发现主机 (1)" in out
        out2 = await stub.extensions["net_discover"](
            stub, {"range": "10.0.0.0/24", "mode": "passive"})
        assert "未发现主机" in out2

    def test_build_cmd_invalid_mode(self):
        from kalitui.profiles.netdiscover import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"range": "10.0.0.0/24", "mode": "loud"})


class TestMsfvenomExtra2:
    def test_build_cmd_invalid_values(self):
        from kalitui.profiles.msfvenom import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"payload": "bad/payload"})
        with pytest.raises(ValueError):
            _build_cmd({"payload": "linux/x64/shell/reverse_tcp",
                        "lhost": "10.0.0.5; rm -rf /", "lport": 4444})
        with pytest.raises(ValueError):
            _build_cmd({"payload": "linux/x64/shell/reverse_tcp",
                        "lhost": "10.0.0.5", "lport": 99999})
        with pytest.raises(ValueError):
            _build_cmd({"payload": "linux/x64/shell/reverse_tcp",
                        "lhost": "10.0.0.5", "lport": 4444, "format": "no-such-fmt"})
        with pytest.raises(ValueError):
            _build_cmd({"payload": "linux/x64/shell/reverse_tcp",
                        "lhost": "10.0.0.5", "lport": 4444, "outfile": "/etc/passwd"})


class TestSqlmapExtra:
    def test_build_cmd_data_cookie(self):
        from kalitui.profiles.sqlmap import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"url": "http://t.com/?id=1", "data": "a=b; rm -rf /"})
        cmd, _t = _build_cmd({"url": "http://t.com/?id=1", "data": "a=1&b=2",
                              "cookie": "sid=abc; PHPSESSID=x", "level": 3, "risk": 2})
        assert "--data a=1&b=2" in cmd
        assert "--cookie 'sid=abc; PHPSESSID=x'" in cmd
        assert "--level 3" in cmd and "--risk 2" in cmd and "--smart" in cmd

    def test_summarize_payloads(self):
        from kalitui.profiles.sqlmap import _summarize

        s = _summarize(
            "Parameter: id (GET) is vulnerable\nPayload: id=1 AND 1=2\n"
        )
        assert "检测到注入点" in s and "Payload" in s
        s2 = _summarize("no injection found\n")
        assert "未检测到可注入参数" in s2


# ---------------------------------------------------------------------------
# bloodhound_py：AD 域关系采集
# ---------------------------------------------------------------------------
class TestBloodHound:
    def test_build_cmd_password_and_hash(self):
        from kalitui.profiles.bloodhound import _build_cmd

        cmd, t = _build_cmd("corp.local", "john", "Passw0rd!", "", "")
        assert "bloodhound-python -d corp.local -u john" in cmd and "-p Passw0rd!" in cmd
        assert "--zip" in cmd and "-c All" in cmd
        cmd2, _t = _build_cmd("corp.local", "john", "", "31d6cfe0d16ae931b73c59d7e0c089c0", "dc1")
        assert "-k 31d6cfe0d16ae931b73c59d7e0c089c0" in cmd2
        assert "--dc dc1" in cmd2

    def test_summarize_done_and_fail(self):
        from kalitui.profiles.bloodhound import _summarize

        s = _summarize("users: 1234\ngroups: 56\nDone in 01M 02S\n")
        assert "AD 采集完成" in s
        assert "users: 1234" in s
        s2 = _summarize("[-] Failed to connect\n")
        assert "采集未完成" in s2

    @pytest.mark.asyncio
    async def test_exec_success(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert "-c All" in arguments["command"]
                return "users: 42\nDone in 00M 05S\n"

        stub = Stub()
        monkeypatch.setattr(P.bloodhound, "check_installed", lambda t: t == "bloodhound-python")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["bloodhound_py"](
            stub, {"domain": "corp.local", "username": "john", "password": "x"})
        assert "AD 采集完成" in out

    @pytest.mark.asyncio
    async def test_exec_validation(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.bloodhound, "check_installed", lambda t: t == "bloodhound-python")
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["bloodhound_py"](
                stub, {"domain": "corp.local", "username": "john"})  # 密码/hash 都没给
        with pytest.raises(ValueError):
            await stub.extensions["bloodhound_py"](
                stub, {"domain": "corp.local", "username": "john",
                       "password": "x", "hash": "badhash"})
        out = await stub.extensions["bloodhound_py"](
            stub, {"domain": "corp.local", "username": "john", "hash": "31d6cfe0d16ae931b73c59d7e0c089c0"})
        assert isinstance(out, str)


class TestPlaybookPortFallback2:
    def test_new_port_fallbacks(self):
        from kalitui.profiles.playbook import _suggest

        assert any("REST" in s for s in _suggest(9200, "unknown"))
        assert any("stats" in s for s in _suggest(11211, "unknown"))
        assert any("containers" in s for s in _suggest(2375, "unknown"))
        assert any("webmin" in s for s in _suggest(10000, "unknown"))
        assert any("管理台" in s for s in _suggest(7001, "unknown"))
        assert any("Kibana" in s for s in _suggest(5601, "unknown"))
        assert any("http_req" in s for s in _suggest(8000, "unknown"))
        assert any("http_req" in s for s in _suggest(8888, "unknown"))


# ---------------------------------------------------------------------------
# masscan：SRC 网段快速发现
# ---------------------------------------------------------------------------
class TestMasscan:
    def test_build_cmd(self):
        from kalitui.profiles.masscan import _build_cmd

        cmd, t = _build_cmd("10.0.0.0/24", "80,443", 5000)
        assert "masscan --rate 5000 -p 80,443" in cmd
        assert "--wait 5 10.0.0.0/24" in cmd
        assert t == 420
        cmd2, _t = _build_cmd("10.0.0.0/24", "", 1000)
        assert "-p 1-10000" in cmd2

    def test_summarize_found_and_empty(self):
        from kalitui.profiles.masscan import _summarize

        s = _summarize("Discovered open port 22/tcp on 10.0.0.5\n"
                       "Discovered open port 80/tcp on 10.0.0.5\n"
                       "Discovered open port 445/tcp on 10.0.0.9\n")
        assert "2 台主机" in s
        assert "3 个开放端口" in s
        assert "10.0.0.5:22" in s
        assert "nmap -sV" in s
        s2 = _summarize("packets: 1000 received\n")
        assert "未发现开放端口" in s2

    @pytest.mark.asyncio
    async def test_exec_success(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert "--rate 1000" in arguments["command"]
                return "Discovered open port 443/tcp on 10.0.0.7\n"

        stub = Stub()
        monkeypatch.setattr(P.masscan, "check_installed", lambda t: t == "masscan")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["masscan"](stub, {"target": "10.0.0.0/24"})
        assert "1 台主机" in out

    @pytest.mark.asyncio
    async def test_exec_validation(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.masscan, "check_installed", lambda t: t == "masscan")
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["masscan"](stub, {"target": ""})
        with pytest.raises(ValueError):
            await stub.extensions["masscan"](stub, {"target": "10.0.0.0/24", "ports": "a;b"})
        with pytest.raises(ValueError):
            await stub.extensions["masscan"](stub, {"target": "10.0.0.0/24", "rate": "fast"})
        with pytest.raises(ValueError):
            await stub.extensions["masscan"](stub, {"target": "10.0.0.0/24", "rate": 0})


# ---------------------------------------------------------------------------
# kerbrute：无凭据 AD 用户枚举 / 密码喷洒
# ---------------------------------------------------------------------------
class TestKerbrute:
    def test_build_cmd_userenum_and_spray(self):
        from kalitui.profiles.kerbrute import _build_cmd

        cmd, t = _build_cmd("corp.local", "users.txt", "", "")
        assert cmd.startswith("kerbrute userenum -d corp.local")
        assert "users.txt" in cmd
        cmd2, _t = _build_cmd("corp.local", "admin,guest", "Summer2024", "10.0.0.1")
        assert cmd2.startswith("kerbrute passwordspray -d corp.local --dc 10.0.0.1 admin guest -p Summer2024")
        assert t == 240

    def test_summarize_found_and_none(self):
        from kalitui.profiles.kerbrute import _summarize

        s = _summarize("[+] VALID USERNAME: admin\n[+] VALID USERNAME: svc_backup\n")
        assert "有效用户 2 个" in s
        assert "admin" in s and "svc_backup" in s
        assert "getnpusers" in s
        s2 = _summarize("[-] KDC_ERR_C_PRINCIPAL_UNKNOWN\n")
        assert "未发现有效用户" in s2

    @pytest.mark.asyncio
    async def test_exec_success(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert "userenum" in arguments["command"]
                return "[+] VALID USERNAME: john\n"

        stub = Stub()
        monkeypatch.setattr(P.kerbrute, "check_installed", lambda t: t == "kerbrute")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["kerbrute"](stub, {"domain": "corp.local", "userlist": "users.txt"})
        assert "有效用户 1 个" in out

    @pytest.mark.asyncio
    async def test_exec_validation(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.kerbrute, "check_installed", lambda t: t == "kerbrute")
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["kerbrute"](stub, {"domain": "bad domain!", "userlist": "x"})
        with pytest.raises(ValueError):
            await stub.extensions["kerbrute"](stub, {"domain": "corp.local", "userlist": ""})
        with pytest.raises(ValueError):
            await stub.extensions["kerbrute"](stub, {"domain": "corp.local", "userlist": "a b"})
        out = await stub.extensions["kerbrute"](
            stub, {"domain": "corp.local", "userlist": "admin,guest", "password": "x"})
        assert isinstance(out, str)


# ---------------------------------------------------------------------------
# whatweb：Web 技术栈指纹
# ---------------------------------------------------------------------------
class TestWhatWeb:
    def test_build_cmd(self):
        from kalitui.profiles.whatweb import _build_cmd

        cmd, t = _build_cmd("http://example.com", 1)
        assert cmd == "whatweb -a 1 --color=never http://example.com"
        assert t == 120

    def test_summarize_tech_and_empty(self):
        from kalitui.profiles.whatweb import _summarize

        raw = ("http://example.com [200 OK] Apache[2.4.57] PHP[8.1] WordPress[6.4] "
               "X-Powered-By[PHP/8.1] [title] example")
        s = _summarize(raw)
        assert "技术栈" in s
        assert "Apache" in s and "WordPress" in s
        assert "wpscan" in s
        s2 = _summarize("https://x [403 Forbidden]\n")
        assert "未识别出技术栈" in s2

    @pytest.mark.asyncio
    async def test_exec_success(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert "-a 1" in arguments["command"]
                return "http://x [200 OK] Nginx[1.22] jQuery[3.6]\n"

        stub = Stub()
        monkeypatch.setattr(P.whatweb, "check_installed", lambda t: t == "whatweb")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["whatweb"](stub, {"url": "http://x"})
        assert "Nginx" in out

    @pytest.mark.asyncio
    async def test_exec_validation(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.whatweb, "check_installed", lambda t: t == "whatweb")
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["whatweb"](stub, {"url": "example.com"})  # 缺协议
        with pytest.raises(ValueError):
            await stub.extensions["whatweb"](stub, {"url": "http://x", "aggression": 9})
        with pytest.raises(ValueError):
            await stub.extensions["whatweb"](stub, {"url": "http://x", "aggression": "high"})
        out = await stub.extensions["whatweb"](stub, {"url": "http://x"})
        assert isinstance(out, str)


# ---------------------------------------------------------------------------
# drupwn：Drupal CMS 专项扫描
# ---------------------------------------------------------------------------
class TestDrupwn:
    def test_build_cmd_modes(self):
        from kalitui.profiles.drupwn import _build_cmd

        cmd, t = _build_cmd("http://example.com", "enumerate")
        assert cmd.startswith("drupwn --mode enumerate")
        cmd2, t2 = _build_cmd("http://example.com", "version_only")
        assert cmd2.startswith("drupwn --mode version")
        assert t == 120 and t2 == 120 or (t, t2) == (180, 120)

    def test_summarize_version_and_modules(self):
        from kalitui.profiles.drupwn import _summarize

        raw = ("Drupal 7.58\nModule: views\nModule: webform\n")
        s = _summarize(raw)
        assert "Drupal 版本: 7.58" in s
        assert "CVE-2014-3704" in s  # 7.x → Drupalgeddon1
        assert "views" in s and "webform" in s
        s2 = _summarize("Connection refused\n")
        assert "未识别出 Drupal 版本" in s2

    @pytest.mark.asyncio
    async def test_exec_success(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert "enumerate" in arguments["command"]
                return "Drupal 8.6.2\n"

        stub = Stub()
        monkeypatch.setattr(P.drupwn, "check_installed", lambda t: t == "drupwn")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["drupwn"](stub, {"url": "http://example.com"})
        assert "8.6.2" in out
        assert "CVE-2018-7600" in out  # 8.x → Drupalgeddon2

    @pytest.mark.asyncio
    async def test_exec_validation(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.drupwn, "check_installed", lambda t: t == "drupwn")
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["drupwn"](stub, {"url": "example.com"})
        with pytest.raises(ValueError):
            await stub.extensions["drupwn"](stub, {"url": "http://x", "mode": "exploit"})
        out = await stub.extensions["drupwn"](stub, {"url": "http://x", "mode": "version_only"})
        assert isinstance(out, str)


# ---------------------------------------------------------------------------
# subfinder：子域名被动枚举
# ---------------------------------------------------------------------------
class TestSubfinder:
    def test_build_cmd_silent(self):
        from kalitui.profiles.subfinder import _build_cmd

        cmd, t = _build_cmd("example.com", True)
        assert cmd == "subfinder -d example.com -silent"
        cmd2, _t = _build_cmd("example.com", False)
        assert cmd2 == "subfinder -d example.com"
        assert t == 240

    def test_summarize_found_and_none(self):
        from kalitui.profiles.subfinder import _summarize

        s = _summarize("api.example.com\nwww.example.com\napi.example.com\n"
                       "notmatching.com\n", "example.com")
        head = s.split("原始输出")[0]
        assert "2 个子域名" in head
        assert "api.example.com" in head
        assert "notmatching.com" not in head  # 非目标域过滤
        assert "httpx" in head
        s2 = _summarize("", "example.com")
        assert "未发现子域名" in s2

    @pytest.mark.asyncio
    async def test_exec_success(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert "-silent" in arguments["command"]
                return "admin.example.com\n"

        stub = Stub()
        monkeypatch.setattr(P.subfinder, "check_installed", lambda t: t == "subfinder")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["subfinder"](stub, {"domain": "example.com"})
        assert "admin.example.com" in out

    @pytest.mark.asyncio
    async def test_exec_validation(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.subfinder, "check_installed", lambda t: t == "subfinder")
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["subfinder"](stub, {"domain": ""})
        with pytest.raises(ValueError):
            await stub.extensions["subfinder"](stub, {"domain": "bad domain;ls"})
        with pytest.raises(ValueError):
            # 超长域名：过 sanitize 但被长度白名单拒绝
            await stub.extensions["subfinder"](stub, {"domain": "a" * 200 + ".com"})
        out = await stub.extensions["subfinder"](stub, {"domain": "example.com", "silent": False})
        assert isinstance(out, str)


# ---------------------------------------------------------------------------
# gau：历史 URL 收集
# ---------------------------------------------------------------------------
class TestGau:
    def test_build_cmd(self):
        from kalitui.profiles.gau import _build_cmd

        cmd, t = _build_cmd("example.com")
        assert cmd == "gau --threads 5 example.com"
        assert t == 240

    def test_summarize_high_value_and_empty(self):
        from kalitui.profiles.gau import _summarize

        raw = ("http://example.com/\nhttp://example.com/admin/login\n"
               "http://example.com/api/v1/users\nhttp://example.com/.env\n"
               "http://example.com/admin/login\nhttp://other.com/x\n")
        s = _summarize(raw)
        head = s.split("原始输出")[0]
        assert "历史 URL 5 条" in head
        assert "2 个主机" in head
        assert "高价值 3 条" in head
        assert ".env" in head
        s2 = _summarize("no urls here\n")
        assert "未收集到历史 URL" in s2

    @pytest.mark.asyncio
    async def test_exec_success(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert "example.com" in arguments["command"]
                return "http://example.com/backup.zip\n"

        stub = Stub()
        monkeypatch.setattr(P.gau, "check_installed", lambda t: t == "gau")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["gau"](stub, {"domain": "example.com"})
        assert "backup.zip" in out

    @pytest.mark.asyncio
    async def test_exec_validation(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.gau, "check_installed", lambda t: t == "gau")
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["gau"](stub, {"domain": ""})
        with pytest.raises(ValueError):
            await stub.extensions["gau"](stub, {"domain": "x;rm -rf /"})
        out = await stub.extensions["gau"](stub, {"domain": "example.com"})
        assert isinstance(out, str)


class TestGauNoHighValue:
    def test_summarize_no_high_value_branch(self):
        from kalitui.profiles.gau import _summarize

        s = _summarize("http://example.com/\nhttp://example.com/about\n")
        head = s.split("原始输出")[0]
        assert "无高价值关键字命中" in head


# ---------------------------------------------------------------------------
# dnsx：批量 DNS 解析验证
# ---------------------------------------------------------------------------
class TestDnsx:
    def test_build_cmd(self):
        from kalitui.profiles.dnsx import _build_cmd

        cmd, t = _build_cmd(["api.example.com", "www.example.com"], True)
        assert cmd == "dnsx -a -silent -d api.example.com www.example.com"
        cmd2, _t = _build_cmd(["x.example.com"], False)
        assert cmd2 == "dnsx -silent -d x.example.com"
        assert t == 120

    def test_summarize_pairs_and_none(self):
        from kalitui.profiles.dnsx import _summarize

        s = _summarize("api.example.com [1.2.3.4]\nwww.example.com [5.6.7.8, 9.10.11.12]\n")
        head = s.split("原始输出")[0]
        assert "解析成功 2/2" in head
        assert "api.example.com" in head
        s2 = _summarize("")
        assert "无域名解析成功" in s2

    @pytest.mark.asyncio
    async def test_exec_success(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert "-a -silent" in arguments["command"]
                return "api.example.com [1.2.3.4]\n"

        stub = Stub()
        monkeypatch.setattr(P.dnsx, "check_installed", lambda t: t == "dnsx")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["dnsx"](
            stub, {"domains": "api.example.com, www.example.com"})
        assert "api.example.com" in out

    @pytest.mark.asyncio
    async def test_exec_validation(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.dnsx, "check_installed", lambda t: t == "dnsx")
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["dnsx"](stub, {"domains": ""})
        with pytest.raises(ValueError):
            await stub.extensions["dnsx"](stub, {"domains": "a b"})
        with pytest.raises(ValueError):
            await stub.extensions["dnsx"](stub, {"domains": ",".join(f"d{i}.com" for i in range(201))})
        out = await stub.extensions["dnsx"](stub, {"domains": "a.example.com", "resolve": False})
        assert isinstance(out, str)


class TestDnsxExtra:
    def test_summarize_plain_format_and_many(self):
        from kalitui.profiles.dnsx import _summarize

        # 空格分隔格式 + 空行跳过
        s = _summarize("\napi.example.com 1.2.3.4\n\nold.example.com\n")
        head = s.split("原始输出")[0]
        assert "解析成功 2/2" in head
        assert "api.example.com → 1.2.3.4" in head
        assert "（无 A 记录）" in head
        # 31+ 域名 → 省略行
        many = "\n".join(f"d{i}.example.com [{i}.1.1.1]" for i in range(35))
        s2 = _summarize(many)
        assert "…等 35 个" in s2


# ---------------------------------------------------------------------------
# katana：JS 端点爬虫
# ---------------------------------------------------------------------------
class TestKatana:
    def test_build_cmd(self):
        from kalitui.profiles.katana import _build_cmd

        cmd, t = _build_cmd("http://example.com", True, 3)
        assert cmd == "katana -u http://example.com -d 3 -silent -jc"
        cmd2, _t = _build_cmd("http://example.com", False, 5)
        assert cmd2 == "katana -u http://example.com -d 5 -silent"
        assert t == 300

    def test_summarize_endpoints_and_empty(self):
        from kalitui.profiles.katana import _summarize

        raw = ("http://example.com/\nhttp://example.com/api/users\n"
               "http://example.com/admin/panel\nhttp://example.com/about\n")
        s = _summarize(raw)
        head = s.split("原始输出")[0]
        assert "提取端点 4 条" in head
        assert "高价值 API/管理端点 2 条" in head
        assert "/api/users" in head
        s2 = _summarize("nothing\n")
        assert "未提取到端点" in s2

    @pytest.mark.asyncio
    async def test_exec_success(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                assert "-jc" in arguments["command"]
                return "http://x/graphql\n"

        stub = Stub()
        monkeypatch.setattr(P.katana, "check_installed", lambda t: t == "katana")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["katana"](stub, {"url": "http://x"})
        assert "graphql" in out

    @pytest.mark.asyncio
    async def test_exec_validation(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.katana, "check_installed", lambda t: t == "katana")
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["katana"](stub, {"url": "x.com"})
        with pytest.raises(ValueError):
            await stub.extensions["katana"](stub, {"url": "http://x", "depth": 99})
        with pytest.raises(ValueError):
            await stub.extensions["katana"](stub, {"url": "http://x", "depth": "deep"})
        out = await stub.extensions["katana"](stub, {"url": "http://x", "js_only": False})
        assert isinstance(out, str)


class TestKatanaNoHigh:
    def test_summarize_no_high_value(self):
        from kalitui.profiles.katana import _summarize

        s = _summarize("http://example.com/\nhttp://example.com/about\n")
        head = s.split("原始输出")[0]
        assert "无 /api//admin/ 等关键字" in head


class TestPlaybookHighValuePorts:
    def test_src_high_value_port_fallbacks(self):
        from kalitui.profiles.playbook import _suggest

        assert any("Grafana" in s for s in _suggest(3000, "unknown"))
        assert any("actuator" in s for s in _suggest(8080, "unknown"))
        assert any("actuator" in s for s in _suggest(8081, "unknown"))
        assert any("targets" in s for s in _suggest(9090, "unknown"))
        assert any("SonarQube" in s for s in _suggest(9000, "unknown"))
        assert any("agent/services" in s for s in _suggest(8500, "unknown"))
        assert any("sys/health" in s for s in _suggest(8200, "unknown"))
        assert any("Kafka" in s for s in _suggest(9092, "unknown"))
        assert any("15672" in s for s in _suggest(15672, "unknown"))
        assert any("MinIO" in s for s in _suggest(9001, "unknown"))
        assert any("kv/range" in s for s in _suggest(2379, "unknown"))
        assert any("namespaces" in s for s in _suggest(6443, "unknown"))


class TestPlaybookClassicPorts:
    def test_classic_high_value_ports(self):
        from kalitui.profiles.playbook import _suggest

        assert any("Ghostcat" in s for s in _suggest(8009, "unknown"))
        assert any("GlassFish" in s for s in _suggest(4848, "unknown"))
        assert any("9300" in s for s in _suggest(9300, "unknown"))
        assert any("Sentinel" in s for s in _suggest(26379, "unknown"))


# ---------------------------------------------------------------------------
# base.py / __init__.py 剩余分支
# ---------------------------------------------------------------------------
class TestBaseBranches:
    def test_sanitize_target_cidr_prefix_errors(self):
        from kalitui.profiles.base import sanitize_target

        with pytest.raises(ValueError):
            sanitize_target("10.0.0.0/abc")   # 前缀非数字
        with pytest.raises(ValueError):
            sanitize_target("10.0.0.0/33")    # 前缀超 32
        assert sanitize_target("10.0.0.0/24") == "10.0.0.0/24"

    def test_sanitize_url_empty_and_query(self):
        from kalitui.profiles.base import sanitize_url, sanitize_wordlist

        with pytest.raises(ValueError):
            sanitize_url("  ")
        with pytest.raises(ValueError):
            sanitize_wordlist("")
        with pytest.raises(ValueError):
            sanitize_wordlist("/etc/passwd")

    def test_parse_ports_top_prefix(self):
        from kalitui.profiles.base import sanitize_ports

        assert sanitize_ports("top-50") == "top-50"
        assert sanitize_ports("80,443") == "80,443"

    def test_inventory_empty_and_no_match(self):
        import kalitui.profiles as P

        saved = list(P.REGISTRY)
        P.REGISTRY.clear()
        try:
            assert P.inventory() == ""
            assert P.lore_for([]) == ""
        finally:
            P.REGISTRY[:] = saved  # 恢复注册表


class TestRegistryMissingExec:
    def test_missing_exec_raises(self):
        """schema 名无对应 exec_ 方法 → AttributeError（注册表一致性）。"""
        import kalitui.profiles as P

        class BadProfile(P.ToolProfile):
            name = "bad_profile"
            extra_schemas = [{
                "type": "function",
                "function": {"name": "bad_profile", "description": "x", "parameters": {}},
            }]

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, n, a):
                return ""

        with pytest.raises(AttributeError):
            BadProfile().register(Stub())  # type: ignore[arg-type]


class TestBloodHoundValidationExtra:
    @pytest.mark.asyncio
    async def test_exec_validation_extra(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.bloodhound, "check_installed", lambda t: t == "bloodhound-python")
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["bloodhound_py"](
                stub, {"domain": "bad domain!", "username": "john", "password": "x"})
        with pytest.raises(ValueError):
            await stub.extensions["bloodhound_py"](
                stub, {"domain": "corp.local", "username": "bad user!", "password": "x"})
        with pytest.raises(ValueError):
            await stub.extensions["bloodhound_py"](
                stub, {"domain": "corp.local", "username": "john",
                       "hash": "not-a-hash"})


class TestCewlWordlistBranches:
    @pytest.mark.asyncio
    async def test_wordlist_missing_file_and_empty(self, monkeypatch, tmp_path):
        """词表文件缺失（OSError）与空文件两分支。"""
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return "Cewl 完成"

        stub = Stub()
        monkeypatch.setattr(P.cewl, "check_installed", lambda t: t == "cewl")
        monkeypatch.setattr(P.cewl, "_OUT_RE", type("R", (), {"match": lambda self, v: True})())
        P.register_extensions(stub)  # type: ignore[arg-type]

        # 文件不存在 → OSError → 0 词
        out = await stub.extensions["cewl_words"](
            stub, {"url": "http://x", "output": "/tmp/no-such-dir-xyz/w.txt"})
        assert "词表为空" in out or "词表已生成" not in out

        # 空文件存在 → 0 词
        empty = tmp_path / "empty.txt"
        empty.write_text("", encoding="utf-8")
        out2 = await stub.extensions["cewl_words"](
            stub, {"url": "http://x", "output": str(empty)})
        assert "词表为空" in out2


class TestChiselModeBranches:
    def test_remote_invalid(self):
        from kalitui.profiles.chisel import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"server": "10.0.0.5:8080", "remote": "R:9999"})  # remote 格式非法

    def test_mode_not_reverse(self):
        from kalitui.profiles.chisel import _build_cmd

        cmd, t = _build_cmd({"server": "10.0.0.5:8080", "remote": "R:3389:10.0.0.9:3389"})
        assert "chisel client 10.0.0.5:8080 R:3389:10.0.0.9:3389" in cmd
        cmd2, _ = _build_cmd({"server": "10.0.0.5:8080", "mode": "forward",
                              "remote": "R:3389:10.0.0.9:3389"})
        assert "chisel client 10.0.0.5:8080 R:3389:10.0.0.9:3389" in cmd2


class TestChiselTunnelEstablished:
    @pytest.mark.asyncio
    async def test_tunnel_established_head(self, monkeypatch):
        """输出含 'server: session' → 隧道建立提示。"""
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.chisel, "check_installed", lambda t: t == "chisel")

        async def fake_run(self, ex, cmd, **kw):
            return "server: session#1 established\nConnected\n其他行"

        monkeypatch.setattr(P.chisel.ChiselProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["chisel_tunnel"](
            stub, {"server": "10.0.0.5:8080", "remote": "R:3389:10.0.0.9:3389"})
        assert "隧道建立" in out


# ---------------------------------------------------------------------------
# crtsh / curl / aircrack / airmon 剩余分支
# ---------------------------------------------------------------------------
class TestCrtshExtra:
    @pytest.mark.asyncio
    async def test_parse_non_list_and_ip_target(self, monkeypatch):
        from kalitui import profiles as P

        assert P.crtsh._parse('{"not": "list"}', 60) == []
        assert P.crtsh._parse("not-json!!", 60) == []

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.crtsh, "check_installed", lambda t: True)
        monkeypatch.setattr(P.crtsh, "_build_cmd", lambda t: "curl -s x")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["crt_sh"](
            stub, {"target": "2001:db8:1:2:3:4:5:6"})  # sanitize 通过（IPv6）但非域名
        assert "域名格式非法" in out

    def test_parse_over_limit_note(self):
        from kalitui.profiles.crtsh import _parse

        raw = json.dumps([{"name_value": "a.example.com\nb.example.com"} for _ in range(80)])
        subs = _parse(raw, 60)
        assert len(subs) >= 2

    @pytest.mark.asyncio
    async def test_exec_over_limit_note(self, monkeypatch):
        """exec 时子域数 ≥ limit → 超出显示上限提示。"""
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.crtsh, "check_installed", lambda t: True)
        raw = json.dumps([{"name_value": f"sub{i}.example.com"} for i in range(90)])
        monkeypatch.setattr(P.crtsh, "_build_cmd", lambda t: "curl -s x")

        async def fake_run(self, ex, cmd, timeout=30):
            return raw

        monkeypatch.setattr(P.crtsh.CrtshProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["crt_sh"](
            stub, {"target": "example.com", "limit": 60})
        assert "超出显示上限" in out


class TestCurlExtra:
    def test_data_and_headers_invalid(self):
        from kalitui.profiles.curl import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"url": "http://x", "data": "bad\x00data"})
        with pytest.raises(ValueError):
            _build_cmd({"url": "http://x", "headers": "NoColonHere"})
        with pytest.raises(ValueError):
            _build_cmd({"url": "http://x", "cookie": "bad\x00cookie"})

    def test_body_over_25_lines(self):
        from kalitui.profiles.curl import _summarize

        body = "\n".join(f"line{i}" for i in range(40))
        out = _summarize(body + "\n200 12345", 100000)
        assert "共 40 行" in out

    def test_request_failed_branch(self):
        from kalitui.profiles.curl import _summarize

        out = _summarize("curl: (7) Failed to connect", 4000)
        assert "请求失败" in out


class TestAircrackUncracked:
    @pytest.mark.asyncio
    async def test_not_cracked_branch(self, monkeypatch, tmp_path):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.aircrack, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "No luck. Exiting."

        monkeypatch.setattr(P.aircrack.AircrackProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        cap = tmp_path / "x.cap"
        cap.write_bytes(b"\x00" * 16)
        out = await stub.extensions["wifi_crack"](
            stub, {"capture": str(cap), "wordlist": "/usr/share/wordlists/rockyou.txt"})
        assert "未破解成功" in out


class TestAirmonNoIface:
    @pytest.mark.asyncio
    async def test_no_iface_branch(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.airmon, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "no interface output here"

        monkeypatch.setattr(P.airmon.AirmonProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["wifi_monitor"](
            stub, {"interface": "wlan0"})
        assert "未检测到无线网卡" in out


# ---------------------------------------------------------------------------
# searchsploit 剩余分支（sploit_search / sploit_show）
# ---------------------------------------------------------------------------
class TestSearchsploitExtra:
    def test_check_keyword_errors(self):
        from kalitui.profiles.searchsploit import _check_keyword

        with pytest.raises(ValueError):
            _check_keyword("   ")
        with pytest.raises(ValueError):
            _check_keyword("x" * 121)
        with pytest.raises(ValueError):
            _check_keyword("vsftpd;rm -rf /")
        assert _check_keyword("  vsftpd 2.3.4  ") == "vsftpd 2.3.4"

    @pytest.mark.asyncio
    async def test_show_not_installed_and_bad_id_and_preview(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.searchsploit, "check_installed", lambda t: False)
        P.register_extensions(stub)  # type: ignore[arg-type]

        # 未安装
        out = await stub.extensions["sploit_show"](
            stub, {"exploit_id": "12345"})
        assert "未安装" in out

        # exploit_id 非法（安装已模拟，但先直接调 _check 逻辑）
        monkeypatch.setattr(P.searchsploit, "check_installed", lambda t: True)
        with pytest.raises(ValueError):
            await stub.extensions["sploit_show"](stub, {"exploit_id": "abc"})

        # preview 模式 → -x
        calls = []

        async def fake_run(self, ex, cmd, timeout=30):
            calls.append((cmd, timeout))
            return "Exploit Title | Path | Type"

        monkeypatch.setattr(P.searchsploit.SploitProfile, "_run", fake_run)
        await stub.extensions["sploit_show"](
            stub, {"exploit_id": "12345", "preview": True})
        assert calls and "-x 12345" in calls[-1][0]

        # 默认（非 preview）→ -p
        await stub.extensions["sploit_show"](stub, {"exploit_id": "12345"})
        assert "-p 12345" in calls[-1][0]

    @pytest.mark.asyncio
    async def test_search_over_25_hits(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.searchsploit, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "\n".join(
                f"Title{i} | exploits/webapps/5{i:04d}.py" for i in range(30))

        monkeypatch.setattr(P.searchsploit.SploitProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["sploit_search"](
            stub, {"keyword": "vsftpd 2.3.4"})
        assert "共 30 条匹配" in out


# ---------------------------------------------------------------------------
# enum4linux / evilwinrm / ffuf / ftp / getnpusers / getuserspns 剩余分支
# ---------------------------------------------------------------------------
class TestEnum4linuxBranches:
    def test_summarize_shares_groups_empty(self):
        from kalitui.profiles.enum4linux import _summarize

        out = _summarize("[+] Sharename       Type   Comment\n"
                         "[+] ---------       ----   -------\n"
                         "[+] share: public  Disk\n"
                         "[+] Group: Domain Admins\n"
                         "user: admin")
        assert "共享 (1)" in out and "组 (1)" in out
        out2 = _summarize("no useful output")
        assert "未枚举到明显信息" in out2


class TestEvilWinrmBadUsername:
    def test_bad_username(self):
        from kalitui.profiles.evilwinrm import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"host": "10.0.0.9", "username": "bad user!"})


class TestFfufBranches:
    def test_bad_match_codes(self):
        from kalitui.profiles.ffuf import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"url": "http://x/FUZZ", "wordlist": "/usr/share/wordlists/dirb/common.txt",
                        "match_codes": "abc"})

    def test_summarize_over_50_hits(self):
        from kalitui.profiles.ffuf import _summarize

        raw = "".join(f"admin{i} [Status: 200, Size: 100]\n" for i in range(60))
        out = _summarize(raw)
        assert "共 60 条命中" in out


class TestFtpBranches:
    def test_bad_creds(self):
        from kalitui.profiles.ftp import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"host": "10.0.0.9", "username": "bad user!"})
        with pytest.raises(ValueError):
            _build_cmd({"host": "10.0.0.9", "password": "bad pass!"})

    def test_summarize_over_30_entries(self):
        from kalitui.profiles.ftp import _summarize

        out = _summarize("\n".join(f"file{i}.bak" for i in range(40)))
        assert "共 40 项" in out


class TestGetNPUsersBranches:
    def test_build_cmd_branches(self, monkeypatch):
        import kalitui.profiles.getnpusers as G

        with pytest.raises(ValueError):
            G._build_cmd({"domain": "corp.local", "username": "bad user!"})
        with pytest.raises(ValueError):
            G._build_cmd({"domain": "corp.local", "username": "john",
                          "password": "bad pass!"})
        monkeypatch.setattr(G, "check_installed", lambda t: False)
        cmd, t = G._build_cmd({"domain": "corp.local", "username": "john",
                               "password": "Passw0rd"})
        assert cmd == "" and t == 0


class TestGetUserSPNsBranches:
    def test_build_cmd_branches(self, monkeypatch):
        import kalitui.profiles.getuserspns as G

        with pytest.raises(ValueError):
            G._build_cmd({"domain": "corp.local", "username": "john",
                          "password": "bad pass!"})
        with pytest.raises(ValueError):
            G._build_cmd({"domain": "corp.local", "username": "john",
                          "password": "Passw0rd!", "spns": "bad spn!"})
        monkeypatch.setattr(G, "check_installed", lambda t: False)
        cmd, t = G._build_cmd({"domain": "corp.local", "username": "john",
                               "password": "Passw0rd!"})
        assert cmd == "" and t == 0


# ---------------------------------------------------------------------------
# gobuster / hping3 / httpx 剩余分支
# ---------------------------------------------------------------------------
class TestGobusterBranches:
    def test_bad_status_codes(self):
        from kalitui.profiles.gobuster import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"url": "http://x:80/", "wordlist": "/usr/share/wordlists/dirb/common.txt",
                        "status_codes": "abc"})

    def test_summarize_over_40(self):
        from kalitui.profiles.gobuster import _summarize

        raw = "".join(f"/admin{i} (Status: 200) [Size: 100]\n" for i in range(50))
        out = _summarize(raw)
        assert "共 50 条命中" in out


class TestHping3Exec:
    @pytest.mark.asyncio
    async def test_exec_success_path(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.hping3, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "len=46 ip=10.0.0.9 ttl=64"

        monkeypatch.setattr(P.hping3.Hping3Profile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["hping_probe"](stub, {"host": "10.0.0.9"})
        assert "10.0.0.9" in out


class TestHttpxBranches:
    def test_parse_skip_non_result_lines(self):
        from kalitui.profiles.httpx import _parse

        rows = _parse("\n"  # 空行跳过
                      "not a result line\n"
                      "http://x.com\n"  # 匹配正则但无状态/标题/技术 → 跳过
                      "http://x.com [200] [title] [tech]")
        assert len(rows) == 1

    @pytest.mark.asyncio
    async def test_exec_no_targets_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.httpx, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["httpx_probe"](
            stub, {"targets": "bad target!;rm -rf /"})
        assert "格式非法" in out or "无法解析" in out
        out2 = await stub.extensions["httpx_probe"](stub, {"targets": "  "})
        assert "targets 不能为空" in out2
        out3 = await stub.extensions["httpx_probe"](
            stub, {"targets": ",".join(f"h{i}.com" for i in range(25))})
        assert "目标数量过多" in out3


# ---------------------------------------------------------------------------
# ldapsearch / linpeas / macchanger 剩余分支
# ---------------------------------------------------------------------------
class TestLdapsearchExtra:
    def test_bad_attrs_and_creds(self):
        from kalitui.profiles.ldapsearch import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"host": "10.0.0.9", "attributes": "bad attr!"})
        with pytest.raises(ValueError):
            _build_cmd({"host": "10.0.0.9", "username": "bad user!"})

    @pytest.mark.asyncio
    async def test_over_30_dns(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.ldapsearch, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "".join(f"dn: OU=u{i},DC=corp,DC=local\n" for i in range(40))

        monkeypatch.setattr(P.ldapsearch.LdapsearchProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["ldap_enum"](
            stub, {"host": "10.0.0.9", "base": "DC=corp,DC=local"})
        assert "共 40 条" in out


class TestLinpeasExtra:
    def test_parse_empty_line_skip(self):
        from kalitui.profiles.linpeas import _parse

        plus, warns = _parse("\n\n   \nnormal line\n[+] \n[+] real find\n")
        assert plus == ["real find"] and warns == []

    @pytest.mark.asyncio
    async def test_over_25_plus_lines(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.linpeas, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return chr(10).join(f"[+] high{i}" for i in range(30))

        monkeypatch.setattr(P.linpeas.LinpeasProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["linpeas"](
            stub, {"mode": "quick"})
        assert "共 30 条" in out


class TestMacchangerExtra:
    def test_bad_action(self):
        from kalitui.profiles.macchanger import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"interface": "eth0", "action": "fly"})

    @pytest.mark.asyncio
    async def test_exec_macs_and_fallback(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.macchanger, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "Current MAC: 00:11:22:33:44:55 (unknown)"

        monkeypatch.setattr(P.macchanger.MacchangerProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["mac_change"](
            stub, {"interface": "eth0", "action": "show"})
        assert "00:11:22:33:44:55" in out

        async def fake_run2(self, ex, cmd, timeout=30):
            return "no mac lines here"

        monkeypatch.setattr(P.macchanger.MacchangerProfile, "_run", fake_run2)
        out2 = await stub.extensions["mac_change"](
            stub, {"interface": "eth0", "action": "show"})
        assert "macchanger 执行完成" in out2


# ---------------------------------------------------------------------------
# hydra / impexec / nuclei 剩余分支
# ---------------------------------------------------------------------------
class TestHydraExtraBranches:
    def test_service_options_too_long(self):
        from kalitui.profiles.hydra import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"target": "10.0.0.9", "protocol": "http-post-form",
                        "username": "admin", "password": "x",
                        "service_options": "a" * 301})
        with pytest.raises(ValueError):
            _build_cmd({"target": "10.0.0.9", "protocol": "http-post-form",
                        "username": "admin", "password": "x",
                        "service_options": "bad\noption"})
        with pytest.raises(ValueError):
            _build_cmd({"target": "10.0.0.9", "protocol": "ssh",
                        "username": "root", "password": "x",
                        "userlist": "/tmp/u.txt"})

    @pytest.mark.asyncio
    async def test_no_hit_branch(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.hydra, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "0 valid password found"

        monkeypatch.setattr(P.hydra.HydraProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["hydra_brute"](
            stub, {"target": "10.0.0.9", "protocol": "ssh",
                   "username": "root", "password": "x"})
        assert "未命中" in out


class TestImpExecExtraBranches:
    def test_build_cmd_branches(self, monkeypatch):
        import kalitui.profiles.impexec as I

        with pytest.raises(ValueError):
            I._build_cmd({"host": "10.0.0.9", "username": "bad user!"})
        with pytest.raises(ValueError):
            I._build_cmd({"host": "10.0.0.9", "username": "john",
                          "password": "x", "hash": "a" * 32})
        with pytest.raises(ValueError):
            I._build_cmd({"host": "10.0.0.9", "username": "john",
                          "hash": "xyz"})  # 非 32 位 NTLM
        with pytest.raises(ValueError):
            I._build_cmd({"host": "10.0.0.9", "username": "john",
                          "password": "x", "domain": "bad dom!"})
        monkeypatch.setattr(I, "check_installed", lambda t: False)
        cmd, t = I._build_cmd({"host": "10.0.0.9", "username": "john", "password": "x"})
        assert cmd == "" and t == 0


class TestNucleiExtraBranches:
    def test_bad_tags_and_templates(self):
        from kalitui.profiles.nuclei import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"target": "http://x", "tags": "bad tag!"})
        with pytest.raises(ValueError):
            _build_cmd({"target": "http://x", "templates": "bad template!"})
        cmd, _ = _build_cmd({"target": "http://x", "templates": "cves/2024"})
        assert "-t cves/2024" in cmd

    @pytest.mark.asyncio
    async def test_over_30_hits(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.nuclei, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return chr(10).join(f"[high] cve-2024-{i:04d}" for i in range(40))

        monkeypatch.setattr(P.nuclei.NucleiProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["nuclei_scan"](
            stub, {"target": "http://x", "severity": "high"})
        assert "共 40 条" in out


# ---------------------------------------------------------------------------
# msfvenom / msf / netcat 剩余分支
# ---------------------------------------------------------------------------
class TestMsfvenomExtra3:
    def test_encoder_arch_platform(self):
        from kalitui.profiles.msfvenom import _build_cmd

        base = {"payload": "linux/x64/shell/reverse_tcp",
                "lhost": "10.0.0.5", "lport": 4444}
        with pytest.raises(ValueError):
            _build_cmd({**base, "encoder": "bad enc!"})
        with pytest.raises(ValueError):
            _build_cmd({**base, "arch": "bad arch!"})
        with pytest.raises(ValueError):
            _build_cmd({**base, "platform": "bad plat!"})
        with pytest.raises(ValueError):
            _build_cmd({**base, "encoder": "x86/shikata_ga_nai",
                        "outfile": "/tmp/a;b.elf"})  # outfile 非法字符
        cmd, _ = _build_cmd({**base, "arch": "x64", "platform": "linux",
                             "encoder": "x86/shikata_ga_nai",
                             "outfile": "/tmp/p2.elf", "format": "elf"})
        assert "-a x64" in cmd and "--platform linux" in cmd

    @pytest.mark.asyncio
    async def test_exec_generation_failed(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.msfvenom, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "Error: invalid payload"

        monkeypatch.setattr(P.msfvenom.MsfvenomProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["payload_gen"](
            stub, {"payload": "linux/x64/shell/reverse_tcp",
                   "lhost": "10.0.0.5", "lport": 4444,
                   "outfile": "/tmp/x.elf", "format": "elf"})
        assert "生成失败" in out


class TestMsfExtra2:
    def test_options_not_dict_and_bad_key(self):
        from kalitui.profiles.msf import _build_script

        with pytest.raises(ValueError):
            _build_script({"module": "exploit/x", "options": "not-a-dict"}, search=False)
        with pytest.raises(ValueError):
            _build_script({"module": "exploit/x", "options": {"bad key!": "v"}}, search=False)


class TestNetcatExtra2:
    def test_bin_fallback_and_bad_data(self):
        import kalitui.profiles.netcat as N

        monkeypatch = None
        # 直接改模块属性再恢复
        orig = N.check_installed
        N.check_installed = lambda t: False
        assert N._nc_bin() == ""
        N.check_installed = lambda t: t in ("ncat", "nc")
        assert N._nc_bin() in ("ncat", "nc")
        N.check_installed = orig

        from kalitui.profiles.netcat import _DATA_RE
        assert _DATA_RE.match("safe data") is not None
        assert _DATA_RE.match("bad\x00data") is None
        assert _DATA_RE.match("safe;rm -rf /") is not None  # 分号合法：_escape_data 单引号包裹防注入

    @pytest.mark.asyncio
    async def test_exec_connect_bad_data(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.netcat, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["nc_connect"](
                stub, {"host": "10.0.0.9", "port": 4444,
                       "data": "bad\x00data"})

    @pytest.mark.asyncio
    async def test_exec_received_data(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.netcat, "check_installed", lambda t: True)
        monkeypatch.setattr(P.netcat.time, "time", lambda: 12345.0)
        with open("/tmp/nc-listen-12345.txt", "w", encoding="utf-8") as f:
            f.write("hello from target")

        async def fake_run(self, ex, cmd, timeout=30):
            return "done"

        monkeypatch.setattr(P.netcat.NcProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["nc_listen"](
            stub, {"port": 4444, "seconds": 10})
        assert "收到数据" in out


# ---------------------------------------------------------------------------
# netdiscover / nfs / nikto / nmap / redis / responder / rsync 剩余分支
# ---------------------------------------------------------------------------
class TestNetdiscoverOver30:
    def test_summarize_over_30_hosts(self):
        from kalitui.profiles.netdiscover import _summarize

        raw = "".join(f"{i}  10.0.0.{i}   aa:bb:cc:dd:ee:00  host{i}\n" for i in range(35))
        out = _summarize(raw)
        assert "共 35 条" in out


class TestNfsExtra2:
    def test_build_cmd_error_lines(self):
        from kalitui.profiles.nfs import _build_cmd, _parse

        cmd = _build_cmd("10.0.0.9")
        assert "showmount -e 10.0.0.9" in cmd
        shares = _parse("Export list for 10.0.0.9:\n"
                        "clnt_create: RPC: Program not registered\n"
                        "\n"
                        "/data 10.0.0.0/24\n")
        assert shares == ["/data 10.0.0.0/24"]

    @pytest.mark.asyncio
    async def test_exec_over_20(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.nfs, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "".join(f"  /share{i}  10.0.0.0/24\n" for i in range(25))

        monkeypatch.setattr(P.nfs.NfsEnumProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["nfs_enum"](
            stub, {"target": "10.0.0.9"})
        assert "共 25 个" in out


class TestNiktoExtra2:
    def test_bad_tuning(self):
        from kalitui.profiles.nikto import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"target": "http://x", "tuning": "xyz"})

    @pytest.mark.asyncio
    async def test_exec_over_40(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.nikto, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return chr(10).join(f"+ /path{i} : something" for i in range(50))

        monkeypatch.setattr(P.nikto.NiktoProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["nikto_scan"](
            stub, {"target": "http://x"})
        assert "共 50 条发现" in out


class TestNmapExtra3:
    def test_summarize_os_and_ports(self):
        from kalitui.profiles.nmap import _summarize

        raw = ("Nmap scan report for 10.0.0.9\n"
               "OS details: Linux 5.4\n"
               "80/tcp open  http\n" * 40)
        out = _summarize(raw)
        assert "存活主机" in out and "OS 猜测" in out
        assert "共 40 个开放端口" in out

    def test_summarize_no_ports(self):
        from kalitui.profiles.nmap import _summarize

        out = _summarize("Nmap done: 1 IP address scanned")
        assert "未发现开放端口" in out


class TestRedisExtra2:
    @pytest.mark.asyncio
    async def test_exec_success_branch(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.redis, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "redis_version:6.0.9\nconnected_clients:1"

        monkeypatch.setattr(P.redis.RedisProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["redis_check"](
            stub, {"host": "10.0.0.5"})
        assert "Redis 未授权" in out

    @pytest.mark.asyncio
    async def test_exec_noauth_branch(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.redis, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "NOAUTH Authentication required."

        monkeypatch.setattr(P.redis.RedisProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["redis_check"](
            stub, {"host": "10.0.0.5", "password": "x"})
        assert "需要密码" in out


class TestResponderExtra2:
    def test_summarize_with_requests(self):
        from kalitui.profiles.responder import _summarize

        raw = ("[+] Listening for events...\n"
               "[+] [HTTP] v10.0.0.9:80  Client     : 10.0.0.9  Username: ADMIN\n"
               "[+] [SMB] v10.0.0.9:445  NTLMv2-SSP Client     : 10.0.0.9\n")
        out = _summarize(raw)
        assert "捕获到协议请求" in out


class TestRsyncExtra2:
    @pytest.mark.asyncio
    async def test_exec_over_20(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.rsync, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "".join(f"drwxr-xr-x  4096 2024  web  module{i}\n" for i in range(25))

        monkeypatch.setattr(P.rsync.RsyncEnumProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["rsync_enum"](
            stub, {"target": "10.0.0.9"})
        assert "共 25 个" in out

    def test_parse_error_lines_skipped(self):
        from kalitui.profiles.rsync import _parse

        mods = _parse("rsync: connection unexpectedly closed\n"
                      "\n"
                      "backup  Backup storage\n")
        assert mods == ["backup  Backup storage"]


# ---------------------------------------------------------------------------
# dnsrecon / secret_scan / secretsdump / smbclient 剩余分支
# ---------------------------------------------------------------------------
class TestDnsreconOver40:
    def test_summarize_over_40(self):
        from kalitui.profiles.dnsrecon import _summarize

        raw = "".join(f"2026-01-01T00:00:00.0 INFO \t A sub{i}.example.com 10.0.0.{i}\n"
                      for i in range(50))
        out = _summarize(raw)
        assert "共 50 条" in out


class TestSecretScanExtra:
    @pytest.mark.asyncio
    async def test_exec_hits_cap(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.secret_scan, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "".join(
                f'x/{i}: secret_key="{i:08d}{"x" * 20}"\n' for i in range(25))

        monkeypatch.setattr(P.secret_scan.SecretScanProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["secret_scan"](
            stub, {"url": "http://x/app.js"})
        assert "发现硬编码密钥" in out


class TestSecretsdumpExtra:
    @pytest.mark.asyncio
    async def test_exec_no_hashes(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.secretsdump, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "no credentials dumped\n"

        monkeypatch.setattr(P.secretsdump.SecretsdumpProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["secrets_dump"](
            stub, {"host": "10.0.0.9", "username": "john", "password": "x"})
        assert "未提取到 hash" in out

    def test_build_cmd_branches(self, monkeypatch):
        import kalitui.profiles.secretsdump as S

        with pytest.raises(ValueError):
            S._build_cmd({"host": "10.0.0.9", "username": "bad user!"})
        with pytest.raises(ValueError):
            S._build_cmd({"host": "10.0.0.9", "username": "john",
                          "password": "x", "hash": "a" * 32})
        with pytest.raises(ValueError):
            S._build_cmd({"host": "10.0.0.9", "username": "john",
                          "hash": "xyz"})
        with pytest.raises(ValueError):
            S._build_cmd({"host": "10.0.0.9", "username": "john",
                          "password": "x", "domain": "bad dom!"})
        with pytest.raises(ValueError):
            S._build_cmd({"host": "10.0.0.9", "username": "john",
                          "password": "x", "target": "registry"})
        monkeypatch.setattr(S, "check_installed", lambda t: False)
        cmd, t = S._build_cmd({"host": "10.0.0.9", "username": "john", "password": "x"})
        assert cmd == "" and t == 0

    @pytest.mark.asyncio
    async def test_exec_over_25_hashes(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.secretsdump, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "".join(f"user{i}:1000:aad3b435b51404eeaad3b435b51404ee:{i:032x}:::\n"
                           for i in range(30))

        monkeypatch.setattr(P.secretsdump.SecretsdumpProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["secrets_dump"](
            stub, {"host": "10.0.0.9", "username": "john", "password": "x"})
        assert "共 30 条" in out


class TestSmbclientExtra2:
    @pytest.mark.asyncio
    async def test_exec_entries_branch(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.smbclient, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return ("  secret.txt  A 100  Wed Jul 10 12:00:00 2024\n"
                    "  docs/  D 0  Wed Jul 10 12:00:00 2024\n"
                    "NT_STATUS_ACCESS_DENIED listing\n")

        monkeypatch.setattr(P.smbclient.SmbclientProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["smb_ls"](
            stub, {"host": "10.0.0.9", "share": "share"})
        assert "目录内容" in out and "secret.txt" in out

    def test_build_cmd_bad_values(self):
        from kalitui.profiles.smbclient import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"host": "10.0.0.9", "share": "share", "username": "bad user!"})
        with pytest.raises(ValueError):
            _build_cmd({"host": "10.0.0.9", "share": "bad share!"})
        cmd, _ = _build_cmd({"host": "10.0.0.9", "share": "C$", "domain": "CORP",
                             "username": "john"})
        assert "CORP\\john" in cmd  # 域\用户内联形式
        cmd2, _ = _build_cmd({"host": "10.0.0.9", "share": "C$", "domain": "CORP"})
        assert "-W CORP" in cmd2  # 无 username 时 -W
        cmd3, _ = _build_cmd({"host": "10.0.0.9", "share": "C$"})
        assert "-N" in cmd3  # 无凭据 -N

    @pytest.mark.asyncio
    async def test_exec_denied_branch(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.smbclient, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "NT_STATUS_ACCESS_DENIED"

        monkeypatch.setattr(P.smbclient.SmbclientProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["smb_ls"](
            stub, {"host": "10.0.0.9", "share": "share", "username": "guest"})
        assert "访问被拒" in out


# ---------------------------------------------------------------------------
# smbmap / smtpenum / snmp / sqlmap / sslscan / tcpdump 剩余分支
# ---------------------------------------------------------------------------
class TestSmbmapExtra2:
    @pytest.mark.asyncio
    async def test_exec_shares_and_files(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.smbmap, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return ("[+] IP: 10.0.0.9:445 Name: 10.0.0.9\n"
                    "Disk\t C$\n"
                    "C$/secret.txt\t READ\t 100\n")

        monkeypatch.setattr(P.smbmap.SmbmapProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["smb_map"](
            stub, {"target": "10.0.0.9"})
        assert "共享列表" in out and "共享内文件" in out


class TestSmtpenumExtra2:
    def test_bad_domain(self):
        from kalitui.profiles.smtpenum import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"host": "10.0.0.9", "domain": "bad dom!"})


class TestSnmpExtra2:
    @pytest.mark.asyncio
    async def test_exec_over_15(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.snmp, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "".join(
                f".1.3.6.1.2.1.1.1.0 = STRING: \"sysDescr {i}\"\n" for i in range(20))

        monkeypatch.setattr(P.snmp.SnmpEnumProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["snmp_enum"](
            stub, {"target": "10.0.0.9", "community": "public"})
        assert "共 20 项" in out


class TestSqlmapExtra2:
    def test_bad_cookie(self):
        from kalitui.profiles.sqlmap import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"url": "http://t.com/?id=1", "cookie": "bad\x00cookie"})


class TestSslscanExtra2:
    def test_summarize_over_20_proto(self):
        from kalitui.profiles.sslscan import _summarize

        raw = "".join(f"TLSv1.2  256 bits  AES256-GCM-SHA384 p{i}\n" for i in range(25))
        out = _summarize(raw)
        assert "共 25 条" in out

    @pytest.mark.asyncio
    async def test_exec_full_path(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.sslscan, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "TLSv1.2  256 bits  AES256-GCM-SHA384\nSubject: CN=x\nRC4-SHA weak\n"

        monkeypatch.setattr(P.sslscan.SslscanProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["ssl_scan"](
            stub, {"host": "10.0.0.9", "port": 443})
        assert "证书" in out and "弱点配置" in out


class TestTcpdumpExtra2:
    def test_summarize_over_25(self):
        from kalitui.profiles.tcpdump import _summarize

        raw = ("".join(f"12:00:00.000000 IP 10.0.0.{i}.1 > 10.0.0.9.80: Flags [S]\n"
                      for i in range(30))
               + "30 packets captured\n")
        out = _summarize(raw)
        assert "共 30 条" in out and "packets captured" in out


# ---------------------------------------------------------------------------
# testssl / theharvester / tshark 剩余分支
# ---------------------------------------------------------------------------
class TestTestsslExtra2:
    def test_bin_fallback(self, monkeypatch):
        import kalitui.profiles.testssl as T

        monkeypatch.setattr(T, "check_installed", lambda t: False)
        monkeypatch.setattr("os.path.exists", lambda p: False)
        assert T._bin() == ""
        monkeypatch.setattr("os.path.exists", lambda p: True)
        assert T._bin() == "/usr/share/testssl.sh/testssl.sh"
        monkeypatch.setattr(T, "check_installed", lambda t: True)
        assert T._bin() == "testssl"  # PATH 命中优先

    @pytest.mark.asyncio
    async def test_exec_full_path(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.testssl, "check_installed", lambda t: True)
        monkeypatch.setattr(P.testssl, "_bin", lambda: "/usr/share/testssl.sh/testssl.sh")

        async def fake_run(self, ex, cmd, timeout=30):
            return "SSLv3  offered\nOK  TLS1.2\n"

        monkeypatch.setattr(P.testssl.TestsslProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["tls_deep"](
            stub, {"host": "10.0.0.9", "port": 443})
        assert "TLS 检测结果" in out


class TestTheharvesterExtra2:
    def test_summarize_over_30(self):
        from kalitui.profiles.theharvester import _summarize

        raw = "".join(f"[*] Hosts found: {i}\n  host{i}.example.com\n" for i in range(35))
        out = _summarize(raw)
        assert "共 35 个" in out

    @pytest.mark.asyncio
    async def test_exec_full_path(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.theharvester, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "[*] Emails found: 1\nadmin@example.com\n"

        monkeypatch.setattr(P.theharvester.TheHarvesterProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["osint_gather"](
            stub, {"domain": "example.com", "sources": "google"})
        assert "邮箱" in out or "Emails" in out


class TestTsharkExtra2:
    def test_bad_interface(self):
        from kalitui.profiles.tshark import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"interface": "bad iface!"})

    def test_summarize_over_30(self):
        from kalitui.profiles.tshark import _summarize

        raw = "".join(f"{i}\t0.000000\t10.0.0.{i}.1\t10.0.0.9\tTCP\t60\t443 -> 51234 [SYN]\n"
                      for i in range(35))
        out = _summarize(raw)
        assert "共 35 条" in out

    @pytest.mark.asyncio
    async def test_exec_full_path(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            def __init__(self):
                self.danger_policy = "ask"
                self.extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.tshark, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return "1\t0.000000\t10.0.0.9\t10.0.0.5\tTCP\t60\t443 -> 51234 [SYN]\n"

        monkeypatch.setattr(P.tshark.TsharkProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["tshark_capture"](
            stub, {"interface": "eth0", "count": 10})
        assert "抓包" in out or "数据包" in out


# ---------------------------------------------------------------------------
# wfuzz / wpscan 剩余分支
# ---------------------------------------------------------------------------
class TestWfuzzExtra2:
    def test_build_cmd_code_branches(self):
        from kalitui.profiles.wfuzz import _build_cmd

        base = {"url": "http://x/FUZZ", "wordlist": "/tmp/w.txt"}
        with pytest.raises(ValueError):
            _build_cmd({**base, "match_codes": "20x"})
        with pytest.raises(ValueError):
            _build_cmd({**base, "hide_codes": "20x"})
        with pytest.raises(ValueError):
            _build_cmd({**base, "match_codes": "200", "hide_codes": "404"})
        with pytest.raises(ValueError):
            _build_cmd({**base, "cookie": "bad\x00cookie"})

    def test_summarize_rows_and_empty(self):
        from kalitui.profiles.wfuzz import _summarize

        raw = "".join(f"{i}: 200  Words: 12  Lines: 1  /path{i}\n" for i in range(35))
        out = _summarize(raw)
        assert "共 35 条" in out
        raw2 = "ID 000001  Resp: 200  Words: 1  Lines: 1  /old\n"
        out3 = _summarize(raw2)
        assert "wfuzz 命中" in out3
        out2 = _summarize("nothing here\n")
        assert "未发现命中" in out2


class TestWpscanExtra2:
    def test_summarize_finds_and_vulns(self):
        from kalitui.profiles.wpscan import _summarize

        raw = ("[+] WordPress version 6.4.3 identified\n"
               "| [!] Title: XSS in plugin X\n")
        out = _summarize(raw)
        assert "主要发现" in out and "漏洞/高风险项" in out
        out2 = _summarize("wordpress.org is up\n")
        assert "未发现明显问题" in out2


# ---------------------------------------------------------------------------
# playbook 剩余分支
# ---------------------------------------------------------------------------
class TestPlaybookParsers2:
    def test_parse_ports_bad_line(self):
        from kalitui.profiles.playbook import _parse_ports

        # "abc/tcp open" 过 re_search_port 但 int 解析失败 → 跳过
        raw = "abc/tcp open http\n80/tcp open http Apache 2.4\n"
        ports = _parse_ports(raw)
        assert ports == [(80, "http", "Apache 2.4")]

    def test_parse_nuclei_empty_lines(self):
        from kalitui.profiles.playbook import _parse_nuclei

        hits = _parse_nuclei("\n\n[critical] CVE-2024-1 X\n\n[high] CVE-2024-2 Y\n")
        assert len(hits) == 2


class TestPlaybookPipeline:
    @pytest.mark.asyncio
    async def test_recon_pipeline_full(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "-sn" in cmd:
                    return "Nmap scan report for 10.0.0.5\n"
                return ("Nmap scan report for 10.0.0.5\n"
                        "80/tcp open http Apache\n"
                        "443/tcp open https\n")

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed", lambda t: t == "nmap")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["recon_pipeline"](
            stub, {"target": "10.0.0.5"})
        assert "存活主机" in out and "开放端口 (2)" in out

    @pytest.mark.asyncio
    async def test_bounty_no_ports_closing(self, monkeypatch):
        """nmap 无端口 → 收尾建议分支。"""
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "nmap" in cmd and "-sn" not in cmd:
                    return "Nmap scan report for example.com\n"
                return "Nmap scan report for example.com\n"

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed", lambda t: t == "nmap")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["bounty_recon"](
            stub, {"target": "example.com"})
        assert "未发现开放端口" in out

    @pytest.mark.asyncio
    async def test_bounty_empty_target(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed", lambda t: t == "nmap")
        P.register_extensions(stub)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await stub.extensions["bounty_recon"](stub, {"target": "  "})


class TestBountyExtraBranches:
    @pytest.mark.asyncio
    async def test_subenum_curl_missing(self, monkeypatch):
        """curl 未安装 → sub_enum 跳过提示。"""
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "nmap" in cmd and "-sn" not in cmd:
                    return "Nmap scan report for example.com\n80/tcp open http\n"
                return "Nmap scan report for example.com\n"

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed",
                            lambda t: t == "nmap")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["bounty_recon"](
            stub, {"target": "example.com", "sub_enum": True})
        assert "curl 未安装" in out

    @pytest.mark.asyncio
    async def test_subenum_over25_and_httpx_fail(self, monkeypatch):
        """crtsh 返回 >25 子域 + httpx 解析抛异常容错。"""
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "curl" in cmd and "crt.sh" in cmd:
                    subs = "".join(
                        f'{{"name_value": "s{i}.example.com"}},' for i in range(30))
                    return f'[{subs[:-1]}]'
                if "nmap" in cmd and "-sn" not in cmd:
                    return "Nmap scan report for example.com\n80/tcp open http\n"
                return "Nmap scan report for example.com\n"

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed",
                            lambda t: t in ("nmap", "curl", "httpx"))
        monkeypatch.setattr(P.httpx, "_parse", lambda raw: (_ for _ in ()).throw(RuntimeError("boom")))
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["bounty_recon"](
            stub, {"target": "example.com", "sub_enum": True})
        assert "共 30 个" in out
        assert "httpx 存活探测失败" in out

    @pytest.mark.asyncio
    async def test_gobuster_except_and_no_ports(self, monkeypatch):
        """gobuster 构建命令抛异常 → 目录枚举失败容错；无端口收尾建议。"""
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "nmap" in cmd and "-sn" not in cmd:
                    return "Nmap scan report for example.com\n80/tcp open http\n"
                return "Nmap scan report for example.com\n"

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed",
                            lambda t: t in ("nmap", "wafw00f", "gobuster"))
        monkeypatch.setattr(P.gobuster, "_build_cmd",
                            lambda args: (_ for _ in ()).throw(RuntimeError("boom")))
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["bounty_recon"](
            stub, {"target": "example.com", "web_check": True})
        assert "目录枚举失败" in out
        assert "建议: Web 目标用 http_req" in out

    @pytest.mark.asyncio
    async def test_nuclei_except_and_skipped(self, monkeypatch):
        """vuln_scan：nuclei 抛异常 → 容错；nuclei 未装 → 跳过提示。"""
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "nuclei" in cmd:
                    raise RuntimeError("nuclei boom")
                if "nmap" in cmd and "-sn" not in cmd:
                    return "Nmap scan report for example.com\n80/tcp open http\n"
                return "Nmap scan report for example.com\n"

        stub = Stub()
        monkeypatch.setattr(P.playbook, "check_installed",
                            lambda t: t in ("nmap", "wafw00f", "gobuster", "nuclei"))
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["bounty_recon"](
            stub, {"target": "example.com", "web_check": True, "vuln_scan": True})
        assert "nuclei: 扫描失败" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "nmap" in cmd and "-sn" not in cmd:
                    return "Nmap scan report for example.com\n80/tcp open http\n"
                return "Nmap scan report for example.com\n"

        stub2 = Stub2()
        monkeypatch.setattr(P.playbook, "check_installed",
                            lambda t: t in ("nmap", "wafw00f", "gobuster"))
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["bounty_recon"](
            stub2, {"target": "example.com", "web_check": True, "vuln_scan": True})
        assert "nuclei: 跳过（未安装" in out2


# ---------------------------------------------------------------------------
# cve_lookup：CVE 情报查询
# ---------------------------------------------------------------------------
class TestCveLookup:
    def test_build_cmd_branches(self):
        from kalitui.profiles.cve_lookup import _build_cmd

        with pytest.raises(ValueError):
            _build_cmd({"cve_id": "CVE-2024"})
        with pytest.raises(ValueError):
            _build_cmd({"cve_id": "bad id"})
        with pytest.raises(ValueError):
            _build_cmd({"vendor": "apache; rm -rf /", "product": "tomcat"})
        with pytest.raises(ValueError):
            _build_cmd({})
        cmd = _build_cmd({"cve_id": "cve-2024-1234"})
        assert "CVE-2024-1234" in cmd and "cve.circl.lu" in cmd
        cmd2 = _build_cmd({"vendor": "apache", "product": "tomcat"})
        assert "/search/apache/tomcat" in cmd2

    def test_parse_detail_branches(self):
        from kalitui.profiles.cve_lookup import _parse_detail

        assert _parse_detail("not json") == {}
        assert _parse_detail("[]") == {}
        d = _parse_detail(
            '{"id": "CVE-2024-1234", "cvss": {"score": 9.8}, '
            '"summary": "RCE in tomcat", "cwe": "CWE-78", '
            '"references": ["a", "b"], "Published": "2024-01-01"}')
        assert d["id"] == "CVE-2024-1234" and d["cvss"] == 9.8
        assert d["refs"] == 2 and d["cwe"] == "CWE-78"

    def test_parse_search_branches(self):
        from kalitui.profiles.cve_lookup import _parse_search

        assert _parse_search("nope") == []
        assert _parse_search('{"a": 1}') == []  # 非列表 JSON
        rows = _parse_search(
            '[{"id": "CVE-2024-1", "cvss": {"score": 7.5}, "summary": "x"}, '
            '"junk", {"id": "CVE-2024-2"}]')
        assert len(rows) == 2 and rows[0]["cvss"] == 7.5
        assert rows[1]["cvss"] is None

    @pytest.mark.asyncio
    async def test_exec_detail_and_miss(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.cve_lookup, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return ('{"id": "CVE-2024-1234", "cvss": {"score": 9.8}, '
                    '"summary": "RCE", "cwe": "CWE-78", "references": [], '
                    '"Published": "2024-01-01"}')

        monkeypatch.setattr(P.cve_lookup.CveLookupProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["cve_lookup"](
            stub, {"cve_id": "CVE-2024-1234"})
        assert "CVSS: 9.8" in out and "严重" in out and "CVE-2024-1234" in out

        async def fake_run2(self, ex, cmd, timeout=30):
            return "not found"

        monkeypatch.setattr(P.cve_lookup.CveLookupProfile, "_run", fake_run2)
        out2 = await stub.extensions["cve_lookup"](
            stub, {"cve_id": "CVE-2024-9999"})
        assert "未查到" in out2

    @pytest.mark.asyncio
    async def test_exec_search_rows(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.cve_lookup, "check_installed", lambda t: True)

        async def fake_run(self, ex, cmd, timeout=30):
            return ('[{"id": "CVE-2024-1", "cvss": {"score": 7.5}, "summary": "s1"}, '
                    '{"id": "CVE-2023-2", "cvss": {"score": 5.4}, "summary": "s2"}]')

        monkeypatch.setattr(P.cve_lookup.CveLookupProfile, "_run", fake_run)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["cve_lookup"](
            stub, {"vendor": "apache", "product": "tomcat"})
        assert "产品 CVE 情报" in out and "CVSS 7.5" in out

        async def fake_run2(self, ex, cmd, timeout=30):
            return "[]"

        monkeypatch.setattr(P.cve_lookup.CveLookupProfile, "_run", fake_run2)
        out2 = await stub.extensions["cve_lookup"](
            stub, {"vendor": "apache", "product": "nope"})
        assert "未搜索到" in out2

        async def fake_run3(self, ex, cmd, timeout=30):
            rows = ",".join(
                f'{{"id": "CVE-2024-{i:04d}", "cvss": {{"score": 5.0}}, "summary": "s"}}'
                for i in range(20))
            return f"[{rows}]"

        monkeypatch.setattr(P.cve_lookup.CveLookupProfile, "_run", fake_run3)
        out3 = await stub.extensions["cve_lookup"](
            stub, {"vendor": "apache", "product": "big"})
        assert "共 15+ 条" in out3

    @pytest.mark.asyncio
    async def test_exec_not_installed(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.cve_lookup, "check_installed", lambda t: False)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["cve_lookup"](stub, {"cve_id": "CVE-2024-1234"})
        assert "未安装" in out


# ---------------------------------------------------------------------------
# report_gen：漏洞报告生成
# ---------------------------------------------------------------------------
class TestReportGen:
    def test_build_report_validation(self):
        from kalitui.profiles.report_gen import _build_report

        with pytest.raises(ValueError):
            _build_report({"title": "", "target": "x"})
        with pytest.raises(ValueError):
            _build_report({"title": "t" * 121, "target": "x"})
        with pytest.raises(ValueError):
            _build_report({"title": "t", "target": "x" * 201})
        with pytest.raises(ValueError):
            _build_report({"title": "t", "target": "x", "severity": "fatal"})
        with pytest.raises(ValueError):
            _build_report({"title": "t", "target": "x", "findings": "nope"})
        with pytest.raises(ValueError):
            _build_report({"title": "t", "target": "x",
                           "findings": [{"title": "a", "severity": "high"}] * 21})

    def test_build_report_sort_and_clean(self):
        from kalitui.profiles.report_gen import _build_report

        r = _build_report({
            "title": "测试报告", "target": "10.0.0.9", "severity": "high",
            "findings": [
                {"title": "低危项", "severity": "low", "description": "d1"},
                {"title": "严重项", "severity": "critical", "description": "d2",
                 "poc": "p2", "fix": "f2"},
                {"title": "坏项", "severity": "fatal"},  # 被过滤
                "junk",  # 被过滤
                {"title": "", "severity": "high"},  # 被过滤
            ],
        })
        assert "严重项" in r and "低危项" in r and "坏项" not in r
        assert r.index("严重项") < r.index("低危项")  # 严重在前
        assert "总体风险: **高**" in r
        assert "10.0.0.9" in r and "复现步骤" in r and "修复建议" in r
        assert "免责声明" in r
        r2 = _build_report({"title": "t", "target": "x", "findings": []})
        assert "未记录漏洞发现" in r2

    @pytest.mark.asyncio
    async def test_exec_writes_file(self, monkeypatch, tmp_path):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        outfile = str(tmp_path / "report.md")
        monkeypatch.setattr(P.report_gen.time, "strftime", lambda fmt: "2024-01-01 00:00")
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["report_gen"](
            stub, {"title": "测试", "target": "10.0.0.9",
                   "output": outfile, "severity": "high",
                   "findings": [{"title": "XSS", "severity": "medium"}]})
        assert "报告已生成" in out and "测试" in out
        content = open(outfile, encoding="utf-8").read()
        assert "# 测试" in content and "XSS" in content
        assert "2024-01-01 00:00" in content

    def test_check_output(self):
        from kalitui.profiles.report_gen import _check_output

        with pytest.raises(ValueError):
            _check_output("/etc/passwd")
        with pytest.raises(ValueError):
            _check_output("/tmp/a;b")
        with pytest.raises(ValueError):
            _check_output("/tmp/" + "a" * 301)
        assert _check_output("/tmp/r.md") == "/tmp/r.md"
        assert _check_output("./r.md") == "./r.md"


# ---------------------------------------------------------------------------
# web_leak：Web 敏感文件泄露探测
# ---------------------------------------------------------------------------
class TestWebLeak:
    def test_build_cmd_quoting(self):
        from kalitui.profiles.web_leak import _build_cmd

        cmd = _build_cmd("http://t.com", ["/.env", "/backup.zip"])
        assert "'http://t.com$p'" in cmd and "'/.env'" in cmd and "'/backup.zip'" in cmd
        assert "%{http_code}" in cmd and "%{size_download}" in cmd

    def test_parse_probe(self):
        from kalitui.profiles.web_leak import _parse_probe

        hits = _parse_probe(
            "200 1234 /.env\n404 0 /nope\n000 0 /timeout\n"
            "301 0 /moved\n403 45 /.htaccess\n"
        )
        assert hits == [("200", "1234", "/.env"), ("403", "45", "/.htaccess")]
        assert not any(h[0] in ("404", "000") for h in hits)
        assert _parse_probe("junk line\n") == []

    def test_parse_robots(self):
        from kalitui.profiles.web_leak import _parse_robots

        dis = _parse_robots(
            "User-agent: *\nDisallow: /admin/\nDisallow: /internal\n"
            "Disallow: *\nAllow: /public\nDisallow:\n"
        )
        assert dis == ["/admin/", "/internal"]

    @pytest.mark.asyncio
    async def test_exec_hits_and_robots(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "for p in" in cmd:
                    return "200 512 /.env\n404 0 /nope\n403 45 /.htaccess\n"
                if "robots.txt" in cmd:
                    return "".join(f"Disallow: /hidden{i}/\n" for i in range(20))
                return ""

        stub = Stub()
        monkeypatch.setattr(P.web_leak, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["web_leak"](
            stub, {"url": "http://t.com"})
        assert "敏感文件命中" in out and "/.env" in out and "/.htaccess" in out
        assert "robots.txt Disallow" in out and "共 20 条" in out

    @pytest.mark.asyncio
    async def test_exec_no_hits(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "robots.txt" in cmd:
                    return "User-agent: *\n"
                return "404 0 /x\n000 0 /y\n"

        stub = Stub()
        monkeypatch.setattr(P.web_leak, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["web_leak"](stub, {"url": "http://t.com"})
        assert "未发现敏感文件命中" in out

    @pytest.mark.asyncio
    async def test_exec_bad_inputs(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.web_leak, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["web_leak"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out
        with pytest.raises(ValueError):
            await stub.extensions["web_leak"](
                stub, {"url": "http://t.com", "paths": "nope"})
        with pytest.raises(ValueError):
            await stub.extensions["web_leak"](
                stub, {"url": "http://t.com", "paths": ["bad path"]})
        with pytest.raises(ValueError):
            await stub.extensions["web_leak"](
                stub, {"url": "http://t.com",
                       "paths": [f"/p{i}" for i in range(30)]})


# ---------------------------------------------------------------------------
# header_check：安全响应头与 CORS 检查
# ---------------------------------------------------------------------------
class TestHeaderCheck:
    def test_build_cmd(self):
        from kalitui.profiles.header_check import _build_cmd

        cmd = _build_cmd("http://t.com/")
        assert "-D - -o /dev/null" in cmd and "'http://t.com/'" in cmd
        assert "Origin" not in cmd
        cmd2 = _build_cmd("http://t.com/", origin="http://evil.com")
        assert "Origin: http://evil.com" in cmd2

    def test_parse_headers(self):
        from kalitui.profiles.header_check import _parse_headers

        h = _parse_headers(
            "HTTP/1.1 200 OK\nServer: nginx/1.18.0\nX-Frame-Options: DENY\n"
            "  continuation\nContent-Length: 123\n\n"
        )
        assert h["server"] == "nginx/1.18.0"
        assert h["x-frame-options"] == "DENY"
        assert h["content-length"] == "123"

    @pytest.mark.asyncio
    async def test_exec_missing_headers_and_cors_reflect(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "Origin" in cmd:
                    return ("HTTP/1.1 200 OK\n"
                            "Access-Control-Allow-Origin: http://evil.com\n"
                            "Server: nginx/1.18.0\n")
                return ("HTTP/1.1 200 OK\n"
                        "Server: nginx/1.18.0\n"
                        "Content-Type: text/html\n")

        stub = Stub()
        monkeypatch.setattr(P.header_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["header_check"](
            stub, {"url": "http://t.com/"})
        assert "缺失安全头" in out and "X-Frame-Options" in out
        assert "CORS 风险" in out and "evil.com" in out
        assert "Server 指纹" in out and "nginx/1.18.0" in out

    @pytest.mark.asyncio
    async def test_exec_all_good(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "Origin" in cmd:
                    return "HTTP/1.1 200 OK\n"
                return ("HTTP/1.1 200 OK\n"
                        "X-Frame-Options: DENY\n"
                        "Content-Security-Policy: default-src 'self'\n"
                        "Strict-Transport-Security: max-age=31536000\n"
                        "X-Content-Type-Options: nosniff\n"
                        "X-XSS-Protection: 1\n")

        stub = Stub()
        monkeypatch.setattr(P.header_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["header_check"](stub, {"url": "https://t.com/"})
        assert "关键安全头齐全" in out
        assert "无 Access-Control-Allow-Origin" in out

    @pytest.mark.asyncio
    async def test_exec_cors_fixed(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "Origin" in cmd:
                    return ("HTTP/1.1 200 OK\n"
                            "Access-Control-Allow-Origin: https://t.com\n")
                return "HTTP/1.1 200 OK\nX-Frame-Options: DENY\n"

        stub = Stub()
        monkeypatch.setattr(P.header_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["header_check"](stub, {"url": "https://t.com/"})
        assert "固定值 https://t.com" in out

    @pytest.mark.asyncio
    async def test_exec_bad_url(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.header_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["header_check"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out


# ---------------------------------------------------------------------------
# http_methods：HTTP 方法测试
# ---------------------------------------------------------------------------
class TestHttpMethods:
    def test_build_cmd_and_parse(self):
        from kalitui.profiles.http_methods import _build_cmd, _parse_allow, _parse_status

        cmd = _build_cmd("http://t.com/", "OPTIONS")
        assert "-X OPTIONS" in cmd and "'http://t.com/'" in cmd
        assert _parse_allow("HTTP/1.1 200 OK\nAllow: GET, POST, PUT, OPTIONS\n") == [
            "GET", "POST", "PUT", "OPTIONS"]
        assert _parse_allow("HTTP/1.1 200 OK\nServer: nginx\n") == []
        assert _parse_status("HTTP/1.1 405 Method Not Allowed\n") == "405"
        assert _parse_status("junk") == ""

    @pytest.mark.asyncio
    async def test_exec_risky_methods(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "-X OPTIONS" in cmd:
                    return "HTTP/1.1 200 OK\nAllow: GET, POST, TRACE, OPTIONS\n"
                if "-X TRACE" in cmd:
                    return "HTTP/1.1 200 OK\nContent-Type: message/http\n"
                return "HTTP/1.1 405 Method Not Allowed\n"

        stub = Stub()
        monkeypatch.setattr(P.http_methods, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["http_methods"](
            stub, {"url": "http://t.com/"})
        assert "Allow 清单" in out and "TRACE" in out
        assert "高风险方法可用" in out and "XST" in out
        assert "PUT → 405" in out  # 拒绝行

    @pytest.mark.asyncio
    async def test_exec_safe_and_put(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "-X OPTIONS" in cmd:
                    return "HTTP/1.1 200 OK\nAllow: GET, POST, OPTIONS\n"
                if "-X PUT" in cmd:
                    return "HTTP/1.1 201 Created\n"
                return "HTTP/1.1 405 Method Not Allowed\n"

        stub = Stub()
        monkeypatch.setattr(P.http_methods, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["http_methods"](stub, {"url": "http://t.com/"})
        assert "PUT → 201（允许！）" in out
        assert "可尝试上传/修改/删除文件" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "-X OPTIONS" in cmd:
                    return "HTTP/1.1 200 OK\nAllow: GET, POST\n"
                if "-X CONNECT" in cmd:
                    return ""  # 无响应（如代理拦截）→ 跳过该行
                return "HTTP/1.1 403 Forbidden\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["http_methods"](stub2, {"url": "http://t.com/"})
        assert "高风险方法均被拒绝" in out2

    @pytest.mark.asyncio
    async def test_exec_bad_url(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.http_methods, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["http_methods"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out


# ---------------------------------------------------------------------------
# jwt_check：JWT 本地弱点分析
# ---------------------------------------------------------------------------
class TestJwtCheck:
    def test_parse_and_analyze(self):
        from kalitui.profiles.jwt_check import _analyze, _parse, _make_token

        h, p, sig = _parse(_make_token({"alg": "RS256"}, {"sub": "u1"}))
        assert h["alg"] == "RS256" and p["sub"] == "u1" and sig is True
        with pytest.raises(ValueError):
            _parse("a.b")  # 段数不够
        with pytest.raises(ValueError):
            _parse(_make_token({"alg": "RS256"}, "notjson"))

        # alg=none + 无签名 + 权限字段
        h2, p2, sig2 = _parse(_make_token({"alg": "none"}, {"admin": True}, sig=""))
        risks = _analyze(h2, p2, sig2, now=1e9)
        joined = "\n".join(risks)
        assert "alg=none" in joined and "无签名段" in joined and "admin" in joined
        # HS256 混淆提示
        risks2 = _analyze({"alg": "HS256"}, {}, True, now=1e9)
        assert "算法混淆" in "\n".join(risks2)
        # exp 检查
        risks3 = _analyze({"alg": "RS256"}, {"exp": 999}, True, now=1e9)
        assert "已过期" in "\n".join(risks3)
        risks4 = _analyze({"alg": "RS256"}, {"exp": 2e9}, True, now=1e9)
        assert "剩余" in "\n".join(risks4)
        # 缺 exp
        risks5 = _analyze({"alg": "RS256"}, {}, True, now=1e9)
        assert "永不过期" in "\n".join(risks5)
        # 缺 alg
        risks6 = _analyze({}, {}, True, now=1e9)
        assert "缺少 alg" in "\n".join(risks6)

    @pytest.mark.asyncio
    async def test_exec_valid_and_bad(self, monkeypatch):
        from kalitui import profiles as P
        from kalitui.profiles.jwt_check import _make_token

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.jwt_check.time, "time", lambda: 1e9)
        P.register_extensions(stub)  # type: ignore[arg-type]
        tok = _make_token({"alg": "RS256"}, {"sub": "u1", "exp": 2e9})
        out = await stub.extensions["jwt_check"](stub, {"token": tok})
        assert "JWT 分析" in out and "RS256" in out and "剩余" in out
        tok2 = _make_token({"alg": "none"}, {"admin": True}, sig="")
        out2 = await stub.extensions["jwt_check"](stub, {"token": tok2})
        assert "alg=none" in out2 and "伪造" in out2

    @pytest.mark.asyncio
    async def test_exec_parse_fail_and_format(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["jwt_check"](stub, {"token": ""})
        assert "不能为空" in out
        out2 = await stub.extensions["jwt_check"](stub, {"token": "bad token!!"})
        assert "格式非法" in out2
        out3 = await stub.extensions["jwt_check"](stub, {"token": "a.b.c"})
        assert "解析失败" in out3


# ---------------------------------------------------------------------------
# open_redirect：开放重定向检测
# ---------------------------------------------------------------------------
class TestOpenRedirect:
    def test_build_cmd_and_parse(self):
        from kalitui.profiles.open_redirect import _build_cmd, _parse_code, _parse_location

        cmd = _build_cmd("http://t.com/login", "next")
        assert "?next=http://evil.com" in cmd and "'http://t.com/login" in cmd
        cmd2 = _build_cmd("http://t.com/login?x=1", "url")
        assert "&url=http://evil.com" in cmd2
        raw = "HTTP/1.1 302 Found\nLocation: http://evil.com/steal\n\n302"
        assert _parse_location(raw) == "http://evil.com/steal"
        assert _parse_code(raw) == "302"
        assert _parse_location("HTTP/1.1 200 OK\nServer: nginx\n") == ""
        assert _parse_code("junk") == ""

    @pytest.mark.asyncio
    async def test_exec_hit_and_clean(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "next=http://evil.com" in cmd:
                    return "HTTP/1.1 302 Found\nLocation: http://evil.com/steal\n\n302"
                if "url=http://evil.com" in cmd:
                    return "HTTP/1.1 302 Found\nLocation: http://t.com/home\n\n302"
                return "HTTP/1.1 200 OK\n\n200"

        stub = Stub()
        monkeypatch.setattr(P.open_redirect, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["open_redirect"](
            stub, {"url": "http://t.com/login"})
        assert "开放重定向命中" in out and "next" in out
        assert "http://evil.com" in out
        assert "url" not in out.split("开放重定向命中")[1].split("下一步")[0]

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "HTTP/1.1 200 OK\n\n200"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["open_redirect"](stub2, {"url": "http://t.com/"})
        assert "未发现开放重定向" in out2

    @pytest.mark.asyncio
    async def test_exec_bad_inputs(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.open_redirect, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["open_redirect"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out
        with pytest.raises(ValueError):
            await stub.extensions["open_redirect"](
                stub, {"url": "http://t.com/", "params": "nope"})
        with pytest.raises(ValueError):
            await stub.extensions["open_redirect"](
                stub, {"url": "http://t.com/", "params": ["bad-param"]})
        with pytest.raises(ValueError):
            await stub.extensions["open_redirect"](
                stub, {"url": "http://t.com/",
                       "params": [f"p{i}" for i in range(15)]})

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "custom1=http://evil.com" in cmd:
                    return "HTTP/1.1 302 Found\nLocation: http://evil.com/x\n\n302"
                return "HTTP/1.1 200 OK\n\n200"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["open_redirect"](
            stub2, {"url": "http://t.com/", "params": ["custom1"]})
        assert "custom1" in out2


# ---------------------------------------------------------------------------
# email_auth：邮件安全记录检查
# ---------------------------------------------------------------------------
class TestEmailAuth:
    def test_build_cmd_and_parse(self):
        from kalitui.profiles.email_auth import _build_cmd, _parse_txt

        assert _build_cmd("example.com", "") == "dig +short TXT example.com"
        assert _build_cmd("example.com", "_dmarc") == "dig +short TXT _dmarc.example.com"
        assert _parse_txt('"v=spf1 include:_spf.google.com ~all"' + "\n") == \
            "v=spf1 include:_spf.google.com ~all"
        assert _parse_txt('"v=spf1 " "include:example.com " "~all"\n') == \
            "v=spf1 include:example.com ~all"
        assert _parse_txt("") == ""

    def test_analyze_branches(self):
        from kalitui.profiles.email_auth import _analyze

        out = _analyze("example.com", "", "")
        assert "SPF: 缺失" in out and "DMARC: 缺失" in out
        out2 = _analyze("example.com",
                        '"v=spf1 include:_spf.google.com ~all"',
                        '"v=DMARC1; p=reject; rua=mailto:x"')
        assert "SPF: 存在" in out2 and "p=reject" in out2
        out3 = _analyze("example.com", '"v=spf1 +all"', '"v=DMARC1; p=none"')
        assert "+all 宽松" in out3 and "p=none" in out3
        out4 = _analyze("example.com", '"random txt"', '"junk"')
        assert "无 v=spf1" in out4 and "格式异常" in out4
        out5 = _analyze("example.com",
                        '"v=spf1 ~all"', '"v=DMARC1; p=quarantine; rua=mailto:x"')
        assert "SPF: 存在" in out5 and "quarantine" in out5

    @pytest.mark.asyncio
    async def test_exec_full(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "_dmarc" in cmd:
                    return '"v=DMARC1; p=none; rua=mailto:dmarc@example.com"\n'
                return '"v=spf1 include:_spf.google.com ~all"\n'

        stub = Stub()
        monkeypatch.setattr(P.email_auth, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["email_auth"](
            stub, {"domain": "example.com"})
        assert "example.com" in out and "SPF: 存在" in out
        assert "p=none" in out and "DKIM" in out

    @pytest.mark.asyncio
    async def test_exec_bad_inputs(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.email_auth, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["email_auth"](stub, {"domain": "bad dom!"})
        assert "domain 格式非法" in out
        monkeypatch.setattr(P.email_auth, "check_installed", lambda t: False)
        out2 = await stub.extensions["email_auth"](stub, {"domain": "example.com"})
        assert "未安装" in out2


# ---------------------------------------------------------------------------
# whois_lookup：Whois 注册信息查询
# ---------------------------------------------------------------------------
class TestWhoisLookup:
    def test_parse_fields(self):
        from kalitui.profiles.whois_lookup import _parse

        raw = (
            "Domain Name: EXAMPLE.COM\n"
            "Registrar: GoDaddy.com, LLC\n"
            "Creation Date: 1995-08-14T04:00:00Z\n"
            "Registry Expiry Date: 2026-08-13T04:00:00Z\n"
            "Name Server: NS1.EXAMPLE.COM\n"
            "Name Server: NS2.EXAMPLE.COM\n"
            "Registrant Organization: Example Inc.\n"
            "Registrant Country: US\n"
            "Registrant Email: admin@example.com\n"
        )
        info = _parse(raw)
        assert info["注册商"] == "GoDaddy.com, LLC"
        assert "1995-08-14" in info["创建时间"]
        assert "2026-08-13" in info["过期时间"]
        assert "NS1.EXAMPLE.COM" in info["DNS 服务器"]
        assert info["注册人组织"] == "Example Inc."
        assert info["注册人国家"] == "US"
        assert info["注册邮箱"] == "admin@example.com"
        assert _parse("No match for domain\n") == {}

    @pytest.mark.asyncio
    async def test_exec_full_and_empty(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ("Registrar: Namecheap Inc.\n"
                        "Creation Date: 2010-01-01T00:00:00Z\n"
                        "Name Server: DNS1.REGISTRAR-SERVERS.COM\n")

        stub = Stub()
        monkeypatch.setattr(P.whois_lookup, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["whois_lookup"](
            stub, {"target": "example.com"})
        assert "whois 摘要" in out and "Namecheap" in out
        assert "注册邮箱: " not in out  # 字段未提取到

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "No match for domain\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["whois_lookup"](stub2, {"target": "8.8.8.8"})
        assert "未提取到标准字段" in out2

    @pytest.mark.asyncio
    async def test_exec_bad_inputs(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.whois_lookup, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["whois_lookup"](stub, {"target": "bad dom!"})
        assert "target 格式非法" in out
        out2 = await stub.extensions["whois_lookup"](stub, {"target": "localhost"})
        assert "target 格式非法" in out2  # 无点号的单标签名
        monkeypatch.setattr(P.whois_lookup, "check_installed", lambda t: False)
        out3 = await stub.extensions["whois_lookup"](stub, {"target": "example.com"})
        assert "未安装" in out3


# ---------------------------------------------------------------------------
# sub_takeover：子域名接管检测
# ---------------------------------------------------------------------------
class TestSubTakeover:
    def test_parse_cname_and_fingerprint(self):
        from kalitui.profiles.sub_takeover import _fingerprint, _parse_cname

        assert _parse_cname("blog.example.com. 300 IN CNAME user.github.io.\n") == \
            "user.github.io"
        assert _parse_cname("alias.example.com.\t3600\tIN\tCNAME\tapp.herokuapp.com.\n") == \
            "app.herokuapp.com"
        assert _parse_cname("x.example.com. 300 IN CNAME internal.corp.example.com.\n") == \
            "internal.corp.example.com"
        assert _parse_cname(";; No answer\n") == ""
        assert _parse_cname("CNAME alias to something\n") == ""  # cname 前缀行跳过
        assert _parse_cname("   \n") == ""  # 空行跳过
        assert _parse_cname("alias.example.com IN A 1.2.3.4\n") == "1.2.3.4"  # 非标准行兜底
        assert _fingerprint("user.github.io") == "GitHub Pages"
        assert _fingerprint("app.herokuapp.com") == "Heroku"
        assert _fingerprint("cdn.example.com") is None

    @pytest.mark.asyncio
    async def test_exec_hits_and_clean(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "crt.sh" in cmd or "curl" in cmd:
                    return '[{"name_value": "blog.example.com\\nwww.example.com"}]\n'
                if "blog.example.com" in cmd:
                    return "blog.example.com. 300 IN CNAME user.github.io.\n"
                if "www.example.com" in cmd:
                    return "www.example.com. 300 IN CNAME target.example.com.\n"
                return ""

        stub = Stub()
        monkeypatch.setattr(P.sub_takeover, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["sub_takeover"](
            stub, {"domain": "example.com"})
        assert "疑似子域名接管" in out and "blog.example.com" in out
        assert "user.github.io" in out and "GitHub Pages" in out
        assert "www.example.com" not in out.split("疑似子域名接管")[1].split("下一步")[0]

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                if "crt.sh" in arguments["command"] or "curl" in arguments["command"]:
                    return '[{"name_value": "www.example.com"}]\n'
                return "www.example.com. 300 IN CNAME www.example.com.\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["sub_takeover"](stub2, {"domain": "example.com"})
        assert "未发现接管指纹" in out2

    @pytest.mark.asyncio
    async def test_exec_no_subs_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.sub_takeover, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["sub_takeover"](stub, {"domain": "example.com"})
        assert "crt.sh 未发现子域记录" in out
        out2 = await stub.extensions["sub_takeover"](stub, {"domain": "bad dom!"})
        assert "domain 格式非法" in out2
        monkeypatch.setattr(P.sub_takeover, "check_installed", lambda t: False)
        out3 = await stub.extensions["sub_takeover"](stub, {"domain": "example.com"})
        assert "未安装" in out3


# ---------------------------------------------------------------------------
# page_scan：HTML 注释信息泄露检查
# ---------------------------------------------------------------------------
class TestPageScan:
    def test_extract_and_filter(self):
        from kalitui.profiles.page_scan import _extract_comments, _filter_comments

        raw = ("<html><!-- admin panel at /internal/login -->\n"
               "<p>hi</p><!-- 正常注释 -->\n"
               "<!--\n  password: admin123\n-->\n<!-- -->")
        comments = _extract_comments(raw)
        assert len(comments) == 4
        assert "admin panel at /internal/login" in comments[0]
        hits = _filter_comments(comments)
        assert len(hits) == 2  # admin + password 命中，正常注释/空注释过滤
        assert "password: admin123" in hits[1]
        assert _filter_comments([]) == []
        assert _filter_comments(["普通注释", "   "]) == []

    @pytest.mark.asyncio
    async def test_exec_hits_and_clean(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ("<html><!-- admin: /internal?debug=1 -->\n"
                        "<body>ok</body><!-- 常规 -->\n")

        stub = Stub()
        monkeypatch.setattr(P.page_scan, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["page_scan"](
            stub, {"url": "http://t.com/index.html"})
        assert "敏感注释命中" in out and "/internal?debug=1" in out
        assert "常规" not in out.split("敏感注释命中")[1].split("下一步")[0]

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "<html><!-- 欢迎光临 --><p>hi</p></html>"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["page_scan"](stub2, {"url": "http://t.com/"})
        assert "无敏感注释" in out2 and "1 条注释" in out2

        class Stub3:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "".join(f"<!-- admin path {i} -->" for i in range(20))

        stub3 = Stub3()
        P.register_extensions(stub3)  # type: ignore[arg-type]
        out3 = await stub3.extensions["page_scan"](stub3, {"url": "http://t.com/"})
        assert "共 20 条" in out3

    @pytest.mark.asyncio
    async def test_exec_truncate_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "x" * 100000

        stub = Stub()
        monkeypatch.setattr(P.page_scan, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["page_scan"](stub, {"url": "http://t.com/"})
        assert "无敏感注释" in out  # 超长截断后仍正常
        out2 = await stub.extensions["page_scan"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out2
        monkeypatch.setattr(P.page_scan, "check_installed", lambda t: False)
        out3 = await stub.extensions["page_scan"](stub, {"url": "http://t.com/"})
        assert "未安装" in out3


# ---------------------------------------------------------------------------
# path_traversal：目录穿越检测
# ---------------------------------------------------------------------------
class TestPathTraversal:
    def test_payloads_and_detect(self):
        from kalitui.profiles.path_traversal import (
            _DEFAULT_PAYLOADS, _is_passwd_hit)

        assert len(_DEFAULT_PAYLOADS) == 8
        assert any("etc/passwd" in p for p in _DEFAULT_PAYLOADS)
        assert _is_passwd_hit("root:x:0:0:root:/root:/bin/bash\n") is True
        assert _is_passwd_hit("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n") is True
        assert _is_passwd_hit("<html>404 not found</html>\n") is False
        assert _is_passwd_hit("some root:x thing inline") is False  # 需行首

    @pytest.mark.asyncio
    async def test_exec_hit_and_clean(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "%252f" in cmd or "etc%252fpasswd" in cmd:
                    return "root:x:0:0:root:/root:/bin/bash\n"
                return "<html>not found</html>\n"

        stub = Stub()
        monkeypatch.setattr(P.path_traversal, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["path_traversal"](
            stub, {"url": "http://t.com/file.php?name=FUZZ"})
        assert "目录穿越命中" in out and "1/8" in out
        assert "root:x:0:0" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "<html>no</html>\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["path_traversal"](
            stub2, {"url": "http://t.com/dl?f=FUZZ"})
        assert "未命中" in out2 and "proc/self/environ" in out2

    @pytest.mark.asyncio
    async def test_exec_custom_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "custom_payload" in cmd:
                    return "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                return "no\n"

        stub = Stub()
        monkeypatch.setattr(P.path_traversal, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["path_traversal"](
            stub, {"url": "http://t.com/f?p=FUZZ",
                   "payloads": ["../../../../etc/passwd", "custom_payload"]})
        assert "custom_payload" in out and "nobody" in out

        out2 = await stub.extensions["path_traversal"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out2
        out3 = await stub.extensions["path_traversal"](
            stub, {"url": "http://t.com/f?p=FUZZ&q=FUZZ"})
        assert "只能包含一个 FUZZ" in out3
        out4 = await stub.extensions["path_traversal"](
            stub, {"url": "http://t.com/f?p=x"})
        assert "只能包含一个 FUZZ" in out4
        with pytest.raises(ValueError):
            await stub.extensions["path_traversal"](
                stub, {"url": "http://t.com/f?p=FUZZ", "payloads": "nope"})
        with pytest.raises(ValueError):
            await stub.extensions["path_traversal"](
                stub, {"url": "http://t.com/f?p=FUZZ", "payloads": ["bad payload;rm"]})
        with pytest.raises(ValueError):
            await stub.extensions["path_traversal"](
                stub, {"url": "http://t.com/f?p=FUZZ",
                       "payloads": [f"p{i}" for i in range(15)]})
        monkeypatch.setattr(P.path_traversal, "check_installed", lambda t: False)
        out5 = await stub.extensions["path_traversal"](
            stub, {"url": "http://t.com/f?p=FUZZ"})
        assert "未安装" in out5


# ---------------------------------------------------------------------------
# cmd_inject：命令注入检测
# ---------------------------------------------------------------------------
class TestCmdInject:
    def test_payloads_and_detect(self):
        from kalitui.profiles.cmd_inject import _DEFAULT_PAYLOADS, _is_inject_hit

        assert len(_DEFAULT_PAYLOADS) == 8
        assert _is_inject_hit("uid=33(www-data) gid=33(www-data)\n") is True
        assert _is_inject_hit("hello MARKER_CMD_INJECT world\n") is True
        assert _is_inject_hit("<html>not found</html>\n") is False
        assert _is_inject_hit("uid= not a real match") is False  # 需完整格式

    @pytest.mark.asyncio
    async def test_exec_hit_and_clean(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "ping?host=;id'" in cmd:
                    return "uid=0(root) gid=0(root)\n"
                if "MARKER" in cmd:
                    return "ok MARKER_CMD_INJECT done\n"
                return "<html>no</html>\n"

        stub = Stub()
        monkeypatch.setattr(P.cmd_inject, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["cmd_inject"](
            stub, {"url": "http://t.com/ping?host=FUZZ"})
        assert "命令注入命中" in out and "uid=0(root)" in out
        assert "MARKER_CMD_INJECT" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "<html>filtered</html>\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["cmd_inject"](
            stub2, {"url": "http://t.com/ping?host=FUZZ"})
        assert "未命中回显" in out2 and "sleep 5" in out2

    @pytest.mark.asyncio
    async def test_exec_custom_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "mycmd" in cmd:
                    return "uid=1000(kali) gid=1000(kali)\n"
                return "no\n"

        stub = Stub()
        monkeypatch.setattr(P.cmd_inject, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["cmd_inject"](
            stub, {"url": "http://t.com/x?c=FUZZ", "payloads": [";id", "mycmd"]})
        assert "mycmd" in out and "kali" in out

        out2 = await stub.extensions["cmd_inject"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out2
        out3 = await stub.extensions["cmd_inject"](
            stub, {"url": "http://t.com/x?c=FUZZ&d=FUZZ"})
        assert "只能包含一个 FUZZ" in out3
        with pytest.raises(ValueError):
            await stub.extensions["cmd_inject"](
                stub, {"url": "http://t.com/x?c=FUZZ", "payloads": "nope"})
        with pytest.raises(ValueError):
            await stub.extensions["cmd_inject"](
                stub, {"url": "http://t.com/x?c=FUZZ", "payloads": ["x\nrm -rf"]})
        with pytest.raises(ValueError):
            await stub.extensions["cmd_inject"](
                stub, {"url": "http://t.com/x?c=FUZZ",
                       "payloads": [f"p{i}" for i in range(15)]})
        monkeypatch.setattr(P.cmd_inject, "check_installed", lambda t: False)
        out4 = await stub.extensions["cmd_inject"](
            stub, {"url": "http://t.com/x?c=FUZZ"})
        assert "未安装" in out4


# ---------------------------------------------------------------------------
# ssrf_check：SSRF 检测
# ---------------------------------------------------------------------------
class TestSsrfCheck:
    def test_payloads_and_meta(self):
        from kalitui.profiles.ssrf_check import _DEFAULT_PAYLOADS, _is_meta_hit

        assert len(_DEFAULT_PAYLOADS) == 9
        assert any("169.254.169.254" in p for p in _DEFAULT_PAYLOADS)
        assert _is_meta_hit("ami-id ami-0abc123\n") is True
        assert _is_meta_hit('{"accountId": "123456"}') is True
        assert _is_meta_hit("<html>not found</html>\n") is False

    @pytest.mark.asyncio
    async def test_exec_meta_hit(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "metadata.google" in cmd:
                    return "ami-id: ami-123\ninstance-id: i-abc\n"
                if "latest/meta-data" in cmd:
                    return "ami-id: ami-456\nsecurity-credentials: admin\n"
                if "?url=x'" in cmd:
                    return "<html>base</html>\n"
                return "<html>no</html>\n"

        stub = Stub()
        monkeypatch.setattr(P.ssrf_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["ssrf_check"](
            stub, {"url": "http://t.com/fetch?url=FUZZ"})
        assert "云元数据泄露命中" in out and "security-credentials" in out
        assert "ami-id: ami-456" in out

    @pytest.mark.asyncio
    async def test_exec_diff_and_clean(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "?url=x'" in cmd:
                    return "<html>base</html>\n"
                if "127.0.0.1" in cmd:
                    return "<html>" + "y" * 500 + "</html>\n"  # 内网应用默认页
                return "<html>base</html>\n"

        stub = Stub()
        monkeypatch.setattr(P.ssrf_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["ssrf_check"](
            stub, {"url": "http://t.com/fetch?url=FUZZ"})
        assert "疑似 SSRF" in out and "127.0.0.1" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "<html>base</html>\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["ssrf_check"](
            stub2, {"url": "http://t.com/fetch?url=FUZZ"})
        assert "未发现 SSRF 迹象" in out2 and "gopher" in out2

    @pytest.mark.asyncio
    async def test_exec_bad_inputs(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.ssrf_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["ssrf_check"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out
        out2 = await stub.extensions["ssrf_check"](stub, {"url": "http://t.com/?u=FUZZ&v=FUZZ"})
        assert "只能包含一个 FUZZ" in out2
        with pytest.raises(ValueError):
            await stub.extensions["ssrf_check"](
                stub, {"url": "http://t.com/?u=FUZZ", "payloads": "nope"})
        with pytest.raises(ValueError):
            await stub.extensions["ssrf_check"](
                stub, {"url": "http://t.com/?u=FUZZ", "payloads": ["x;rm"]})
        with pytest.raises(ValueError):
            await stub.extensions["ssrf_check"](
                stub, {"url": "http://t.com/?u=FUZZ",
                       "payloads": [f"p{i}" for i in range(15)]})
        monkeypatch.setattr(P.ssrf_check, "check_installed", lambda t: False)
        out3 = await stub.extensions["ssrf_check"](stub, {"url": "http://t.com/?u=FUZZ"})
        assert "未安装" in out3


# ---------------------------------------------------------------------------
# xxe_check：XXE 检测
# ---------------------------------------------------------------------------
class TestXxeCheck:
    def test_payloads_and_detect(self):
        from kalitui.profiles.xxe_check import _DEFAULT_PAYLOADS, _is_xxe_hit

        assert len(_DEFAULT_PAYLOADS) == 3
        assert all("DOCTYPE" in p for p in _DEFAULT_PAYLOADS)
        assert _is_xxe_hit("root:x:0:0:root:/root:/bin/bash\n") is True
        assert _is_xxe_hit("web01.example.com\n") is True  # hostname 特征
        assert _is_xxe_hit("<html>parse error</html>\n") is False

    @pytest.mark.asyncio
    async def test_exec_hit_and_clean(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "etc/passwd" in cmd:
                    return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n"
                if "etc/hostname" in cmd:
                    return "web01\n"
                return "parse error\n"

        stub = Stub()
        monkeypatch.setattr(P.xxe_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["xxe_check"](
            stub, {"url": "http://t.com/api/parse"})
        assert "XXE 命中" in out and "root:x:0:0" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "invalid XML\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["xxe_check"](stub2, {"url": "http://t.com/api/parse"})
        assert "未命中回显" in out2 and "外带" in out2

    @pytest.mark.asyncio
    async def test_exec_custom_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "myxxe" in cmd:
                    return "bin:x:2:2:bin:/bin\n"
                return "no\n"

        stub = Stub()
        monkeypatch.setattr(P.xxe_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["xxe_check"](
            stub, {"url": "http://t.com/api/parse",
                   "payloads": ["<?xml version=\"1.0\"?><r>myxxe</r>"]})
        assert "myxxe" in out and "bin:x:2:2" in out

        out2 = await stub.extensions["xxe_check"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out2
        with pytest.raises(ValueError):
            await stub.extensions["xxe_check"](
                stub, {"url": "http://t.com/api", "payloads": "nope"})
        with pytest.raises(ValueError):
            await stub.extensions["xxe_check"](
                stub, {"url": "http://t.com/api", "payloads": ["\x00bad"]})
        with pytest.raises(ValueError):
            await stub.extensions["xxe_check"](
                stub, {"url": "http://t.com/api",
                       "payloads": [f"<r>{i}</r>" for i in range(10)]})
        monkeypatch.setattr(P.xxe_check, "check_installed", lambda t: False)
        out3 = await stub.extensions["xxe_check"](stub, {"url": "http://t.com/api"})
        assert "未安装" in out3


# ---------------------------------------------------------------------------
# xss_check：反射型 XSS 检测
# ---------------------------------------------------------------------------
class TestXssCheck:
    def test_payloads_and_classify(self):
        from kalitui.profiles.xss_check import _DEFAULT_PAYLOADS, _classify

        assert len(_DEFAULT_PAYLOADS) == 5
        assert _classify('x<script>alert(1)</script>y', '<script>alert(1)</script>') == "raw"
        assert _classify('x&lt;script&gt;alert(1)&lt;/script&gt;y',
                         '<script>alert(1)</script>') == "encoded"
        assert _classify("no reflection", '<img src=x onerror=alert(1)>') == "none"

    @pytest.mark.asyncio
    async def test_exec_raw_and_encoded(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "onerror" in cmd:
                    return ('<html><body><p>结果: <img src=x onerror=alert(1)>'
                            ' 未找到</p></body></html>\n')
                return '<html>结果: &lt;script&gt;alert(1)&lt;/script&gt;</html>\n'

        stub = Stub()
        monkeypatch.setattr(P.xss_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["xss_check"](
            stub, {"url": "http://t.com/search?q=FUZZ"})
        assert "未编码反射" in out and "onerror" in out
        assert "上下文" in out and "1 个 payload 被编码" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "<html>结果: 未找到</html>\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["xss_check"](stub2, {"url": "http://t.com/s?q=FUZZ"})
        assert "未发现未编码反射" in out2

    @pytest.mark.asyncio
    async def test_exec_encoded_only(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return '<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>\n'

        stub = Stub()
        monkeypatch.setattr(P.xss_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["xss_check"](stub, {"url": "http://t.com/s?q=FUZZ"})
        assert "未发现未编码反射" in out
        assert "HTML 编码" in out

    @pytest.mark.asyncio
    async def test_exec_bad_inputs(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.xss_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["xss_check"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out
        out2 = await stub.extensions["xss_check"](stub, {"url": "http://t.com/?q=FUZZ&r=FUZZ"})
        assert "只能包含一个 FUZZ" in out2
        with pytest.raises(ValueError):
            await stub.extensions["xss_check"](
                stub, {"url": "http://t.com/?q=FUZZ", "payloads": "nope"})
        with pytest.raises(ValueError):
            await stub.extensions["xss_check"](
                stub, {"url": "http://t.com/?q=FUZZ", "payloads": ["\x00bad"]})
        with pytest.raises(ValueError):
            await stub.extensions["xss_check"](
                stub, {"url": "http://t.com/?q=FUZZ",
                       "payloads": [f"<b>{i}</b>" for i in range(15)]})

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return '<p>myxss</p>\n'

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out4 = await stub2.extensions["xss_check"](
            stub2, {"url": "http://t.com/?q=FUZZ", "payloads": ["<b>myxss</b>"]})
        assert "未发现未编码反射" in out4
        monkeypatch.setattr(P.xss_check, "check_installed", lambda t: False)
        out3 = await stub.extensions["xss_check"](stub, {"url": "http://t.com/?q=FUZZ"})
        assert "未安装" in out3


# ---------------------------------------------------------------------------
# exif_meta：EXIF 元数据提取
# ---------------------------------------------------------------------------
class TestExifMeta:
    def test_parse_and_dms(self):
        from kalitui.profiles.exif_meta import _dms_to_decimal, _parse

        raw = (
            "File Name : photo.jpg\n"
            "GPS Latitude : 39 deg 54' 26.10\" N\n"
            "GPS Longitude : 116 deg 23' 29.20\" E\n"
            "Artist : Zhang San\n"
            "Software : Adobe Photoshop 24.0\n"
            "Model : iPhone 15 Pro\n"
            "DateTimeOriginal : 2024:03:01 10:30:00\n"
        )
        info = _parse(raw)
        assert info["GPS Latitude"] == "39 deg 54' 26.10\" N"
        assert info["Artist"] == "Zhang San"
        assert info["Model"] == "iPhone 15 Pro"
        assert info["Software"] == "Adobe Photoshop 24.0"
        assert _dms_to_decimal("39 deg 54' 26.10\" N") is not None
        assert 39.90 < _dms_to_decimal("39 deg 54' 26.10\" N") < 39.92
        assert _dms_to_decimal("151 deg 12' 0.00\" S") < 0  # 南纬为负
        assert _dms_to_decimal("garbage") is None
        assert "DateTimeOriginal" in info

    @pytest.mark.asyncio
    async def test_exec_with_gps(self, monkeypatch, tmp_path):
        from kalitui import profiles as P

        img = tmp_path / "p.jpg"
        img.write_bytes(b"junk")

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ("GPS Latitude : 39 deg 54' 26.10\" N\n"
                        "GPS Longitude : 116 deg 23' 29.20\" E\n"
                        "Artist : Zhang San\n")

        stub = Stub()
        monkeypatch.setattr(P.exif_meta, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["exif_meta"](stub, {"file": str(img)})
        assert "GPS: 39.907" in out and "google.com/maps" in out
        assert "Zhang San" in out

    @pytest.mark.asyncio
    async def test_exec_empty_and_bad(self, monkeypatch, tmp_path):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "File Name : x.jpg\n"

        stub = Stub()
        monkeypatch.setattr(P.exif_meta, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["exif_meta"](
            stub, {"file": str(tmp_path / "nope.jpg")})
        assert "文件不存在" in out
        out2 = await stub.extensions["exif_meta"](stub, {"file": ""})
        assert "路径非法" in out2
        out3 = await stub.extensions["exif_meta"](stub, {"file": "a\nb"})
        assert "路径非法" in out3

        img = tmp_path / "clean.jpg"
        img.write_bytes(b"junk")

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "File Name : clean.jpg\nFile Size : 4 bytes\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out5 = await stub2.extensions["exif_meta"](stub2, {"file": str(img)})
        assert "未提取到关键元数据" in out5
        monkeypatch.setattr(P.exif_meta, "check_installed", lambda t: False)
        out4 = await stub.extensions["exif_meta"](
            stub, {"file": str(tmp_path / "nope.jpg")})
        assert "未安装" in out4


# ---------------------------------------------------------------------------
# csrf_check：CSRF 表单 token 检查
# ---------------------------------------------------------------------------
class TestCsrfCheck:
    def test_extract_forms(self):
        from kalitui.profiles.csrf_check import _extract_forms, _has_token

        raw = (
            '<form action="/change_pwd" method="POST">'
            '<input type="hidden" name="csrf_token" value="abc">'
            '<input type="text" name="old_pwd">'
            '</form>\n'
            '<form method="get" action="/delete?id=1">'
            '<input type="submit" name="go">'
            '</form>'
        )
        forms = _extract_forms(raw)
        assert len(forms) == 2
        assert forms[0]["action"] == "/change_pwd" and forms[0]["method"] == "post"
        assert _has_token(forms[0]["inputs"]) is True
        assert _has_token(forms[1]["inputs"]) is False
        assert _extract_forms("<html>no forms</html>") == []
        assert _has_token([]) is False

    @pytest.mark.asyncio
    async def test_exec_mixed(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return (
                    '<form action="/safe" method="POST">'
                    '<input name="csrfmiddlewaretoken" value="x"></form>\n'
                    '<form action="/delete" method="GET">'
                    '<input name="id"></form>\n'
                    '<form action="/transfer" method="POST">'
                    '<input name="amount"></form>'
                )

        stub = Stub()
        monkeypatch.setattr(P.csrf_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["csrf_check"](stub, {"url": "http://t.com/"})
        assert "3 个表单" in out and "无 CSRF token 的表单 (2)" in out
        assert "/delete" in out and "/transfer" in out
        summary = out.split("下一步")[0]
        assert "/safe" not in summary.split("无 CSRF token")[1]

    @pytest.mark.asyncio
    async def test_exec_all_safe_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ('<form action="/a"><input name="_token" value="x">'
                        '<input name="user"></form>')

        stub = Stub()
        monkeypatch.setattr(P.csrf_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["csrf_check"](stub, {"url": "http://t.com/"})
        assert "全部表单均含 CSRF token" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "<html>static page</html>\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["csrf_check"](stub2, {"url": "http://t.com/"})
        assert "0 个表单" in out2

        out3 = await stub2.extensions["csrf_check"](stub2, {"url": "ftp://x"})
        assert "url 格式非法" in out3

        class Stub3:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "".join(
                    f'<form action="/f{i}"><input name="a{i}"></form>'
                    for i in range(12)) + "x" * 20000

        stub3 = Stub3()
        P.register_extensions(stub3)  # type: ignore[arg-type]
        out5 = await stub3.extensions["csrf_check"](stub3, {"url": "http://t.com/"})
        assert "共 12 个无 token 表单" in out5
        monkeypatch.setattr(P.csrf_check, "check_installed", lambda t: False)
        out4 = await stub2.extensions["csrf_check"](stub2, {"url": "http://t.com/"})
        assert "未安装" in out4


# ---------------------------------------------------------------------------
# error_leak：错误页信息泄露检测
# ---------------------------------------------------------------------------
class TestErrorLeak:
    def test_find_leak(self):
        from kalitui.profiles.error_leak import _find_leak

        assert "Traceback" in _find_leak("Traceback (most recent call last):\nFile /x.py") 
        assert "nginx" in _find_leak("Powered by nginx/1.18.0")
        assert "/var/www" in _find_leak("open(/var/www/html/config.php)")
        assert "Fatal error" in _find_leak("Fatal error: Uncaught TypeError")
        assert "at com.foo.Bar" in _find_leak("java.lang.NullPointerException at com.foo.Bar.run:12")
        assert _find_leak("<html>404 not found</html>") is None

    @pytest.mark.asyncio
    async def test_exec_leak_and_clean(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "x[]=1" in cmd:
                    return ("Fatal error: Uncaught TypeError: array to string conversion "
                            "in /var/www/html/app.php on line 42\n")
                if "aaaa" in cmd:
                    return "Warning: 参数过长 in /var/www/html/app.php on line 10\n"
                return "<html>错误</html>\n"

        stub = Stub()
        monkeypatch.setattr(P.error_leak, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["error_leak"](stub, {"url": "http://t.com/app.php"})
        assert "错误页泄露" in out and "数组参数错误" in out
        assert "Fatal error" in out and "on line" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "<html>统一错误页</html>\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["error_leak"](stub2, {"url": "http://t.com/app.php"})
        assert "未发现错误页泄露" in out2

    @pytest.mark.asyncio
    async def test_exec_bad_url(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.error_leak, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["error_leak"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out
        monkeypatch.setattr(P.error_leak, "check_installed", lambda t: False)
        out2 = await stub.extensions["error_leak"](stub, {"url": "http://t.com/a.php"})
        assert "未安装" in out2


# ---------------------------------------------------------------------------
# api_enum：API 端点枚举
# ---------------------------------------------------------------------------
class TestApiEnum:
    def test_build_and_parse(self):
        from kalitui.profiles.api_enum import _build_cmd, _parse_probe

        cmd = _build_cmd("http://t.com", "/api/v1/users")
        assert "'http://t.com/api/v1/users'" in cmd
        assert "%{http_code} %{size_download}" in cmd
        assert _parse_probe("200 1234") == ("200", "1234")
        assert _parse_probe("") == ("000", "0")

    @pytest.mark.asyncio
    async def test_exec_open_and_auth(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "api/v1/users'" in cmd:
                    return "200 5432"
                if "api/admin" in cmd:
                    return "401 0"
                if "api/internal" in cmd:
                    return "403 12"
                return "404 0"

        stub = Stub()
        monkeypatch.setattr(P.api_enum, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["api_enum"](stub, {"url": "http://t.com"})
        assert "未授权可访问" in out and "api/v1/users" in out
        assert "存在但需认证" in out and "api/admin" in out
        assert "api/internal" in out

    @pytest.mark.asyncio
    async def test_exec_nothing_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "404 0"

        stub = Stub()
        monkeypatch.setattr(P.api_enum, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["api_enum"](stub, {"url": "http://t.com"})
        assert "全部 404" in out

        out2 = await stub.extensions["api_enum"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out2
        with pytest.raises(ValueError):
            await stub.extensions["api_enum"](stub, {"url": "http://t.com", "paths": "x"})
        with pytest.raises(ValueError):
            await stub.extensions["api_enum"](stub, {"url": "http://t.com", "paths": ["bad path"]})
        with pytest.raises(ValueError):
            await stub.extensions["api_enum"](
                stub, {"url": "http://t.com", "paths": [f"/p{i}" for i in range(30)]})

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "custom1'" in cmd:
                    return "200 99"
                return "404 0"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out4 = await stub2.extensions["api_enum"](
            stub2, {"url": "http://t.com", "paths": ["/custom1"]})
        assert "custom1" in out4
        monkeypatch.setattr(P.api_enum, "check_installed", lambda t: False)
        out3 = await stub.extensions["api_enum"](stub, {"url": "http://t.com"})
        assert "未安装" in out3


# ---------------------------------------------------------------------------
# ssh_banner：SSH Banner 版本审计
# ---------------------------------------------------------------------------
class TestSshBanner:
    def test_parse_and_weak(self):
        from kalitui.profiles.ssh_banner import (
            _check_weak, _parse_banner, _parse_version)

        assert _parse_banner("SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\n") == \
            "OpenSSH_7.2p2"
        assert _parse_banner("SSH-2.0-OpenSSH_9.6p1 Debian-3\n") == "OpenSSH_9.6p1"
        assert _parse_banner("220 ftp ready\n") == ""
        assert _parse_version("OpenSSH_7.2p2") == (7, 2, 0)
        assert _parse_version("OpenSSH_9.3.1p1") == (9, 3, 1)
        assert _parse_version("weird") == (99, 99, 99)
        assert "CVE-2016-6210" in _check_weak("OpenSSH_7.2p2")
        assert "CVE-2023-38408" in _check_weak("OpenSSH_8.9p1")
        assert _check_weak("OpenSSH_9.6p1") is None
        assert _check_weak("weird") is None

    @pytest.mark.asyncio
    async def test_exec_weak_and_safe(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\n"

        stub = Stub()
        monkeypatch.setattr(P.ssh_banner, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["ssh_banner"](
            stub, {"target": "10.0.0.9", "port": 22})
        assert "SSH 指纹" in out and "OpenSSH_7.2p2" in out
        assert "弱版本风险" in out and "CVE-2016-6210" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "SSH-2.0-OpenSSH_9.6p1 Debian-3\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["ssh_banner"](stub2, {"target": "t.com"})
        assert "版本高于已知弱版本阈值" in out2

    @pytest.mark.asyncio
    async def test_exec_no_banner_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.ssh_banner, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["ssh_banner"](stub, {"target": "10.0.0.9"})
        assert "未获取到 SSH banner" in out
        out2 = await stub.extensions["ssh_banner"](stub, {"target": "bad host!"})
        assert "target 格式非法" in out2
        out3 = await stub.extensions["ssh_banner"](stub, {"target": "t.com", "port": 0})
        assert "port 非法" in out3
        monkeypatch.setattr(P.ssh_banner, "check_installed", lambda t: False)
        out4 = await stub.extensions["ssh_banner"](stub, {"target": "t.com"})
        assert "未安装" in out4


# ---------------------------------------------------------------------------
# default_page：默认页检测
# ---------------------------------------------------------------------------
class TestDefaultPage:
    def test_match_defaults(self):
        from kalitui.profiles.default_page import _match_defaults

        assert _match_defaults("<title>Welcome to nginx!</title>\n") == ["nginx 默认欢迎页"]
        assert _match_defaults("Apache2 Ubuntu Default Page: It works\n") == [
            "Apache2（Ubuntu）默认页"]
        hits = _match_defaults("<h1>It works!</h1>\n")
        assert hits == ["Apache 默认页"]
        assert _match_defaults("<html><body>Company Site</body></html>") == []

    @pytest.mark.asyncio
    async def test_exec_hit_and_clean(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ("<html><head><title>Welcome to nginx!</title></head>"
                        "<body>If you see this page, the nginx web server is "
                        "successfully installed.</body></html>\n")

        stub = Stub()
        monkeypatch.setattr(P.default_page, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["default_page"](stub, {"url": "http://t.com/"})
        assert "疑似默认安装页" in out and "nginx 默认欢迎页" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "<html><body>深挖科技 - 产品首页</body></html>\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["default_page"](stub2, {"url": "http://t.com/"})
        assert "未匹配默认页特征" in out2

        class Stub3:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "x" * 40000

        stub3 = Stub3()
        P.register_extensions(stub3)  # type: ignore[arg-type]
        out3 = await stub3.extensions["default_page"](stub3, {"url": "http://t.com/"})
        assert "未匹配默认页特征" in out3  # 超长截断后正常判定

    @pytest.mark.asyncio
    async def test_exec_bad_url(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.default_page, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["default_page"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out
        monkeypatch.setattr(P.default_page, "check_installed", lambda t: False)
        out2 = await stub.extensions["default_page"](stub, {"url": "http://t.com/"})
        assert "未安装" in out2


# ---------------------------------------------------------------------------
# directory_list：目录列表检测
# ---------------------------------------------------------------------------
class TestDirectoryList:
    def test_listing_detect(self):
        from kalitui.profiles.directory_list import _is_listing

        assert _is_listing("<h1>Index of /backup</h1>\n<a href='a.zip'>") is True
        assert _is_listing("[To Parent Directory]  a.sql 2024-01-01") is True
        assert _is_listing("<html>403 Forbidden</html>") is False
        assert _is_listing("Directory not found") is False  # 无特征短语

    @pytest.mark.asyncio
    async def test_exec_hit_and_clean(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "/backup/'" in cmd:
                    return ("<h1>Index of /backup/</h1>\n"
                            "<a href='db.sql'>db.sql</a>\n"
                            "<a href='config.zip'>config.zip</a>\n")
                if "/uploads/'" in cmd:
                    return "Parent Directory\n<a href='photo1.jpg'>photo1.jpg</a>\n"
                return "<html>404 Not Found</html>\n"

        stub = Stub()
        monkeypatch.setattr(P.directory_list, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["directory_list"](stub, {"url": "http://t.com"})
        assert "目录列表开启" in out and "/backup/" in out
        assert "Index of /backup/" in out
        assert "/uploads/" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "<html>404 Not Found</html>\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["directory_list"](stub2, {"url": "http://t.com"})
        assert "未发现目录列表" in out2

    @pytest.mark.asyncio
    async def test_exec_bad_inputs(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ""

        stub = Stub()
        monkeypatch.setattr(P.directory_list, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["directory_list"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out
        with pytest.raises(ValueError):
            await stub.extensions["directory_list"](
                stub, {"url": "http://t.com", "paths": "x"})
        with pytest.raises(ValueError):
            await stub.extensions["directory_list"](
                stub, {"url": "http://t.com", "paths": ["bad path"]})
        with pytest.raises(ValueError):
            await stub.extensions["directory_list"](
                stub, {"url": "http://t.com", "paths": [f"/d{i}/" for i in range(20)]})

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "/custom1/'" in cmd:
                    return "<h1>Index of /custom1/</h1>\n"
                return "404\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out3 = await stub2.extensions["directory_list"](
            stub2, {"url": "http://t.com", "paths": ["/custom1/"]})
        assert "custom1" in out3
        monkeypatch.setattr(P.directory_list, "check_installed", lambda t: False)
        out2 = await stub.extensions["directory_list"](stub, {"url": "http://t.com"})
        assert "未安装" in out2


# ---------------------------------------------------------------------------
# cookie_check：Cookie 安全属性审计
# ---------------------------------------------------------------------------
class TestCookieCheck:
    def test_parse_and_analyze(self):
        from kalitui.profiles.cookie_check import _analyze_cookie, _parse_cookies

        raw = (
            "HTTP/1.1 200 OK\n"
            "Set-Cookie: session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax\n"
            "Set-Cookie: user_pref=dark; Path=/\n"
            "Set-Cookie: cross=1; SameSite=None\n"
        )
        cookies = _parse_cookies(raw)
        assert len(cookies) == 3
        assert cookies[0]["name"] == "session"
        assert cookies[0]["attrs"]["httponly"] is True
        assert cookies[0]["attrs"]["samesite"] == "Lax"
        assert _analyze_cookie(cookies[0]) == []
        missing = _analyze_cookie(cookies[1])
        joined = "、".join(missing)
        assert "HttpOnly" in joined and "Secure" in joined and "SameSite" in joined
        # SameSite=None 无 Secure
        missing2 = _analyze_cookie(cookies[2])
        assert "SameSite=None 但无 Secure" in "、".join(missing2)
        assert _parse_cookies("HTTP/1.1 200 OK\nServer: nginx\n") == []
        assert _parse_cookies("Set-Cookie: ; Path=/\n") == []  # 无名字段
        # SameSite 无值
        c3 = _parse_cookies("Set-Cookie: v=1; SameSite\n")
        assert "SameSite 无值" in "、".join(_analyze_cookie(c3[0]))

    @pytest.mark.asyncio
    async def test_exec_mixed(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ("HTTP/1.1 200 OK\n"
                        "Set-Cookie: session=abc; Path=/; HttpOnly\n"
                        "Set-Cookie: pref=1; Path=/\n"
                        "Set-Cookie: token=x; Path=/; HttpOnly; Secure; SameSite=Lax\n")

        stub = Stub()
        monkeypatch.setattr(P.cookie_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["cookie_check"](stub, {"url": "http://t.com/"})
        assert "Cookie 审计（3 个）" in out
        assert "session: 缺 Secure" in out
        assert "token: 属性齐全" in out
        assert "HttpOnly" in out

    @pytest.mark.asyncio
    async def test_exec_no_cookie_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "HTTP/1.1 200 OK\nServer: nginx\n"

        stub = Stub()
        monkeypatch.setattr(P.cookie_check, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["cookie_check"](stub, {"url": "http://t.com/"})
        assert "未返回 Set-Cookie" in out
        out2 = await stub.extensions["cookie_check"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out2
        monkeypatch.setattr(P.cookie_check, "check_installed", lambda t: False)
        out3 = await stub.extensions["cookie_check"](stub, {"url": "http://t.com/"})
        assert "未安装" in out3


# ---------------------------------------------------------------------------
# upload_detect：文件上传点发现
# ---------------------------------------------------------------------------
class TestUploadDetect:
    def test_extract_forms(self):
        from kalitui.profiles.upload_detect import _extract_forms

        raw = (
            '<form action="/avatar" enctype="multipart/form-data">'
            '<input type="file" name="pic"><input type="submit"></form>\n'
            '<form action="/plain" method="post">'
            '<input type="text" name="x"></form>\n'
            '<form action="/upload2" method="post">'
            '<input type="file" name="f"></form>'
        )
        forms = _extract_forms(raw)
        assert len(forms) == 2
        assert forms[0]["action"] == "/avatar"
        assert "multipart" in forms[0]["enctype"]
        assert forms[1]["action"] == "/upload2"
        assert _extract_forms("<html>no forms</html>") == []

    @pytest.mark.asyncio
    async def test_exec_with_upload(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "%{http_code}" in cmd:
                    if "/api/upload'" in cmd:
                        return "200 88"
                    return "404 0"
                return ('<form action="/avatar" enctype="multipart/form-data">'
                        '<input type="file" name="pic"></form>')

        stub = Stub()
        monkeypatch.setattr(P.upload_detect, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["upload_detect"](stub, {"url": "http://t.com/profile"})
        assert "页面上传表单" in out and "/avatar" in out
        assert "上传路径可达" in out and "/api/upload" in out

    @pytest.mark.asyncio
    async def test_exec_nothing_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                if "%{http_code}" in arguments["command"]:
                    return "404 0"
                return "<html>static</html>\n"

        stub = Stub()
        monkeypatch.setattr(P.upload_detect, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["upload_detect"](stub, {"url": "http://t.com/"})
        assert "未发现上传入口" in out
        out2 = await stub.extensions["upload_detect"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out2
        with pytest.raises(ValueError):
            await stub.extensions["upload_detect"](
                stub, {"url": "http://t.com/", "paths": "x"})
        with pytest.raises(ValueError):
            await stub.extensions["upload_detect"](
                stub, {"url": "http://t.com/", "paths": ["bad path"]})
        with pytest.raises(ValueError):
            await stub.extensions["upload_detect"](
                stub, {"url": "http://t.com/", "paths": [f"/p{i}" for i in range(15)]})

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                if "%{http_code}" in arguments["command"]:
                    if "/custom_upload'" in arguments["command"]:
                        return "200 10"
                    return "404 0"
                return "<html>static</html>\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out4 = await stub2.extensions["upload_detect"](
            stub2, {"url": "http://t.com/", "paths": ["/custom_upload"]})
        assert "/custom_upload" in out4
        monkeypatch.setattr(P.upload_detect, "check_installed", lambda t: False)
        out3 = await stub.extensions["upload_detect"](stub, {"url": "http://t.com/"})
        assert "未安装" in out3


# ---------------------------------------------------------------------------
# js_extract：JS 文件清单提取
# ---------------------------------------------------------------------------
class TestJsExtract:
    def test_extract_scripts(self):
        from kalitui.profiles.js_extract import _extract_scripts

        raw = (
            '<script src="/app.js"></script>\n'
            '<script src="https://cdn.other.com/lib.js"></script>\n'
            '<script src="/app.js"></script>\n'  # 去重
            '<script src="data:text/javascript,x"></script>\n'  # 跳过
            '<script>inline()</script>\n'
        )
        same, external = _extract_scripts(raw, "http://t.com/page")
        assert same == ["http://t.com/app.js"]
        assert external == ["https://cdn.other.com/lib.js"]
        assert _extract_scripts("<html>none</html>", "http://t.com/") == ([], [])

    @pytest.mark.asyncio
    async def test_exec_mixed(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return (
                    '<script src="/assets/app.abc123.js"></script>\n'
                    '<script src="/js/util.js"></script>\n'
                    '<script src="https://cdn.google.com/gtag.js"></script>\n'
                )

        stub = Stub()
        monkeypatch.setattr(P.js_extract, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["js_extract"](stub, {"url": "http://t.com/app"})
        assert "外部 JS（3 个）" in out
        assert "http://t.com/assets/app.abc123.js" in out
        assert "同域 (2)" in out and "外域 (1)" in out
        assert "cdn.google.com" in out

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "".join(
                    f'<script src="https://cdn{i}.x.com/s.js"></script>'
                    for i in range(20)) + "x" * 40000

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out2 = await stub2.extensions["js_extract"](stub2, {"url": "http://t.com/app"})
        assert "共 20 个外域脚本" in out2

    @pytest.mark.asyncio
    async def test_exec_none_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "<html><div>SPA 容器</div></html>\n"

        stub = Stub()
        monkeypatch.setattr(P.js_extract, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["js_extract"](stub, {"url": "http://t.com/app"})
        assert "无外部脚本" in out
        out2 = await stub.extensions["js_extract"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out2
        monkeypatch.setattr(P.js_extract, "check_installed", lambda t: False)
        out3 = await stub.extensions["js_extract"](stub, {"url": "http://t.com/"})
        assert "未安装" in out3


# ---------------------------------------------------------------------------
# plain_login：明文凭据传输检测
# ---------------------------------------------------------------------------
class TestPlainLogin:
    def test_has_pwd_and_actions(self):
        from kalitui.profiles.plain_login import _form_actions, _has_password_input

        assert _has_password_input('<input type="password" name="pw">') is True
        assert _has_password_input("<input type=password>") is True
        assert _has_password_input('<input type="text" name="u">') is False
        raw = ('<form action="/do_login" method="post">'
               '<input type="password"></form>'
               '<form action="http://old.t.com/login"></form>')
        assert _form_actions(raw) == ["/do_login", "http://old.t.com/login"]

    @pytest.mark.asyncio
    async def test_exec_http_plain(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ('<form action="/do_login" method="post">'
                        '<input type="password" name="pw">'
                        '<input type="submit"></form>')

        stub = Stub()
        monkeypatch.setattr(P.plain_login, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["plain_login"](stub, {"url": "http://t.com/login"})
        assert "HTTP 明文页面" in out and "密码明文传输" in out
        assert "/do_login" in out

    @pytest.mark.asyncio
    async def test_exec_https_and_bad_action(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return ('<form action="http://t.com/do_login" method="post">'
                        '<input type="password" name="pw"></form>')

        stub = Stub()
        monkeypatch.setattr(P.plain_login, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["plain_login"](stub, {"url": "https://t.com/login"})
        assert "走 HTTPS" in out
        assert "action 指向 http 明文" in out and "http://t.com/do_login" in out

    @pytest.mark.asyncio
    async def test_exec_no_pwd_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "<html>SPA 容器</html>\n"

        stub = Stub()
        monkeypatch.setattr(P.plain_login, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["plain_login"](stub, {"url": "http://t.com/login"})
        assert "无密码输入框" in out
        out2 = await stub.extensions["plain_login"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out2

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return '<input type="password">' + 'x' * 40000

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out4 = await stub2.extensions["plain_login"](stub2, {"url": "http://t.com/"})
        assert "HTTP 明文页面" in out4  # 超长截断后仍检出密码框
        monkeypatch.setattr(P.plain_login, "check_installed", lambda t: False)
        out3 = await stub.extensions["plain_login"](stub, {"url": "http://t.com/"})
        assert "未安装" in out3


# ---------------------------------------------------------------------------
# param_discover：隐藏参数探测
# ---------------------------------------------------------------------------
class TestParamDiscover:
    @pytest.mark.asyncio
    async def test_exec_hit(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "debug=1'" in cmd:
                    return "ERROR: debug stack trace at /api/search\n" + "x" * 500
                if "callback=1'" in cmd:
                    return "callback(1)({\"data\":\"secret\"})"
                return "OK\n"

        stub = Stub()
        monkeypatch.setattr(P.param_discover, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["param_discover"](
            stub, {"url": "http://t.com/api/search?q=1"})
        assert "参数生效" in out and "debug=1" in out
        assert "callback=1" in out

    @pytest.mark.asyncio
    async def test_exec_none_and_bad(self, monkeypatch):
        from kalitui import profiles as P

        class Stub:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                return "OK\n"

        stub = Stub()
        monkeypatch.setattr(P.param_discover, "check_installed", lambda t: True)
        P.register_extensions(stub)  # type: ignore[arg-type]
        out = await stub.extensions["param_discover"](stub, {"url": "http://t.com/"})
        assert "未发现生效参数" in out
        out2 = await stub.extensions["param_discover"](stub, {"url": "ftp://x"})
        assert "url 格式非法" in out2
        with pytest.raises(ValueError):
            await stub.extensions["param_discover"](
                stub, {"url": "http://t.com/", "params": "x"})
        with pytest.raises(ValueError):
            await stub.extensions["param_discover"](
                stub, {"url": "http://t.com/", "params": ["bad-name"]})
        with pytest.raises(ValueError):
            await stub.extensions["param_discover"](
                stub, {"url": "http://t.com/", "params": [f"p{i}" for i in range(30)]})

        class Stub2:
            danger_policy = "ask"
            extensions = {}

            async def execute(self, name, arguments):
                cmd = arguments["command"]
                if "zzz=1'" in cmd:
                    return "zzz-mode enabled! " + "y" * 300
                return "OK\n"

        stub2 = Stub2()
        P.register_extensions(stub2)  # type: ignore[arg-type]
        out4 = await stub2.extensions["param_discover"](
            stub2, {"url": "http://t.com/", "params": ["zzz"]})
        assert "zzz=1" in out4
        monkeypatch.setattr(P.param_discover, "check_installed", lambda t: False)
        out3 = await stub.extensions["param_discover"](stub, {"url": "http://t.com/"})
        assert "未安装" in out3
