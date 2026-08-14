"""深度定制工具档案测试：命令构造、参数校验、注入防护、摘要、集成。"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kalitui.profiles import (  # noqa: E402
    REGISTRY,
    all_schemas,
    inventory,
    lore_for,
    register_extensions,
)
from kalitui.profiles.base import (  # noqa: E402
    sanitize_int,
    sanitize_ports,
    sanitize_target,
    sanitize_url,
    sanitize_wordlist,
)
from kalitui.profiles.gobuster import _build_cmd as gobuster_cmd  # noqa: E402
from kalitui.profiles.msf import _build_script as msf_script  # noqa: E402
from kalitui.profiles.nikto import _build_cmd as nikto_cmd  # noqa: E402
from kalitui.profiles.nmap import _build_cmd as nmap_cmd, _summarize  # noqa: E402
from kalitui.tools import Executor  # noqa: E402

# ---------------- 参数校验 ----------------

VALID_TARGETS = ["192.168.1.10", "192.168.1.0/24", "scanme.nmap.org", "localhost", "10.0.0.1"]
BAD_TARGETS = ["192.168.1.10; rm -rf /", "x$(whoami)", "http://evil.com", "a b c", "1.2.3.4/33", "192.168.1.10 && reboot"]


@pytest.mark.parametrize("t", VALID_TARGETS)
def test_target_ok(t: str) -> None:
    assert sanitize_target(t) == t


@pytest.mark.parametrize("t", BAD_TARGETS)
def test_target_bad(t: str) -> None:
    with pytest.raises(ValueError):
        sanitize_target(t)


def test_url_and_wordlist() -> None:
    assert sanitize_url("http://192.168.1.10:8080/admin") == "http://192.168.1.10:8080/admin"
    with pytest.raises(ValueError):
        sanitize_url("ftp://x.com")
    with pytest.raises(ValueError):
        sanitize_url("http://x.com;ls")
    assert sanitize_wordlist("/usr/share/wordlists/dirb/common.txt") == "/usr/share/wordlists/dirb/common.txt"
    with pytest.raises(ValueError):
        sanitize_wordlist("/etc/passwd")
    with pytest.raises(ValueError):
        sanitize_wordlist("../../evil.txt")


def test_ports_and_int() -> None:
    assert sanitize_ports("22,80,443") == "22,80,443"
    assert sanitize_ports("1-1000") == "1-1000"
    assert sanitize_ports(None) is None
    with pytest.raises(ValueError):
        sanitize_ports("22;rm")
    with pytest.raises(ValueError):
        sanitize_ports("99999")
    assert sanitize_int(None, 20, 1, 200, "t") == 20
    assert sanitize_int("abc", 20, 1, 200, "t") == 20
    assert sanitize_int(9999, 20, 1, 200, "t") == 200


# ---------------- 命令构造 ----------------

def test_nmap_cmd_modes() -> None:
    assert nmap_cmd({"target": "192.168.1.10"})[0] == "nmap -T4 -F 192.168.1.10"
    assert nmap_cmd({"target": "192.168.1.10", "scan_type": "version"})[0] == "nmap -sV -T4 192.168.1.10"
    assert nmap_cmd({"target": "192.168.1.10", "scan_type": "aggressive"})[0] == "nmap -sV -sC -O -T4 192.168.1.10"
    assert nmap_cmd({"target": "192.168.1.10", "scan_type": "ping"})[0] == "nmap -sn -T4 192.168.1.10"
    assert nmap_cmd({"target": "192.168.1.10", "scan_type": "udp"})[0] == "nmap -sU --top-ports 20 -T4 192.168.1.10"
    assert nmap_cmd({"target": "192.168.1.10", "scan_type": "all"})[0] == "nmap -p- -T4 192.168.1.10"
    assert nmap_cmd({"target": "h.example.com", "ports": "22,80"})[0] == "nmap -p22,80 h.example.com"
    assert nmap_cmd({"target": "h.example.com", "sudo": True})[0].startswith("sudo nmap")
    with pytest.raises(ValueError):
        nmap_cmd({"target": "h.example.com", "scan_type": "stealth"})
    with pytest.raises(ValueError):
        nmap_cmd({"target": "1.2.3.4;whoami"})


def test_msf_script() -> None:
    s = msf_script({"module": "auxiliary/scanner/ssh/ssh_version", "options": {"RHOSTS": "10.0.0.5"}}, search=False)
    assert s == "use auxiliary/scanner/ssh/ssh_version; set RHOSTS 10.0.0.5; run -j; sleep 8"
    s2 = msf_script({"module": "exploit/multi/handler", "action": "check"}, search=False)
    assert s2 == "use exploit/multi/handler; check"
    assert msf_script({"keyword": "vsftpd 2.3.4"}, search=True) == "search vsftpd 2.3.4"
    with pytest.raises(ValueError):
        msf_script({"module": "exploit/../../etc"}, search=False)
    with pytest.raises(ValueError):
        msf_script({"keyword": "x;rm -rf /"}, search=True)
    with pytest.raises(ValueError):
        msf_script({"module": "a/b", "options": {"RHOSTS": "1.2.3.4;ls"}}, search=False)
    with pytest.raises(ValueError):
        msf_script({"module": "a/b", "action": "rm"}, search=False)


def test_nikto_and_gobuster_cmd() -> None:
    assert nikto_cmd({"target": "http://10.0.0.5"})[0] == "nikto -h http://10.0.0.5"
    assert nikto_cmd({"target": "https://x.com:8443", "tuning": "x"})[0] == "nikto -h https://x.com:8443 -Tuning x"
    with pytest.raises(ValueError):
        nikto_cmd({"target": "http://x.com;ls"})

    cmd, _ = gobuster_cmd({"url": "http://10.0.0.5"})
    assert cmd.startswith("gobuster dir -u http://10.0.0.5 -w /usr/share/wordlists/dirbuster/")
    cmd2, _ = gobuster_cmd({"url": "http://10.0.0.5", "extensions": "php,bak", "status_codes": "200,301", "threads": 50})
    assert "-x php,bak" in cmd2 and "-s 200,301" in cmd2 and "-t 50" in cmd2
    with pytest.raises(ValueError):
        gobuster_cmd({"url": "http://x.com", "extensions": "php;ls"})
    with pytest.raises(ValueError):
        gobuster_cmd({"url": "http://x.com", "wordlist": "/etc/shadow"})


# ---------------- 摘要 ----------------

def test_nmap_summarize() -> None:
    raw = """Starting Nmap 7.98
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0000020s latency).
Not shown: 99 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds"""
    s = _summarize(raw)
    assert "开放端口 (2)" in s
    assert "22/tcp   open  ssh" in s
    assert "存活主机: 1" in s
    assert "下一步建议" in s


# ---------------- registry / 动态 lore ----------------

def test_registry_inventory() -> None:
    names = [s["function"]["name"] for s in all_schemas()]
    assert "nmap_scan" in names and "msf_run" in names and "nikto_scan" in names and "dir_brute" in names
    assert "nmap" in inventory() and "gobuster" in inventory()
    assert len(REGISTRY) >= 4


def test_lore_matching() -> None:
    assert "nmap" in lore_for([{"role": "user", "content": "帮我扫描 192.168.1.0/24"}])
    assert "Metasploit" in lore_for([{"role": "user", "content": "用 msfconsole 搜个 exploit"}])
    assert "gobuster" in lore_for([{"role": "tool", "content": "dir_brute 的结果"}])
    assert lore_for([{"role": "user", "content": "今天天气不错"}]) == ""


# ---------------- 集成：stub executor 验证命令流转 ----------------

class StubEx:
    """记录传给 run_command 的命令。"""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.danger_policy = "ask"
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        self.calls.append((name, arguments))
        return "STUB-OUTPUT\n22/tcp open ssh"


@pytest.mark.asyncio
async def test_profile_executors_route_to_run_command() -> None:
    from kalitui.tools import ToolError

    stub = StubEx()
    register_extensions(stub)  # type: ignore[arg-type]

    out = await stub.extensions["nmap_scan"](stub, {"target": "127.0.0.1", "scan_type": "quick"})
    assert "STUB-OUTPUT" in out
    name, args = stub.calls[-1]
    assert name == "run_command"
    assert "nmap -T4 -F 127.0.0.1" in args["command"]

    await stub.extensions["msf_search"](stub, {"keyword": "vsftpd"})
    assert "msfconsole -q -x" in stub.calls[-1][1]["command"]

    await stub.extensions["nikto_scan"](stub, {"target": "http://127.0.0.1"})
    assert "nikto -h http://127.0.0.1" in stub.calls[-1][1]["command"]

    await stub.extensions["dir_brute"](stub, {"url": "http://127.0.0.1"})
    assert "gobuster dir -u http://127.0.0.1" in stub.calls[-1][1]["command"]

    # 注入字符必须被拒（参数校验层直接拒绝）
    with pytest.raises(ValueError):
        await stub.extensions["nmap_scan"](stub, {"target": "1.2.3.4;rm -rf /"})


# ---------------- 集成：真实 nmap 冒烟（本机快速扫描） ----------------

@pytest.mark.asyncio
async def test_nmap_scan_real_localhost() -> None:
    from kalitui.profiles.nmap import NmapProfile

    ex = Executor()
    NmapProfile().register(ex)

    out = await ex.execute("nmap_scan", {"target": "127.0.0.1", "scan_type": "quick"})
    assert "原始输出" in out  # 摘要格式
    assert "存活主机" in out or "开放端口" in out or "未发现开放端口" in out
