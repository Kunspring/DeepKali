"""第二批深度定制档案测试：searchsploit / hydra / sqlmap / crack / wpscan。"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from DeepKali.profiles import REGISTRY, all_schemas, lore_for  # noqa: E402
from DeepKali.profiles.crack import _check_hash  # noqa: E402
from DeepKali.profiles.hydra import _build_cmd as hydra_cmd  # noqa: E402
from DeepKali.profiles.searchsploit import SploitProfile  # noqa: E402
from DeepKali.profiles.sqlmap import _build_cmd as sqlmap_cmd  # noqa: E402
from DeepKali.profiles.wpscan import _build_cmd as wpscan_cmd  # noqa: E402

# ---------------- 命令构造与校验 ----------------


def test_hydra_cmd() -> None:
    cmd, timeout = hydra_cmd(
        {
            "protocol": "ssh",
            "target": "192.168.1.10",
            "username": "root",
            "passlist": "/usr/share/wordlists/rockyou.txt",
            "threads": 8,
        }
    )
    assert cmd == "hydra -l root -P /usr/share/wordlists/rockyou.txt -t 8 -f ssh://192.168.1.10"
    assert timeout == 600

    cmd2, _ = hydra_cmd(
        {
            "protocol": "http-post-form",
            "target": "10.0.0.5",
            "userlist": "/usr/share/wordlists/dirb/common.txt",
            "password": "pass123",
            "port": 8080,
            "service_options": "login=^USER^&pass=^PASS^:F=incorrect",
        }
    )
    assert cmd2 == (
        "hydra -L /usr/share/wordlists/dirb/common.txt -p pass123 -t 16 -f "
        "-s 8080 -m 'login=^USER^&pass=^PASS^:F=incorrect' http-post-form://10.0.0.5"
    )

    with pytest.raises(ValueError):
        hydra_cmd({"protocol": "ssh", "target": "1.2.3.4", "username": "root"})  # 无密码
    with pytest.raises(ValueError):
        hydra_cmd({"protocol": "ssh", "target": "1.2.3.4", "password": "x"})  # 无用户名
    with pytest.raises(ValueError):
        hydra_cmd({"protocol": "ldap", "target": "1.2.3.4", "username": "a", "password": "b"})
    with pytest.raises(ValueError):
        hydra_cmd({"protocol": "ssh", "target": "1.2.3.4;id", "username": "a", "password": "b"})
    with pytest.raises(ValueError):
        hydra_cmd({"protocol": "ssh", "target": "1.2.3.4", "username": "a", "password": "b;c"})


def test_sqlmap_cmd() -> None:
    cmd, _ = sqlmap_cmd({"url": "http://10.0.0.5/page.php?id=1"})
    assert cmd.startswith("sqlmap -u 'http://10.0.0.5/page.php?id=1' --batch --flush-session --random-agent")
    assert "--smart" in cmd

    cmd2, _ = sqlmap_cmd({"url": "http://x.com/login", "data": "user=a&pass=b", "level": 3, "risk": 2, "cookie": "sid=abc123"})
    assert "--data user=a&pass=b" in cmd2
    assert "--level 3" in cmd2 and "--risk 2" in cmd2
    assert "--cookie sid=abc123" in cmd2

    with pytest.raises(ValueError):
        sqlmap_cmd({"url": "http://x.com;rm"})
    with pytest.raises(ValueError):
        sqlmap_cmd({"url": "http://x.com", "data": "a=b;rm -rf /"})


def test_wpscan_cmd() -> None:
    cmd, _ = wpscan_cmd({"url": "http://10.0.0.5/wp"})
    assert cmd == "wpscan --url http://10.0.0.5/wp --no-banner --random-user-agent --enumerate v"
    cmd2, _ = wpscan_cmd({"url": "http://x.com", "enumerate": "users"})
    assert "--enumerate u" in cmd2
    cmd3, _ = wpscan_cmd({"url": "http://x.com", "enumerate": "all", "api_token": "tok12345678"})
    assert "--enumerate vtub" in cmd3 and "--api-token tok12345678" in cmd3
    with pytest.raises(ValueError):
        wpscan_cmd({"url": "http://x.com", "enumerate": "everything"})
    with pytest.raises(ValueError):
        wpscan_cmd({"url": "http://x.com", "api_token": "bad token!"})


def test_crack_hash_check() -> None:
    assert _check_hash("5f4dcc3b5aa765d61d8327deb882cf99") == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert _check_hash("$6$rounds=656000$abc$xyz") == "$6$rounds=656000$abc$xyz"
    with pytest.raises(ValueError):
        _check_hash("abc;rm -rf /")
    with pytest.raises(ValueError):
        _check_hash("")


def test_sploit_show_id() -> None:
    import re

    # ExploitDB ID 只能是纯数字
    assert re.fullmatch(r"\d{1,7}", "49757")
    assert not re.fullmatch(r"\d{1,7}", "49757;ls")


# ---------------- registry ----------------


def test_registry_contains_second_batch() -> None:
    names = [s["function"]["name"] for s in all_schemas()]
    for t in ("sploit_search", "sploit_show", "hydra_brute", "sqlmap_check", "crack_hash", "wpscan_scan"):
        assert t in names
    profile_names = [p.name for p in REGISTRY]
    for n in ("searchsploit", "hydra", "sqlmap", "crack", "wpscan"):
        assert n in profile_names


def test_lore_second_batch() -> None:
    assert "searchsploit" in lore_for([{"role": "user", "content": "用 exploitdb 搜一下 vsftpd 的 exp"}])
    assert "hydra" in lore_for([{"role": "user", "content": "对 ssh 做弱口令爆破"}])
    assert "sqlmap" in lore_for([{"role": "user", "content": "检测这个页面的 sql 注入 http://x/?id=1"}])
    assert "hashcat" in lore_for([{"role": "user", "content": "帮我破解这个 md5 hash"}])
    assert "wpscan" in lore_for([{"role": "user", "content": "扫描 wordpress 站点的漏洞"}])


# ---------------- stub 集成：命令流转 ----------------


class StubEx2:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.danger_policy = "ask"
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        self.calls.append((name, arguments))
        if name == "run_command" and "hashcat" in arguments["command"]:
            return "5f4dcc3b5aa765d61d8327deb882cf99:password123"
        return "STUB-OUTPUT\n[22][ssh] host: 1.2.3.4 login: root password: toor"


@pytest.mark.asyncio
async def test_second_batch_route_to_run_command() -> None:
    from DeepKali.profiles import register_extensions

    stub = StubEx2()
    register_extensions(stub)  # type: ignore[arg-type]

    await stub.extensions["sploit_search"](stub, {"keyword": "vsftpd 2.3.4"})
    assert "searchsploit vsftpd 2.3.4" in stub.calls[-1][1]["command"]

    await stub.extensions["sploit_show"](stub, {"exploit_id": "49757", "preview": True})
    assert "searchsploit -x 49757" in stub.calls[-1][1]["command"]

    await stub.extensions["hydra_brute"](
        stub, {"protocol": "ssh", "target": "1.2.3.4", "username": "root", "passlist": "/usr/share/wordlists/rockyou.txt"}
    )
    assert "hydra -l root" in stub.calls[-1][1]["command"]

    await stub.extensions["sqlmap_check"](stub, {"url": "http://x.com/?id=1"})
    assert "sqlmap -u 'http://x.com/?id=1'" in stub.calls[-1][1]["command"]

    await stub.extensions["wpscan_scan"](stub, {"url": "http://x.com"})
    assert "wpscan --url http://x.com" in stub.calls[-1][1]["command"]

    # hydra 命中摘要
    out = await stub.extensions["hydra_brute"](
        stub, {"protocol": "ssh", "target": "1.2.3.4", "username": "root", "passlist": "/usr/share/wordlists/rockyou.txt"}
    )
    assert "爆破命中" in out

    # crack_hash：hash 写临时文件后调用
    await stub.extensions["crack_hash"](stub, {"hash": "5f4dcc3b5aa765d61d8327deb882cf99", "hash_type": "md5"})
    name, args = stub.calls[-1]
    assert name == "run_command"
    assert "hashcat -m 0" in args["command"]
    assert "/tmp" in args["command"] or "DeepKali-crack" in args["command"]
    # 危险命令自动过安全层 → confirm 级
    from DeepKali.safety import classify

    assert classify(args["command"]).level in ("confirm", "blocked")


# ---------------- 真实冒烟：searchsploit（本机已装，纯本地查询） ----------------


@pytest.mark.asyncio
async def test_sploit_search_real() -> None:
    from DeepKali.tools import Executor

    ex = Executor()
    SploitProfile().register(ex)
    out = await ex.execute("sploit_search", {"keyword": "vsftpd 2.3.4"})
    assert "vsftpd" in out.lower() or "无匹配" in out
