"""第三批深度定制档案测试：enum4linux / smbmap / dnsrecon / ffuf / aircrack。"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from DeepKali.profiles import REGISTRY, all_schemas, lore_for, register_extensions  # noqa: E402
from DeepKali.profiles.aircrack import _build_cmd as aircrack_cmd  # noqa: E402
from DeepKali.profiles.dnsrecon import _build_cmd as dnsrecon_cmd  # noqa: E402
from DeepKali.profiles.enum4linux import _build_cmd as enum_cmd  # noqa: E402
from DeepKali.profiles.ffuf import _build_cmd as ffuf_cmd  # noqa: E402
from DeepKali.profiles.smbmap import _build_cmd as smbmap_cmd  # noqa: E402
from DeepKali.safety import classify  # noqa: E402

# ---------------- 命令构造与校验 ----------------


def test_enum4linux_cmd() -> None:
    assert enum_cmd({"target": "192.168.1.10"})[0] == "enum4linux -a 192.168.1.10"
    assert enum_cmd({"target": "10.0.0.5", "mode": "users"})[0] == "enum4linux -U 10.0.0.5"
    assert enum_cmd({"target": "10.0.0.5", "mode": "shares"})[0] == "enum4linux -S 10.0.0.5"
    assert enum_cmd({"target": "10.0.0.5", "mode": "groups"})[0] == "enum4linux -G 10.0.0.5"
    assert enum_cmd({"target": "10.0.0.5", "mode": "policy"})[0] == "enum4linux -P 10.0.0.5"
    with pytest.raises(ValueError):
        enum_cmd({"target": "1.2.3.4;ls", "mode": "all"})
    with pytest.raises(ValueError):
        enum_cmd({"target": "1.2.3.4", "mode": "everything"})


def test_smbmap_cmd() -> None:
    assert smbmap_cmd({"target": "192.168.1.10"})[0] == "smbmap -H 192.168.1.10"
    cmd, _ = smbmap_cmd({"target": "10.0.0.5", "username": "admin", "password": "pass1", "domain": "corp", "share": "C$", "recursive": True})
    assert cmd == "smbmap -H 10.0.0.5 -u admin -p pass1 -d corp -s C$ -R"
    with pytest.raises(ValueError):
        smbmap_cmd({"target": "10.0.0.5", "username": "a b"})
    with pytest.raises(ValueError):
        smbmap_cmd({"target": "10.0.0.5", "password": "x;ls"})


def test_dnsrecon_cmd() -> None:
    assert dnsrecon_cmd({"target": "example.com"})[0] == "dnsrecon -d example.com -t std"
    cmd, _ = dnsrecon_cmd({"target": "example.com", "mode": "brt"})
    assert cmd == (
        "dnsrecon -d example.com -t brt -D /usr/share/wordlists/dnsrecon/subdomains-top1million-20000.txt"
    )
    cmd2, _ = dnsrecon_cmd({"target": "example.com", "mode": "axfr", "server": "8.8.8.8"})
    assert cmd2 == "dnsrecon -d example.com -t axfr -n 8.8.8.8"
    with pytest.raises(ValueError):
        dnsrecon_cmd({"target": "example.com;id"})
    with pytest.raises(ValueError):
        dnsrecon_cmd({"target": "example.com", "mode": "brt", "wordlist": "/etc/passwd"})


def test_ffuf_cmd() -> None:
    cmd, timeout = ffuf_cmd({"url": "http://10.0.0.5/FUZZ"})
    assert cmd.startswith("ffuf -u http://10.0.0.5/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 40")
    assert "-mc 200,204,301,302,307,401,403,405,500" in cmd
    assert "-s" in cmd
    assert timeout > 120

    cmd2, _ = ffuf_cmd({"url": "http://x.com/api/FUZZ", "extensions": "php,bak", "match_codes": "200,301", "threads": 100, "max_time": 60})
    assert "-x php,bak" in cmd2 and "-mc 200,301" in cmd2 and "-t 100" in cmd2 and "-maxtime 60" in cmd2

    with pytest.raises(ValueError):
        ffuf_cmd({"url": "http://x.com"})  # 缺 FUZZ
    with pytest.raises(ValueError):
        ffuf_cmd({"url": "http://x.com/FUZZ;ls"})
    with pytest.raises(ValueError):
        ffuf_cmd({"url": "http://x.com/FUZZ", "extensions": "php;ls"})


def test_aircrack_cmd(tmp_path: Path) -> None:
    cap = tmp_path / "handshake.cap"
    cap.write_bytes(b"\x00\x01")
    cmd, _ = aircrack_cmd({"capture": str(cap)})
    assert cmd == f"aircrack-ng -w /usr/share/wordlists/rockyou.txt {cap}"
    cmd2, _ = aircrack_cmd({"capture": str(cap), "bssid": "AA:BB:CC:DD:EE:FF"})
    assert "-b AA:BB:CC:DD:EE:FF" in cmd2

    with pytest.raises(ValueError):
        aircrack_cmd({"capture": str(tmp_path / "nope.cap")})  # 文件不存在
    with pytest.raises(ValueError):
        aircrack_cmd({"capture": str(cap), "bssid": "not-a-mac"})
    with pytest.raises(ValueError):
        aircrack_cmd({"capture": "../evil.cap"})

    # 危险等级：aircrack 必须 confirm
    assert classify(cmd).level == "confirm"


# ---------------- registry / lore ----------------


def test_registry_third_batch() -> None:
    names = [s["function"]["name"] for s in all_schemas()]
    for t in ("smb_enum", "smb_map", "dns_recon", "ffuf_dir", "wifi_crack"):
        assert t in names
    pnames = [p.name for p in REGISTRY]
    for n in ("enum4linux", "smbmap", "dnsrecon", "ffuf", "aircrack"):
        assert n in pnames
    assert len(REGISTRY) >= 14


def test_lore_third_batch() -> None:
    assert "enum4linux" in lore_for([{"role": "user", "content": "对 445 端口做 smb 枚举"}])
    assert "smbmap" in lore_for([{"role": "user", "content": "看看这个主机的 smb 共享里有什么"}])
    assert "dnsrecon" in lore_for([{"role": "user", "content": "对 example.com 做 dns 侦察和子域爆破"}])
    assert "ffuf" in lore_for([{"role": "user", "content": "对这个网站做模糊测试 fuzz"}])
    assert "aircrack" in lore_for([{"role": "user", "content": "破解这个 wifi 握手包"}])


# ---------------- stub 流转 ----------------


class StubEx3:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.danger_policy = "ask"
        self.extensions: dict = {}

    async def execute(self, name: str, arguments: dict) -> str:
        self.calls.append((name, arguments))
        return "STUB-OUTPUT\n[+] 10.0.0.5 admin (Local User)"


@pytest.mark.asyncio
async def test_third_batch_route_to_run_command() -> None:
    stub = StubEx3()
    register_extensions(stub)  # type: ignore[arg-type]

    await stub.extensions["smb_enum"](stub, {"target": "10.0.0.5"})
    assert "enum4linux -a 10.0.0.5" in stub.calls[-1][1]["command"]

    await stub.extensions["smb_map"](stub, {"target": "10.0.0.5"})
    assert "smbmap -H 10.0.0.5" in stub.calls[-1][1]["command"]

    await stub.extensions["dns_recon"](stub, {"target": "example.com"})
    assert "dnsrecon -d example.com -t std" in stub.calls[-1][1]["command"]

    await stub.extensions["ffuf_dir"](stub, {"url": "http://10.0.0.5/FUZZ"})
    assert "ffuf -u http://10.0.0.5/FUZZ" in stub.calls[-1][1]["command"]
