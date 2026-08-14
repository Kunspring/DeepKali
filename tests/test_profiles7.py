"""第七批深度定制档案测试：impexec / wfuzz / netdiscover / airmon / macchanger。"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kalitui.profiles import REGISTRY, all_schemas, lore_for, register_extensions  # noqa: E402
from kalitui.profiles.airmon import _build_cmd as airmon_cmd  # noqa: E402
from kalitui.profiles.impexec import _build_cmd as impexec_cmd  # noqa: E402
from kalitui.profiles.macchanger import _build_cmd as mac_cmd  # noqa: E402
from kalitui.profiles.netdiscover import _build_cmd as netdisc_cmd  # noqa: E402
from kalitui.profiles.wfuzz import _build_cmd as wfuzz_cmd  # noqa: E402
from kalitui.safety import classify  # noqa: E402

# ---------------- 命令构造与校验 ----------------


def test_impexec_cmd() -> None:
    cmd, _ = impexec_cmd({"host": "10.0.0.10", "username": "admin", "password": "P@ss"})
    assert "impacket-smbexec" in cmd and "admin:P@ss@10.0.0.10" in cmd and " whoami" in cmd
    cmd2, _ = impexec_cmd({"host": "10.0.0.10", "username": "admin", "hash": "a" * 32, "mode": "wmiexec", "command": "ipconfig", "domain": "CORP"})
    assert "impacket-wmiexec" in cmd2 and "-hashes :" + "a" * 32 in cmd2 and "CORP\\admin@10.0.0.10" in cmd2 and " ipconfig" in cmd2
    cmd3, _ = impexec_cmd({"host": "10.0.0.10", "username": "admin", "password": "x", "mode": "atexec"})
    assert "impacket-atexec" in cmd3
    with pytest.raises(ValueError):
        impexec_cmd({"host": "10.0.0.10", "username": "admin"})
    with pytest.raises(ValueError):
        impexec_cmd({"host": "10.0.0.10", "username": "admin", "password": "x", "command": "whoami;id"})
    with pytest.raises(ValueError):
        impexec_cmd({"host": "10.0.0.10", "username": "admin", "password": "x", "mode": "psh"})
    assert classify(cmd).level == "confirm"


def test_wfuzz_cmd() -> None:
    cmd, _ = wfuzz_cmd({"url": "http://10.0.0.5/FUZZ"})
    assert cmd == "wfuzz -w /usr/share/wordlists/dirb/common.txt -t 20 http://10.0.0.5/FUZZ"
    cmd2, _ = wfuzz_cmd({"url": "http://x.com/FUZZ", "match_codes": "200,301", "threads": 50, "cookie": "session=abc"})
    assert "-b session=abc" in cmd2 and "-t 50" in cmd2
    cmd3, _ = wfuzz_cmd({"url": "http://x.com/FUZZ", "hide_codes": "404,403"})
    assert "http://x.com/FUZZ" in cmd3
    with pytest.raises(ValueError):
        wfuzz_cmd({"url": "http://x.com"})
    with pytest.raises(ValueError):
        wfuzz_cmd({"url": "http://x.com/FUZZ;ls"})
    with pytest.raises(ValueError):
        wfuzz_cmd({"url": "http://x.com/FUZZ", "match_codes": "200", "hide_codes": "404"})
    # cookie 含 ; 是合法语法（多 cookie 分隔），用 shell 引用防注入
    safe = wfuzz_cmd({"url": "http://x.com/FUZZ", "cookie": "x;rm"})
    assert "-b 'x;rm'" in safe[0]


def test_netdiscover_cmd() -> None:
    cmd, timeout = netdisc_cmd({})
    assert cmd == "timeout 15 netdiscover"
    assert timeout > 15
    cmd2, _ = netdisc_cmd({"range": "192.168.1.0/24", "interface": "eth0", "mode": "passive", "seconds": 60})
    assert "timeout 60 netdiscover -i eth0 -p -r 192.168.1.0/24" in cmd2
    with pytest.raises(ValueError):
        netdisc_cmd({"range": "192.168.1.0/33"})
    with pytest.raises(ValueError):
        netdisc_cmd({"interface": "eth0;ls"})


def test_airmon_cmd() -> None:
    cmd, _ = airmon_cmd({"action": "status"})
    assert cmd == "airmon-ng"
    cmd2, _ = airmon_cmd({"action": "start", "interface": "wlan0"})
    assert cmd2 == "airmon-ng start wlan0"
    cmd3, _ = airmon_cmd({"action": "stop", "interface": "wlan0"})
    assert cmd3 == "airmon-ng stop wlan0"
    with pytest.raises(ValueError):
        airmon_cmd({"action": "start"})
    with pytest.raises(ValueError):
        airmon_cmd({"action": "fly"})
    assert classify(cmd2).level == "confirm"


def test_mac_cmd() -> None:
    cmd, _ = mac_cmd({"interface": "wlan0", "action": "show"})
    assert cmd == "macchanger -s wlan0"
    cmd2, _ = mac_cmd({"interface": "wlan0", "action": "set", "mac": "00:11:22:33:44:55"})
    assert cmd2 == "macchanger -m 00:11:22:33:44:55 wlan0"
    cmd3, _ = mac_cmd({"interface": "wlan0", "action": "random"})
    assert cmd3 == "macchanger -r wlan0"
    with pytest.raises(ValueError):
        mac_cmd({"interface": "wlan0", "action": "set", "mac": "not-a-mac"})
    with pytest.raises(ValueError):
        mac_cmd({"interface": "wlan0;ls", "action": "show"})
    assert classify(cmd2).level == "confirm"


# ---------------- registry / lore ----------------


def test_registry_seventh_batch() -> None:
    names = [s["function"]["name"] for s in all_schemas()]
    for t in ("imp_exec", "wfuzz_fuzz", "net_discover", "wifi_monitor", "mac_change"):
        assert t in names
    pnames = [p.name for p in REGISTRY]
    for n in ("impexec", "wfuzz", "netdiscover", "airmon-ng", "macchanger"):
        assert n in pnames
    assert len(REGISTRY) >= 34


def test_lore_seventh_batch() -> None:
    assert "impexec" in lore_for([{"role": "user", "content": "用 smbexec 在目标机上执行 ipconfig"}])
    assert "wfuzz" in lore_for([{"role": "user", "content": "对这个站做字典爆破"}])
    assert "netdiscover" in lore_for([{"role": "user", "content": "扫一下内网有哪些存活主机"}])
    assert "airmon" in lore_for([{"role": "user", "content": "把网卡切到监控模式"}])
    assert "macchanger" in lore_for([{"role": "user", "content": "改一下 mac 地址匿名化"}])
