"""第六批深度定制档案测试：GetNPUsers / GetUserSPNs / socat / tshark / hping3。"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from DeepKali.profiles import REGISTRY, all_schemas, lore_for, register_extensions  # noqa: E402
from DeepKali.profiles.getnpusers import _build_cmd as npusers_cmd  # noqa: E402
from DeepKali.profiles.getuserspns import _build_cmd as userspns_cmd  # noqa: E402
from DeepKali.profiles.hping3 import _build_cmd as hping_cmd  # noqa: E402
from DeepKali.profiles.socat import _build_cmd as socat_cmd  # noqa: E402
from DeepKali.profiles.tshark import _build_cmd as tshark_cmd  # noqa: E402
from DeepKali.safety import classify  # noqa: E402

# ---------------- 命令构造与校验 ----------------


def test_npusers_cmd() -> None:
    cmd, _ = npusers_cmd({"domain": "corp.local"})
    assert "impacket-GetNPUsers" in cmd or "GetNPUsers" in cmd
    assert "corp.local/" in cmd and "-format hashcat" in cmd
    cmd2, _ = npusers_cmd({"domain": "corp.local", "dc": "10.0.0.5", "username": "svc", "password": "p1", "users": "/tmp/users.txt"})
    assert "-dc-ip 10.0.0.5" in cmd2 and "corp.local/svc:p1" in cmd2 and "-usersfile /tmp/users.txt" in cmd2
    with pytest.raises(ValueError):
        npusers_cmd({"domain": "corp.local;id"})
    with pytest.raises(ValueError):
        npusers_cmd({"domain": "corp.local", "users": "/etc/passwd;ls"})
    assert classify(cmd).level == "confirm"


def test_userspns_cmd() -> None:
    cmd, _ = userspns_cmd({"domain": "corp.local", "username": "alice", "password": "P@ss"})
    assert "impacket-GetUserSPNs" in cmd or "GetUserSPNs" in cmd
    assert "-request corp.local/alice:P@ss" in cmd and "-format hashcat" in cmd
    cmd2, _ = userspns_cmd({"domain": "corp.local", "username": "alice", "password": "P@ss", "dc": "10.0.0.5", "spns": "MSSQLSvc/db.corp.local:1433"})
    assert "-dc-ip 10.0.0.5" in cmd2 and "-spn MSSQLSvc/db.corp.local:1433" in cmd2
    with pytest.raises(ValueError):
        userspns_cmd({"domain": "corp.local", "username": "a b", "password": "x"})
    with pytest.raises(ValueError):
        userspns_cmd({"domain": "corp.local;ls", "username": "a", "password": "x"})
    assert classify(cmd).level == "confirm"


def test_socat_cmd() -> None:
    cmd, timeout = socat_cmd({"listen_port": 8081, "target_host": "10.0.0.5", "target_port": 3389})
    assert cmd == "timeout 30 socat TCP-LISTEN:8081,reuseaddr,fork TCP:10.0.0.5:3389"
    assert timeout > 30
    with pytest.raises(ValueError):
        socat_cmd({"listen_port": 8081, "target_host": "10.0.0.5;ls", "target_port": 3389})
    with pytest.raises(ValueError):
        socat_cmd({"listen_port": 99999, "target_host": "10.0.0.5", "target_port": 3389})
    assert classify(cmd).level == "confirm"


def test_tshark_cmd() -> None:
    cmd, timeout = tshark_cmd({})
    assert "timeout 15 tshark -i any" in cmd
    assert "-c 200" in cmd and "-e _ws.col.Protocol" in cmd
    cmd2, _ = tshark_cmd({"interface": "wlan0", "filter": "tcp port 80", "display": "http.request", "seconds": 5, "count": 50})
    assert "-i wlan0" in cmd2 and "-f 'tcp port 80'" in cmd2 and '-Y http.request' in cmd2 and "-c 50" in cmd2
    with pytest.raises(ValueError):
        tshark_cmd({"filter": "tcp port 80;rm -rf /"})
    with pytest.raises(ValueError):
        tshark_cmd({"display": "http.request;id"})


def test_hping_cmd() -> None:
    cmd, _ = hping_cmd({"host": "10.0.0.5", "mode": "syn", "port": 80})
    assert cmd == "hping3 -S -p 80 -c 3 10.0.0.5"
    cmd2, _ = hping_cmd({"host": "10.0.0.5", "mode": "ack", "port": 443, "count": 5})
    assert cmd2 == "hping3 -A -p 443 -c 5 10.0.0.5"
    cmd3, _ = hping_cmd({"host": "10.0.0.5", "mode": "icmp", "port": 0})
    assert cmd3 == "hping3 -1 -c 3 10.0.0.5"
    with pytest.raises(ValueError):
        hping_cmd({"host": "10.0.0.5;ls", "mode": "syn", "port": 80})
    with pytest.raises(ValueError):
        hping_cmd({"host": "10.0.0.5", "mode": "flood", "port": 80})


# ---------------- registry / lore ----------------


def test_registry_sixth_batch() -> None:
    names = [s["function"]["name"] for s in all_schemas()]
    for t in ("asrep_roast", "kerberoast", "socat_tunnel", "tshark_capture", "hping_probe"):
        assert t in names
    pnames = [p.name for p in REGISTRY]
    for n in ("getnpusers", "getuserspns", "socat", "tshark", "hping3"):
        assert n in pnames
    assert len(REGISTRY) >= 29


def test_lore_sixth_batch() -> None:
    assert "getnpusers" in lore_for([{"role": "user", "content": "对域做 asrep 预认证枚举"}])
    assert "getuserspns" in lore_for([{"role": "user", "content": "做一下 kerberoast"}])
    assert "socat" in lore_for([{"role": "user", "content": "把内网 3389 端口转发出来"}])
    assert "tshark" in lore_for([{"role": "user", "content": "用 wireshark 命令行抓包看 http 请求"}])
    assert "hping3" in lore_for([{"role": "user", "content": "测试防火墙对 syn 包的反应"}])
