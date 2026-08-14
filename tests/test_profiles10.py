"""第十批（收官）测试：playbook 联动流水线。"""

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
