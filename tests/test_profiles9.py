"""第九批深度定制档案测试：theHarvester / testssl / smtpenum / hashid / cewl。"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kalitui.profiles import REGISTRY, all_schemas, lore_for, register_extensions  # noqa: E402
from kalitui.profiles.cewl import _build_cmd as cewl_cmd  # noqa: E402
from kalitui.profiles.hashid import _build_cmd as hashid_cmd  # noqa: E402
from kalitui.profiles.smtpenum import _build_cmd as smtpenum_cmd  # noqa: E402
from kalitui.profiles.testssl import _bin, _build_cmd as tssl_cmd  # noqa: E402
from kalitui.profiles.theharvester import _build_cmd as harvest_cmd  # noqa: E402
from kalitui.safety import classify  # noqa: E402

# ---------------- 命令构造与校验 ----------------


def test_harvest_cmd() -> None:
    cmd, _ = harvest_cmd({"domain": "example.com"})
    assert cmd == "theHarvester -d example.com -b crtsh -l 100"
    cmd2, _ = harvest_cmd({"domain": "corp.local", "source": "bing", "limit": 50})
    assert "corp.local" in cmd2 and "-b bing" in cmd2 and "-l 50" in cmd2
    with pytest.raises(ValueError):
        harvest_cmd({"domain": "x.com;ls"})
    with pytest.raises(ValueError):
        harvest_cmd({"domain": "x.com", "source": "darkweb"})
    with pytest.raises(ValueError):
        harvest_cmd({"domain": "x.com", "limit": 5})


def test_testssl_cmd() -> None:
    cmd, timeout = tssl_cmd({"host": "example.com"})
    assert cmd == "testssl --quiet --color 0 --fast example.com"
    assert timeout <= 300
    cmd2, _ = tssl_cmd({"host": "x.com:8443", "quick": False})
    assert "x.com:8443" in cmd2 and "--fast" not in cmd2
    cmd3, _ = tssl_cmd({"host": "x.com", "protocols": True})
    assert "-p" in cmd3
    with pytest.raises(ValueError):
        tssl_cmd({"host": "x.com;id"})


def test_smtpenum_cmd() -> None:
    cmd, _ = smtpenum_cmd({"host": "10.0.0.5"})
    assert cmd == "smtp-user-enum -M RCPT -U /usr/share/smtp-user-enum/users.txt -t 10.0.0.5 -p 25"
    cmd2, _ = smtpenum_cmd({"host": "10.0.0.5", "mode": "vrfy", "domain": "corp.local", "users": "/tmp/users.txt", "port": 2525})
    assert "-M VRFY" in cmd2 and "-d corp.local" in cmd2 and "-U /tmp/users.txt" in cmd2 and "-p 2525" in cmd2
    with pytest.raises(ValueError):
        smtpenum_cmd({"host": "10.0.0.5;ls"})
    with pytest.raises(ValueError):
        smtpenum_cmd({"host": "10.0.0.5", "mode": "mail"})
    with pytest.raises(ValueError):
        smtpenum_cmd({"host": "10.0.0.5", "users": "/etc/passwd;x"})
    assert classify(cmd).level == "confirm"


def test_hashid_cmd() -> None:
    cmd, _ = hashid_cmd({"hash": "5f4dcc3b5aa765d61d8327deb882cf99"})
    assert cmd == "hashid -m 5f4dcc3b5aa765d61d8327deb882cf99"
    cmd2, _ = hashid_cmd({"hash": "$6$salt$hash", "john": True})
    assert "-j" in cmd2
    with pytest.raises(ValueError):
        hashid_cmd({"hash": "abc;rm -rf /"})
    with pytest.raises(ValueError):
        hashid_cmd({"hash": "x" * 300})


def test_cewl_cmd() -> None:
    cmd, _ = cewl_cmd({"url": "http://target.com"})
    assert cmd == "cewl http://target.com -d 2 -m 4 -w /tmp/cewl-words.txt"
    cmd2, _ = cewl_cmd({"url": "https://x.com", "depth": 3, "min_length": 6, "output": "/tmp/w.txt", "email": True})
    assert "-d 3" in cmd2 and "-m 6" in cmd2 and "-w /tmp/w.txt" in cmd2 and "-e" in cmd2
    with pytest.raises(ValueError):
        cewl_cmd({"url": "ftp://x.com"})
    with pytest.raises(ValueError):
        cewl_cmd({"url": "http://x.com/;ls"})
    with pytest.raises(ValueError):
        cewl_cmd({"url": "http://x.com", "output": "/etc/passwd"})


# ---------------- registry / lore ----------------


def test_registry_ninth_batch() -> None:
    names = [s["function"]["name"] for s in all_schemas()]
    for t in ("osint_gather", "tls_deep", "smtp_enum", "hash_id", "cewl_words"):
        assert t in names
    pnames = [p.name for p in REGISTRY]
    for n in ("theharvester", "testssl", "smtp-enum", "hashid", "cewl"):
        assert n in pnames
    assert len(REGISTRY) >= 44


def test_lore_ninth_batch() -> None:
    assert "theharvester" in lore_for([{"role": "user", "content": "收集 example.com 的子域和邮箱"}])
    assert "testssl" in lore_for([{"role": "user", "content": "对这个站点做 tls 深度检测"}])
    assert "smtp-enum" in lore_for([{"role": "user", "content": "枚举 smtp 服务器上的用户"}])
    assert "hashid" in lore_for([{"role": "user", "content": "识别这个 hash 是什么类型"}])
    assert "cewl" in lore_for([{"role": "user", "content": "从网站生成密码词表"}])
