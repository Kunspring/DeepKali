"""第八批深度定制档案测试：curl / sslscan / wafw00f / redis / ftp。"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from DeepKali.profiles import REGISTRY, all_schemas, lore_for, register_extensions  # noqa: E402
from DeepKali.profiles.curl import _build_cmd as curl_cmd  # noqa: E402
from DeepKali.profiles.ftp import _build_cmd as ftp_cmd  # noqa: E402
from DeepKali.profiles.redis import _build_cmd as redis_cmd  # noqa: E402
from DeepKali.profiles.sslscan import _build_cmd as ssl_cmd  # noqa: E402
from DeepKali.profiles.wafw00f import _build_cmd as waf_cmd  # noqa: E402
from DeepKali.safety import classify  # noqa: E402

# ---------------- 命令构造与校验 ----------------


def test_curl_cmd() -> None:
    cmd, _ = curl_cmd({"url": "http://10.0.0.5/admin.php"})
    assert cmd.startswith("curl -s -o /dev/stdout -w '\\n%{http_code} %{size_download}' --max-time 20")
    assert cmd.endswith("http://10.0.0.5/admin.php")
    cmd2, _ = curl_cmd({
        "url": "http://x.com/login",
        "method": "POST",
        "data": "user=admin&pass=123",
        "headers": "Authorization: Bearer xyz; X-Forwarded-For: 127.0.0.1",
        "cookie": "session=abc",
        "follow": True,
        "insecure": True,
    })
    assert "-X POST" in cmd2 and "--data-raw 'user=admin&pass=123'" in cmd2
    assert "-H 'Authorization: Bearer xyz'" in cmd2 and "-H 'X-Forwarded-For: 127.0.0.1'" in cmd2
    assert "-b session=abc" in cmd2 and "-L" in cmd2 and "-k" in cmd2
    with pytest.raises(ValueError):
        curl_cmd({"url": "ftp://x.com/file"})
    with pytest.raises(ValueError):
        curl_cmd({"url": "http://x.com/;ls"})
    with pytest.raises(ValueError):
        curl_cmd({"url": "http://x.com/", "headers": "X: a\r\nInjected: 1"})
    with pytest.raises(ValueError):
        curl_cmd({"url": "http://x.com/", "method": "TRACE"})
    # 注入防护：data 经 shlex.quote
    safe = curl_cmd({"url": "http://x.com/", "method": "POST", "data": "a;rm -rf /"})
    assert "--data-raw 'a;rm -rf /'" in safe[0]


def test_ssl_cmd() -> None:
    cmd, _ = ssl_cmd({"host": "example.com"})
    assert cmd == "sslscan --no-colour --show-ciphers example.com:443"
    cmd2, _ = ssl_cmd({"host": "10.0.0.5", "port": 465, "sni": "mail.corp.local"})
    assert "10.0.0.5:465" in cmd2 and "--sni-name mail.corp.local" in cmd2
    with pytest.raises(ValueError):
        ssl_cmd({"host": "x.com;id"})
    with pytest.raises(ValueError):
        ssl_cmd({"host": "x.com", "port": 99999})


def test_waf_cmd() -> None:
    cmd, _ = waf_cmd({"url": "http://target.com"})
    assert cmd == "wafw00f http://target.com"
    cmd2, _ = waf_cmd({"url": "https://x.com", "verbose": True})
    assert "wafw00f https://x.com -v" in cmd2
    with pytest.raises(ValueError):
        waf_cmd({"url": "http://x.com;ls"})


def test_redis_cmd() -> None:
    cmd, _ = redis_cmd({"host": "10.0.0.5"})
    assert cmd == "redis-cli -h 10.0.0.5 -p 6379 INFO server | head -12"
    cmd2, _ = redis_cmd({"host": "10.0.0.5", "port": 6380, "password": "p@ss"})
    assert "-p 6380" in cmd2 and "-a 'p@ss'" in cmd2 and "--no-auth-warning" in cmd2
    with pytest.raises(ValueError):
        redis_cmd({"host": "10.0.0.5;ls"})
    with pytest.raises(ValueError):
        redis_cmd({"host": "10.0.0.5", "password": "x;id"})
    assert classify(cmd).level == "confirm"


def test_ftp_cmd() -> None:
    cmd, _ = ftp_cmd({"host": "10.0.0.5"})
    assert cmd == "curl -s --max-time 20 ftp://10.0.0.5:21/"
    cmd2, _ = ftp_cmd({"host": "10.0.0.5", "username": "admin", "password": "p@ss", "port": 2121})
    assert "ftp://admin:p@ss@10.0.0.5:2121/" in cmd2
    with pytest.raises(ValueError):
        ftp_cmd({"host": "10.0.0.5;ls"})
    with pytest.raises(ValueError):
        ftp_cmd({"host": "10.0.0.5", "port": 0})
    assert classify(cmd).level == "confirm"


# ---------------- registry / lore ----------------


def test_registry_eighth_batch() -> None:
    names = [s["function"]["name"] for s in all_schemas()]
    for t in ("http_req", "ssl_scan", "waf_detect", "redis_check", "ftp_check"):
        assert t in names
    pnames = [p.name for p in REGISTRY]
    for n in ("curl", "sslscan", "wafw00f", "redis", "ftp"):
        assert n in pnames
    assert len(REGISTRY) >= 39


def test_lore_eighth_batch() -> None:
    assert "curl" in lore_for([{"role": "user", "content": "看一下这个页面返回什么"}])
    assert "sslscan" in lore_for([{"role": "user", "content": "检查目标的 tls 配置"}])
    assert "wafw00f" in lore_for([{"role": "user", "content": "检测目标有没有 waf"}])
    assert "redis" in lore_for([{"role": "user", "content": "检查 6379 未授权访问"}])
    assert "ftp" in lore_for([{"role": "user", "content": "试试目标 ftp 能不能匿名登录"}])
