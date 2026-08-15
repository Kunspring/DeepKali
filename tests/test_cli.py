"""CLI 子命令测试：DeepKali config / DeepKali setup。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import DeepKali.config as kconfig  # noqa: E402
from DeepKali import __main__ as cli  # noqa: E402


@pytest.fixture
def iso_cli(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """把 CONFIG_FILE 隔离到 tmp_path。"""
    monkeypatch.setattr(kconfig, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(kconfig, "CONFIG_FILE", tmp_path / "config" / "config.json")
    monkeypatch.setattr(kconfig, "SESSION_DIR", tmp_path / "sessions")
    monkeypatch.setattr(kconfig, "DATA_DIR", tmp_path / "data")
    for env in ("DEEPKALI_API_KEY", "DEEPKALI_BASE_URL", "DEEPKALI_MODEL",
                "DEEPKALI_DEMO", "DEEPKALI_WORKDIR", "DEEPKALI_SCOPE_POLICY"):
        monkeypatch.delenv(env, raising=False)
    return kconfig


def test_config_view(iso_cli, capsys):
    rc = cli._cmd_config([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "API key" in out
    assert "(未设置)" in out


def test_config_set_api_key(iso_cli):
    rc = cli._cmd_config(["--api-key", "sk-cli-test-abcdef"])
    assert rc == 0
    assert iso_cli.CONFIG_FILE.exists()
    data = json.loads(iso_cli.CONFIG_FILE.read_text(encoding="utf-8"))
    assert data["api_key"] == "sk-cli-test-abcdef"


def test_config_set_other_fields(iso_cli):
    rc = cli._cmd_config(["--model", "deepseek-r1", "--danger", "always_allow"])
    assert rc == 0
    data = json.loads(iso_cli.CONFIG_FILE.read_text(encoding="utf-8"))
    assert data["model"] == "deepseek-r1"
    assert data["danger_policy"] == "always_allow"


def test_config_masked_key_display(iso_cli, capsys):
    cli._cmd_config(["--api-key", "sk-display-12345678"])
    cli._cmd_config([])
    out = capsys.readouterr().out
    assert "sk-dis...5678" in out
    assert "sk-display-12345678" not in out  # 明文不显示


def test_setup_wizard(iso_cli, monkeypatch, capsys):
    inputs = iter(["sk-setup-key-abcdef", "", "deepseek-v4-flash", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
    rc = cli._cmd_setup()
    assert rc == 0
    data = json.loads(iso_cli.CONFIG_FILE.read_text(encoding="utf-8"))
    assert data["api_key"] == "sk-setup-key-abcdef"
    assert data["model"] == "deepseek-v4-flash"


def test_setup_invalid_danger(iso_cli, monkeypatch):
    inputs = iter(["", "", "", "bogus"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
    rc = cli._cmd_setup()
    assert rc == 1


def test_find_subcommand():
    assert cli._find_subcommand(["config"]) == "config"
    assert cli._find_subcommand(["--workdir", "/tmp", "config"]) == "config"
    assert cli._find_subcommand(["setup"]) == "setup"
    assert cli._find_subcommand(["--demo"]) is None
    assert cli._find_subcommand([]) is None
