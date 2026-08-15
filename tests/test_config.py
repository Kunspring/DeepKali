"""config 模块测试：加载优先级、目录、持久化。"""

from __future__ import annotations

import json

import pytest


@pytest.fixture
def iso_config(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """把 CONFIG_FILE/SESSION_DIR 隔离到 tmp_path。"""
    import kalitui.config as C

    monkeypatch.setattr(C, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(C, "CONFIG_FILE", tmp_path / "config" / "config.json")
    monkeypatch.setattr(C, "SESSION_DIR", tmp_path / "sessions")
    monkeypatch.setattr(C, "DATA_DIR", tmp_path / "data")
    for env in ("KALITUI_API_KEY", "KALITUI_BASE_URL", "KALITUI_MODEL",
                "KALITUI_DEMO", "KALITUI_WORKDIR", "KALITUI_SCOPE_POLICY"):
        monkeypatch.delenv(env, raising=False)
    return C


def test_defaults(iso_config):
    cfg = iso_config.Config()
    assert cfg.danger_policy == "ask"
    assert cfg.scope_policy == "ask"
    assert cfg.temperature == 0.2


def test_load_from_file(iso_config, monkeypatch: pytest.MonkeyPatch):
    iso_config.CONFIG_FILE.parent.mkdir(parents=True)
    iso_config.CONFIG_FILE.write_text(
        json.dumps({"model": "file-model", "max_tokens": 2048, "unknown_key": 1}),
        encoding="utf-8",
    )
    cfg = iso_config.Config.load()
    assert cfg.model == "file-model"
    assert cfg.max_tokens == 2048
    assert not hasattr(cfg, "unknown_key")  # 未知字段忽略


def test_load_bad_json_ignored(iso_config):
    iso_config.CONFIG_FILE.parent.mkdir(parents=True)
    iso_config.CONFIG_FILE.write_text("{broken json", encoding="utf-8")
    cfg = iso_config.Config.load()  # 不抛
    assert cfg.model == "deepseek-chat"


def test_env_overrides_file(iso_config, monkeypatch: pytest.MonkeyPatch):
    iso_config.CONFIG_FILE.parent.mkdir(parents=True)
    iso_config.CONFIG_FILE.write_text(json.dumps({"model": "file-model"}), encoding="utf-8")
    monkeypatch.setenv("KALITUI_MODEL", "env-model")
    monkeypatch.setenv("KALITUI_API_KEY", "sk-env")
    monkeypatch.setenv("KALITUI_DEMO", "true")
    monkeypatch.setenv("KALITUI_SCOPE_POLICY", "off")
    cfg = iso_config.Config.load()
    assert cfg.model == "env-model"  # env 优先
    assert cfg.api_key == "sk-env"
    assert cfg.demo is True
    assert cfg.scope_policy == "off"


def test_demo_env_parsing(iso_config, monkeypatch: pytest.MonkeyPatch):
    for v, expect in (("1", True), ("false", False), ("no", False), ("yes", True)):
        monkeypatch.setenv("KALITUI_DEMO", v)
        cfg = iso_config.Config.load()
        assert cfg.demo is expect, v


def test_ensure_dirs_creates_session_dir(iso_config):
    cfg = iso_config.Config()
    cfg.ensure_dirs()
    assert iso_config.SESSION_DIR.is_dir()


def test_save_roundtrip(iso_config):
    cfg = iso_config.Config()
    cfg.model = "roundtrip-model"
    cfg.danger_policy = "always_allow"
    cfg.save()
    assert iso_config.CONFIG_FILE.exists()
    data = json.loads(iso_config.CONFIG_FILE.read_text(encoding="utf-8"))
    assert data["model"] == "roundtrip-model"
    assert data["danger_policy"] == "always_allow"
    assert "demo" not in data  # demo 不持久化
    assert "api_key" not in data  # 密钥不落盘
