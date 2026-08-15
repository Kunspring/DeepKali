"""配置加载：环境变量优先，其次 ~/.config/DeepKali/config.json。"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "DeepKali"
CONFIG_FILE = CONFIG_DIR / "config.json"
DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "DeepKali"
SESSION_DIR = DATA_DIR / "sessions"


@dataclass
class Config:
    api_key: str = ""
    base_url: str = "https://api.deepseek.com/v1"
    model: str = "deepseek-chat"
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout: float = 120.0
    demo: bool = False          # 无 API 时用内置脚本演示（测试/预览用）
    workdir: str = field(default_factory=os.getcwd)
    max_output_lines: int = 2000   # 单条命令输出送入上下文的行数上限
    danger_policy: str = "ask"     # ask | always_allow | always_block
    scope_policy: str = "ask"      # ask（外部目标需授权确认） | off
    extra_system_prompt: str = ""

    @classmethod
    def load(cls) -> "Config":
        cfg = cls()
        # 文件配置（较低优先级）
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                for k, v in data.items():
                    if hasattr(cfg, k) and v is not None:
                        setattr(cfg, k, v)
            except (json.JSONDecodeError, OSError):
                pass
        # 环境变量（最高优先级）
        env_map = {
            "DEEPKALI_API_KEY": "api_key",
            "DEEPKALI_BASE_URL": "base_url",
            "DEEPKALI_MODEL": "model",
            "DEEPKALI_DEMO": "demo",
            "DEEPKALI_WORKDIR": "workdir",
            "DEEPKALI_SCOPE_POLICY": "scope_policy",
        }
        for env, attr in env_map.items():
            if os.environ.get(env):
                val: object = os.environ[env]
                if attr == "demo":
                    val = val.lower() in ("1", "true", "yes")
                setattr(cfg, attr, val)
        return cfg

    def masked_key(self) -> str:
        """打码显示 api_key：sk-1234****abcd。"""
        if not self.api_key:
            return "(未设置)"
        key = self.api_key
        if len(key) <= 8:
            return "*" * len(key)
        return f"{key[:6]}...{key[-4:]}"

    def ensure_dirs(self) -> None:
        SESSION_DIR.mkdir(parents=True, exist_ok=True)

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        # demo 是运行态（CLI/env 指定），不持久化，避免污染后续启动
        data = {
            "base_url": self.base_url,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
            "workdir": self.workdir,
            "danger_policy": self.danger_policy,
        }
        if self.api_key:
            data["api_key"] = self.api_key
        CONFIG_FILE.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        # 含密钥，收紧为仅当前用户可读写
        try:
            CONFIG_FILE.chmod(0o600)
        except OSError:
            pass
