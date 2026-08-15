"""命令行入口：python -m DeepKali [选项]"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .config import Config


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="DeepKali",
        description="DeepKali — 专为 Kali Linux 打造的 TUI AI agent，让 AI 驾驭你的终端。",
    )
    p.add_argument("--version", action="version", version=f"DeepKali {__version__}")
    p.add_argument("--config", type=Path, default=None, help="配置文件路径（默认 ~/.config/DeepKali/config.json）")
    p.add_argument("--api-key", default=None, help="API key（也可用环境变量 DEEPKALI_API_KEY）")
    p.add_argument("--base-url", default=None, help="OpenAI 兼容 API 地址（默认 https://api.deepseek.com/v1）")
    p.add_argument("--model", default=None, help="模型名（默认 deepseek-chat）")
    p.add_argument("--demo", action="store_true", help="强制 demo 模式（无 API，脚本大脑）")
    p.add_argument("--workdir", default=None, help="agent 工作目录（默认当前目录）")
    p.add_argument(
        "--danger",
        choices=["ask", "always_allow", "always_block"],
        default=None,
        help="危险命令策略（默认 ask）",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    cfg = Config.load()
    if args.config is not None and args.config.exists():
        import json

        data = json.loads(args.config.read_text(encoding="utf-8"))
        for k, v in data.items():
            if hasattr(cfg, k) and v is not None:
                setattr(cfg, k, v)
    for attr, val in (
        ("api_key", args.api_key),
        ("base_url", args.base_url),
        ("model", args.model),
        ("workdir", args.workdir),
        ("danger_policy", args.danger),
    ):
        if val is not None:
            setattr(cfg, attr, val)
    if args.demo:
        cfg.demo = True
    if cfg.workdir:
        try:
            os.chdir(cfg.workdir)
        except OSError as e:
            print(f"无法切换到工作目录 {cfg.workdir}: {e}", file=sys.stderr)
            return 1
    cfg.ensure_dirs()
    cfg.save()

    # 延迟导入，加快 --version 响应
    from .app import DeepKaliApp

    app = DeepKaliApp(cfg)
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
