"""命令行入口：python -m DeepKali [选项] [子命令]"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .config import CONFIG_FILE, Config


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


def _print_config(cfg: Config) -> None:
    print(f"  API key  : {cfg.masked_key()}")
    print(f"  API 地址 : {cfg.base_url}")
    print(f"  模型     : {cfg.model}")
    print(f"  危险策略 : {cfg.danger_policy}")
    print(f"  工作目录 : {cfg.workdir}")
    print(f"  配置文件 : {CONFIG_FILE}")


def _cmd_config(argv: list[str]) -> int:
    """DeepKali config [--api-key X] [--base-url X] [--model X] [--danger X] [--workdir X]"""
    p = argparse.ArgumentParser(prog="DeepKali config", description="查看或修改持久化配置")
    p.add_argument("--api-key", default=None, help="设置 API key")
    p.add_argument("--base-url", default=None, help="设置 API 地址")
    p.add_argument("--model", default=None, help="设置模型名")
    p.add_argument(
        "--danger",
        choices=["ask", "always_allow", "always_block"],
        default=None,
        help="设置危险命令策略",
    )
    p.add_argument("--workdir", default=None, help="设置默认工作目录")
    args = p.parse_args(argv)

    cfg = Config.load()
    changed = False
    for attr, val in (
        ("api_key", args.api_key),
        ("base_url", args.base_url),
        ("model", args.model),
        ("danger_policy", args.danger),
        ("workdir", args.workdir),
    ):
        if val is not None:
            setattr(cfg, attr, val)
            changed = True
    if changed:
        cfg.save()
        print("✔ 配置已保存\n")
    _print_config(cfg)
    return 0


def _cmd_setup() -> int:
    """DeepKali setup — 交互式配置向导"""
    print("DeepKali 配置向导（直接回车保留当前值）\n")
    cfg = Config.load()
    val = input(f"API key [{cfg.masked_key()}]: ").strip()
    if val:
        cfg.api_key = val
    val = input(f"API 地址 [{cfg.base_url}]: ").strip()
    if val:
        cfg.base_url = val
    val = input(f"模型 [{cfg.model}]: ").strip()
    if val:
        cfg.model = val
    val = input(f"危险命令策略 (ask/always_allow/always_block) [{cfg.danger_policy}]: ").strip()
    if val:
        if val not in ("ask", "always_allow", "always_block"):
            print(f"✘ 无效策略: {val}（可选 ask/always_allow/always_block）")
            return 1
        cfg.danger_policy = val
    cfg.save()
    print("\n✔ 配置已保存\n")
    _print_config(cfg)
    return 0


def _find_subcommand(argv: list[str]) -> str | None:
    """扫描 argv 找到子命令（跳过 --opt 及其值），支持 python -m DeepKali --workdir X config。"""
    for tok in argv:
        if tok.startswith("-"):
            continue
        if tok in ("config", "setup"):
            return tok
        # 不以 - 开头的 token 是某个选项的值，跳过
    return None


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    sub = _find_subcommand(argv)
    if sub == "config":
        return _cmd_config([a for a in argv if a not in ("config", "setup")])
    if sub == "setup":
        return _cmd_setup()

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
