#!/usr/bin/env bash
# KaliTUI 一键安装：创建 venv、装依赖、生成启动脚本
set -euo pipefail
cd "$(dirname "$0")"

echo "==> 创建虚拟环境 .venv"
python3 -m venv .venv

echo "==> 安装依赖 (textual, httpx)"
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

echo "==> 生成启动脚本 ~/.local/bin/kalitui"
mkdir -p ~/.local/bin
cat > ~/.local/bin/kalitui <<EOF
#!/usr/bin/env bash
cd "$(pwd)"
exec "$(pwd)/.venv/bin/python" -m kalitui "\$@"
EOF
chmod +x ~/.local/bin/kalitui

echo
echo "✔ 安装完成！"
echo "  运行:  kalitui"
echo "  配置:  export KALITUI_API_KEY=sk-你的key    (或首次运行后编辑 ~/.config/kalitui/config.json)"
echo "  提示:  若 ~/.local/bin 不在 PATH，可:  echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.bashrc"
