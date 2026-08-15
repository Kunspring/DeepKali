"""提权（Privilege Escalation）知识库（lore-only 档案，白帽拿到低权限 shell 后的高频场景）。

不注册工具——对话命中"提权/SUID/sudo -l"等场景时，注入 Linux/Windows
提权检查清单深度知识。
"""

from __future__ import annotations

from typing import Any

from .base import ToolProfile

PRIVESC_LORE = """### 提权（Privesc）检查清单（拿到低权限 shell 后按序排查）

#### 0. 纪律
- 目标是**最小证明**：`id` 显示 uid=0 即可证明，不删文件不改配置不装后门。
- 每步检查都产生真实输出（证据闸门会校验结论），不要凭记忆声称。

#### 1. Linux 提权（从最常用到最冷门）
- **sudo -l**：看当前用户能免密/带密执行什么；结合 GTFOBins 找提权方式
  （如 `sudo vi` → `:!sh`、`sudo python -c 'import pty;pty.spawn("/bin/bash")'`）
- **SUID 二进制**：`find / -perm -4000 -type f 2>/dev/null`——配合 GTFOBins
  判断可利用性（`find`/`vim`/`python` 等带 SUID 基本都能提）
- **内核版本**：`uname -a`——对照内核提权 CVE（脏牛 DirtyCow 等）；先 searchsploit 查本地利用
- **可写 cron 任务**：`cat /etc/crontab` + `/etc/cron.*`——若脚本目录可写，
  写入反弹/复制 SUID 的 payload（注意：改系统文件前先 ask_user）
- **PATH 劫持**：`echo $PATH` + 可写目录在 PATH 前部 → 放同名恶意命令
- **环境变量注入**：`LD_PRELOAD`（sudo 场景常配 env_keep）
- **可写 /etc/passwd**：`ls -l /etc/passwd`——可写则追加 root 用户行
- **能力（capabilities）**：`getcap -r / 2>/dev/null`——cap_setuid+ep 的 python/perl 可提
- **密码与凭证复用**：`cat /etc/shadow`（不可读则跳过）、备份文件、`.bash_history`、
  `.ssh/`、配置文件里的明文口令——历史凭证是白帽提权的黄金路径
- **服务滥用**：运行中的服务/容器（docker 组内 → `docker run -v /:/mnt`）、
  lxd 组、NFS `no_root_squash`（`showmount -e`）
- **自动化工具**：linpeas.sh（下载后执行，输出即证据）、pspy（监控 cron 进程）

#### 2. Windows 提权要点
- `whoami /priv`——SeImpersonatePrivilege → Potato 家族（Juicy/Lonely Potato）
- `whoami /groups`——本地管理员组但 UAC 限制 → UAC bypass 或服务路径注入
- 服务：`sc qc <服务>` / `accesschk`——服务二进制路径可写/服务未引号路径
- 注册表 AlwaysInstallElevated、未引号服务路径、计划任务
- 凭证：`reg save HKLM\\SAM`、`secretsdump`（已有定制工具）、浏览器/应用留存

#### 3. 流程建议
- 先 `sudo -l` + SUID + `uname -a` 三连（最快三条路），再深入 cron/能力/凭证。
- 每条线索用一条命令验证，输出留档；失败路径记入反思升级，换下一条，不重复硬试。
- 提权成功（uid=0 / NT AUTHORITY\\SYSTEM）立即停止横向扩展，向用户汇报并生成报告。"""


class PrivescProfile(ToolProfile):
    name = "privesc"
    aliases = [
        "提权", "提权枚举", "提权知识", "privesc", "privilege escalation",
        "sudo -l", "suid", "linpeas", "拿到 shell", "低权限", "get root",
        "root 权限", "system 权限", "内核提权",
    ]
    summary = "提权知识库（拿到低权限 shell 后按需注入）"
    lore = PRIVESC_LORE
    extra_schemas: list[dict[str, Any]] = []

    # 纯 lore 档案：没有可注册的工具
    def register(self, executor: Any) -> None:
        return
