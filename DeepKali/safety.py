"""命令安全分级：识别危险命令，决定是否需要人工确认。

级别:
  safe        —— 自动执行
  confirm     —— 需要用户在 TUI 里确认
  blocked     —— 默认拒绝（除非用户在弹窗里显式「强制」）

实现：对整条命令行做子串正则匹配（分段切分反而会被 fork 炸弹等
含 `;`/`|` 的语法绕开）。保守优先：宁可多拦一次，也不放过真危险。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---- 危险模式 ----
# 每个模式: (正则, 级别, 理由)
_PATTERNS: list[tuple[re.Pattern[str], str, str]] = []


def _pat(regex: str, level: str, reason: str) -> None:
    _PATTERNS.append((re.compile(regex, re.IGNORECASE | re.VERBOSE), level, reason))


# ============ 直接封禁级（默认拒绝，可强制） ============
_pat(r"\brm\s+(-[a-z]*[rf][a-z]*\s+)+/(?:\*|\s|$)", "blocked", "递归删除根目录")
_pat(r"\brm\s+(-[a-z]*[rf][a-z]*\s+)+/etc(?:\s|$|/)", "blocked", "删除 /etc 关键配置")
_pat(r"\brm\s+(-[a-z]*[rf][a-z]*\s+)*\*(?:\s|$|;|&&|\|)", "blocked", "当前目录通配删除")
_pat(r"\bdd\s+.*\bof=/dev/(sd|nvme|vd|hd)[a-z]", "blocked", "dd 直接写块设备")
_pat(r"\bmkfs(\.\w+)?\s+", "blocked", "格式化文件系统")
_pat(r"\bparted\s+.*\bmklabel\b", "blocked", "重建分区表")
_pat(r"\bfdisk\s+/dev/(sd|nvme|vd|hd)", "blocked", "修改磁盘分区")
_pat(r"\bshutdown\b|\breboot\b|\bpoweroff\b|\bhalt\b", "blocked", "关机/重启")
_pat(r":\(\)\s*\{\s*:\|:&\s*\}\s*;", "blocked", "fork 炸弹")
_pat(r"\bchmod\s+-[a-z]*R[a-z]*\s+777\s+/(?=\s|$)", "blocked", "根目录递归放开权限")
_pat(r"\bchown\s+-[a-z]*R[a-z]*\s+\w+\s+/(?=\s|$)", "blocked", "根目录递归改属主")
_pat(r">+\s*/dev/(sd|nvme|vd|hd)", "blocked", "直接写块设备")
_pat(r"\bgit\s+push\s+.*--force\b", "blocked", "git 强推（防误操作）")
_pat(r"\bwipefs\b|\bblkdiscard\b", "blocked", "擦除磁盘")

# ============ 确认级（弹窗确认） ============
_pat(r"\brm\s+(-[a-z]*[rf][a-z]*\s+)+[^\s]+", "confirm", "递归/强制删除")
_pat(r"\brm\s+-[a-z]*i", "confirm", "rm 交互删除（批量）")
_pat(r"\bapt\s+(remove|purge|autoremove)\b", "confirm", "卸载软件包")
_pat(r"\bdpkg\s+(-r|--remove|--purge)\b", "confirm", "卸载软件包")
_pat(r"\bservice\s+\S+\s+stop\b|\bsystemctl\s+(stop|disable)\b", "confirm", "停止系统服务")
_pat(r"\buserdel\b|\bdeluser\b", "confirm", "删除用户")
_pat(r"\bpasswd\s+(?!$)", "confirm", "修改密码")
_pat(r"\bkill\s+-?9?\s+\d+", "confirm", "强杀进程")
_pat(r"\bpkill\b|\bkillall\b", "confirm", "批量杀进程")
_pat(r"\biptables\b|\bnft\b|\bufw\b", "confirm", "修改防火墙规则")
_pat(r"\bsysctl\s+-w\b", "confirm", "修改内核参数")
_pat(r"\bchmod\s+[0-7]{3,4}\s+/(etc|boot|usr)\b", "confirm", "修改系统目录权限")
_pat(r"\bsudo\s+rm\b", "confirm", "sudo 删除")
_pat(r"\bmsfconsole\b", "confirm", "Metasploit 交互（exploit 前请确认目标）")
_pat(r"\bhydra\b|\bmedusa\b|\bjohn\b|\bhashcat\b|\baircrack-ng\b|\bsqlmap\b|\bmsfvenom\b|\bnuclei\b|\bresponder\b|\bevil-winrm\b|\bsecretsdump\b|\bimpacket-[a-z-]+\b|\bchisel\b|\bnc\b|\bncat\b|\bnetcat\b|\bsocat\b|\bwfuzz\b|\bmacchanger\b|\bairmon-ng\b|\bredis-cli\b|\bftp\b|\bsmtp-user-enum\b", "confirm", "爆破/注入/口令/投毒/远程执行/隧道/网络监听工具")
_pat(r"\bnikto\b", "confirm", "nikto 主动扫描")
_pat(r"\bsearchsploit\s+-[a-z]*[mM]", "confirm", "searchsploit 利用代码查看")
_pat(r"\bairmon-ng\b|\bairodump-ng\b|\bwash\b|\breaver\b", "confirm", "无线攻击工具")
_pat(r"\bsocat\s+.*(exec|system)", "confirm", "socat 反弹 shell 类")
_pat(r"\bnc\s+(-e|-c)\b", "confirm", "nc 反弹 shell 类")
_pat(r"\bpython3?\s+.*\b(socket|pty|subprocess).*(connect|spawn)", "confirm", "反弹 shell 脚本")
_pat(r"\bcurl\s+.*\|?\s*(ba)?sh\b", "confirm", "curl 管道执行")
_pat(r"\bwget\s+.*\|?\s*(ba)?sh\b", "confirm", "wget 管道执行")
_pat(r"\bchmod\s+[0-7]{3,4}\s+/etc/passwd\b", "confirm", "修改 passwd 权限")
_pat(r"\bopenssl\s+req\s+.*-x509", "confirm", "生成证书（确认用途）")


@dataclass(frozen=True)
class Verdict:
    level: str          # safe | confirm | blocked
    reason: str = ""


def classify(cmdline: str) -> Verdict:
    """整串子串匹配，取最高危险级。空命令视为 safe。"""
    if not cmdline.strip():
        return Verdict("safe", "空命令")
    worst: Verdict = Verdict("safe", "")
    for pat, level, reason in _PATTERNS:
        if pat.search(cmdline):
            if level == "blocked":
                return Verdict("blocked", reason)
            if worst.level != "blocked":
                worst = Verdict(level, reason)
    return worst
