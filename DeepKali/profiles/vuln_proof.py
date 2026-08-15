"""漏洞影响证明 lore（lore-only 档案，白帽报告被拒的头号原因：证明不了 impact）。

不注册工具——对话命中"验证漏洞/复现/PoC"等场景时，注入
"证明漏洞影响的最小安全操作"深度知识。
"""

from __future__ import annotations

from typing import Any

from .base import ToolProfile

VULN_PROOF_LORE = """### 漏洞影响证明要点（报告价值的核心）

#### 0. 原则
- 目标是**证明 impact 的最小安全操作**：不删数据、不写 webshell、不做破坏性动作；
  破坏性验证必须先用 ask_user 征求同意。
- 证据要可复现：请求/命令 + 响应差异（时间、状态码、内容）。
- 证明性输出必须完整保留——证据闸门会校验你的结论是否真实出现在工具输出里。

#### 1. 分类型证明手法
- **RCE**：`id` / `whoami` / `cat /etc/passwd | head -1`（读一行即可，不反弹 shell、不下载工具）
- **SQL 注入**：
  - UNION 提取：`union select version(),database()`（有回显）
  - 报错注入：`updatexml(1,concat(0x7e,version()),1)`（报错带数据）
  - 时间盲注：`if(1=1,sleep(3),0)` 对比响应时间（无回显也证明）
  - 布尔盲注：`1' and '1'='1` vs `1' and '1'='2` 页面差异
- **XSS**：`alert(document.domain)` 证明执行上下文；存储型展示持久化（重载后仍触发）
- **SSRF**：请求自己可控的监听器收集回连——`nc -lvnp 8888` 监听 + payload 指向
  `http://<你的IP>:8888/proof`，抓到 HTTP 请求即证明（或用 dnslog 域名）
- **LFI/路径穿越**：读 `/etc/passwd` 或应用配置文件（不读 /etc/shadow 等敏感凭证细节）
- **越权/认证绕过**：两个账号对比（A 账号访问 B 的资源）、低权限访问高权限接口；
  展示请求与响应的**前后差异**是关键
- **文件上传**：上传无害文件（内容 `DeepKali-proof-<随机串>`），再访问确认存在；
  不传 webshell、不改扩展名链
- **反序列化/POP**：本地先验证链可用，远程用最小 payload（sleep / 读文件）证明

#### 2. 输出格式（写进最终结论）
```
漏洞: <类型>
目标: <url/ip>
证明: <关键输出，引用证据 id>
复现: <1-2 步最小复现>
影响: <一句话说明能拿到什么>
```

#### 3. 边界
- 证明性输出含敏感数据（口令/令牌）时脱敏后再写报告。
- 无法证明 = 不成立：宁可继续探测，不要声称未验证的漏洞（证据闸门会拒绝）。"""


class VulnProofProfile(ToolProfile):
    name = "vuln_proof"
    aliases = [
        "验证漏洞", "证明漏洞", "漏洞验证", "确认可利用", "poc", "poc 验证",
        "复现", "复现漏洞", "impact", "影响证明", "proof", "利用验证",
        "写报告", "提交报告", "漏洞报告", "如何证明",
    ]
    summary = "漏洞影响证明 lore（验证/复现/PoC 时按需注入）"
    lore = VULN_PROOF_LORE
    extra_schemas: list[dict[str, Any]] = []

    # 纯 lore 档案：没有可注册的工具
    def register(self, executor: Any) -> None:
        return
