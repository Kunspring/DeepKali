"""漏洞检测知识库（lore-only 档案，白帽漏洞发现阶段）。

不注册工具——对话命中"SQL 注入/XSS/命令注入"等漏洞类型或"测一下注入"
场景时，注入各漏洞类型的最小检测手法：探测 payload → 确认标准 → 工具衔接。
与 vuln_proof（验证阶段）互补：这里是"发现"，vuln_proof 是"证明"。
"""

from __future__ import annotations

from typing import Any

from .base import ToolProfile

VULN_DETECT_LORE = """### 漏洞检测手法（发现阶段：最小探测 + 确认标准 + 工具衔接）

#### 0. 纪律
- 每个探测 payload 都是**无害最小**（alert(1)、sleep(0)、7*7 之类），确认即止；
  影响大/慢速的探测（爆破、sleep>3）先 ask_user。
- 响应差异（正常 vs 注入）就是证据：状态码/响应体/时间差/报错信息都要留档。
- 检测命中后再进 vuln_proof lore 做可利用性证明，不要直接下结论。

#### 1. SQL 注入（最常考）
- 探测：URL/表单参数后加 `'`（单引号）看 500/报错；加 `' AND '1'='1` vs `' AND '1'='2`
  对比页面差异；数字型参数直接试 `1-1` vs `1`
- 时间盲注确认：`' AND SLEEP(0) -- ` 与 `' AND SLEEP(3) -- ` 对比响应时间（sleep 别超过 3 秒）
- 工具：sqlmap_scan 自动化（--batch --level 1 --risk 1 起步），报错/布尔/时间型都支持
- 确认标准：能通过注入读取库名/表名（报错型）或稳定时间差（盲注型）

#### 2. XSS
- 反射型探测：参数回显位置插入 `<script>alert(1)</script>`（无害）与 `<img src=x onerror=alert(1)>`
- 编码绕过（WAF 存在时）：大小写混合、`<svg/onload=alert(1)>`、HTML 实体、Unicode
- 存储型：表单提交后在其他页面回显（多页面检查）
- 确认标准：payload 原样出现在响应中（反射）或跨页面持久回显（存储）——仅证明弹窗点即可

#### 3. 命令注入
- 探测：`; id`、`` `id` ``、`$(id)`（拼接类）、`127.0.0.1 && echo PWN`（有回显）
- 无回显：`ping -c 3 127.0.0.1` 类的时间延迟，或用 nc 自建监听看回连
- 确认标准：id 输出/PWN 标记回显，或观察到延迟差异

#### 4. SSRF
- 探测：URL 参数（?url=/img=）指向自身观测点——先试内网地址响应差异（127.0.0.1 通 vs 不通）
- 确认：自建监听（nc -lvnp）看回连来源；或用 http_req 打内网元数据地址（如
  http://169.254.169.254/）看是否有云元数据响应
- 注意：云元数据/内网探测属敏感操作，先 ask_user 确认授权范围

#### 5. 文件包含（LFI/RFI）
- LFI 探测：`?page=../../../../etc/passwd`（逐级 ../，Windows 用 ..\\..\\）
- php wrapper：`?page=php://filter/convert.base64-encode/resource=config.php`（源码读取）
- 确认标准：/etc/passwd 或 base64 源码出现在响应

#### 6. 文件上传
- 探测：上传图片/文本后访问上传目录看路径；双扩展名（.php.jpg）、大小写（.pHp）、
  空字节（.php%00.jpg，旧环境）、Content-Type 伪造
- 确认标准：上传文件被原样保存且可访问（能解析执行才算 RCE，否则只是存储型 XSS 面）

#### 7. 越权/水平垂直越权
- 探测：正常请求后改资源 ID/用户名（A 用户操作 B 的资源），对比响应差异
- 确认标准：B 的数据/操作在 A 的会话下成功——这就是越权，不需要额外攻击

#### 8. 其他快速清单
- 认证绕过：默认口令（admin/admin）、响应头泄露、目录遍历（../admin）、弱会话（可预测 cookie）
- CSRF：表单无 CSRF token 且同源检查缺失（配合 cookie 凭证即可验证）
- SSTI：`{{7*7}}` → 响应出现 49；`${7*7}` → 49（Jinja2/FreeMarker 等）
- 开放重定向：`?redirect=https://evil.com` / `?next=//evil.com` 看 302 Location

#### 9. 工具衔接
- sqlmap_scan / xsstrike 扫描 / ffuf 参数爆破 / nuclei 已知模板——检测命中后按工具档案逐个深入。"""


class VulnDetectProfile(ToolProfile):
    name = "vuln_detect"
    aliases = [
        "sql 注入", "sql注入", "xss", "命令注入", "ssrf", "csrf", "越权",
        "文件包含", "lfi", "rfi", "文件上传", "反序列化", "模板注入", "ssti",
        "开放重定向", "注入测试", "测一下注入", "试试注入", "检测漏洞", "漏洞探测",
        "cve 探测", "owasp",
    ]
    summary = "漏洞检测手法知识库（发现阶段按需注入）"
    lore = VULN_DETECT_LORE
    extra_schemas: list[dict[str, Any]] = []

    # 纯 lore 档案：没有可注册的工具
    def register(self, executor: Any) -> None:
        return
