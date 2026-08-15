"""WAF 绕过知识库（lore-only 档案，白帽挖洞高频场景）。

不注册任何工具——只在对话命中绕过场景关键词时，向模型注入
WAF 绕过深度知识（参考 VulnClaw waf-bypass skill + Reflexion L0-L4 升级思路）。
"""

from __future__ import annotations

from typing import Any

from .base import ToolProfile

WAF_BYPASS_LORE = """### WAF 绕过深度要点（仅授权目标）

#### 0. 先确认，再动手
- 用 waf_detect 确认 WAF 类型与厂商；不同 WAF 绕过点不同。
- 有 WAF 时：暴力扫描/注入会被拦截，先降速（--rate-limit）、关指纹（-A 换 UA）。

#### 1. 语义混淆（L1，最低成本）
- 关键字大小写变换：`SeLeCt`（仅对不区分大小写匹配有效）
- 内联注释拆分：`sel/**/ect`、`/*!50000SELECT*/`（MySQL 版本号注释）
- 空白字符变体：`%09`、`%0a`、`%0b`、`%0c` 替代空格
- 等价函数/语法：`sleep(5)` → `benchmark(10000000,md5(1))` / 笛卡尔积 `(select 1 from a join b)`；
  `concat` → `concat_ws`；`information_schema` 大小写变体
- 字符串拼接：`'se'||'lect'`、`CHAR(115,101)`、`0x73656c656374`（hex）

#### 2. 编码层（L2-L3）
- 双重 URL 编码：`%2527`（WAF 解一次，后端解一次）
- Unicode/宽字节：`%u0027`、`%bf%27`（GBK 宽字节注入）
- HTML 实体：`&#x27;`、`&#39;`
- 全角/异体字符、注释符号变体：`--+` / `#` / `%23` / `/*!*/`

#### 3. 协议层（L4，绕过 CDN/WAF 网关）
- 打源站：CDN 后找真实 IP（历史 DNS、邮件头、子域直连），直接访问源站 IP
- Host 头替换 / 直接 IP + `-H "Host: target.com"`
- HTTP 版本降级（1.0/0.9）、分块传输（chunked）、畸形 Content-Length
- 参数污染 HPP：`?id=1&id=2'`（WAF 看第一个，后端取最后一个）
- 多段编码组合 + 换攻击面（POST→JSON body、XML、multipart 表单）

#### 4. 工具配合
- sqlmap：`--tamper=space2comment,charencode,randomcase,equaltolike`（按 WAF 选）
- wfuzz/ffuf：把 payload 放字典，`--hw/--hl` 过滤 WAF 拦截页特征
- nuclei：`-tags waf` 模板；先 `waf_detect` 再选模板

#### 5. 心态与合规
- 一次被拦 ≠ 无漏洞：记录被拦特征（状态码/关键词），换编码再试，别重复同一 payload。
- 绕过仅限**已授权目标**；对第三方 CDN/WAF 基础设施本身不做任何测试。
- 免费 WAF 常可整段绕过，商业 WAF（Cloudflare/Imperva）优先打源站与业务逻辑漏洞。"""


class WafBypassProfile(ToolProfile):
    name = "waf_bypass"
    aliases = [
        "waf 绕过", "绕过 waf", "bypass", "被 waf 拦截", "被拦截",
        "cloudflare", "modsecurity", "安全狗", "宝塔 waf", "tamper",
        "is behind", "waf 检测结果", "防火墙绕过", "waf bypass",
    ]
    summary = "WAF 绕过知识库（检测到防护/被拦截时按需注入）"
    lore = WAF_BYPASS_LORE
    extra_schemas: list[dict[str, Any]] = []

    # 纯 lore 档案：没有可注册的工具
    def register(self, executor: Any) -> None:
        return
