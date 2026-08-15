"""证据记忆（AgentState 精华移植自 VulnClaw）。

核心思路（与 VulnClaw agent_state/correction_layer 同源）：
- 每次工具调用的完整输出都保存为证据（EvidenceRecord，带 id/hash/size），
  这是唯一可信的事实来源，模型不能凭空声称结论。
- 模型上下文只注入"高信号预览"：自动挑选 flag / SQL / form / endpoint /
  sink / 状态码等关键行，避免大段 HTML/日志反复污染上下文。
- 长期事实（pinned facts：SQL 片段、表单、JS endpoint、URL、flag 等）
  每轮可见，避免后续探测把真实入口淹没。
- evidence_search / evidence_view 按需回查原始证据；重复查看被短路。
- 工具健康跟踪：连续失败 → degraded，提示模型换思路。
- 相同 raw 输出再次出现时只保留 same_as=eXXX 引用，不重复占上下文。
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any

# 单个证据在 active context 中的预览上限（字符）
DEFAULT_PREVIEW_CHARS = 6000
# 每次注入模型的高信号摘要中最多展示的证据条数
MAX_PREVIEW_EVIDENCE = 8
MAX_PINNED_FACTS = 40
MAX_STORED_EVIDENCE = 240

# 高信号关键行标记（VulnClaw _important_lines 精简版，适配 Kali 工具输出）
_IMPORTANT_MARKERS = (
    "flag", "ctf{", "status:", "headers:", "location:", "set-cookie",
    "error", "exception", "sql", "union", "select", "form", "<input",
    "href=", "script", "token", "secret", "key", "password", "admin",
    "endpoint", "api/", "highlight_file", "show_source", "source",
    "<?php", "$_get", "$_post", "$_request", "$_cookie",
    "unserialize", "serialize", "__wakeup", "__destruct", "__tostring",
    "eval(", "assert(", "system(", "shell_exec", "preg_match",
    "open", "closed", "filtered", "found", "vulnerable",
)

_FLAG_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,20}\{[^{}\n]{1,200}\}")
_STATUS_RE = re.compile(r"(?:Status|HTTP/\d(?:\.\d)?)\s*:?\s*(\d{3})", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s'\"<>）)]+", re.IGNORECASE)
_FORM_RE = re.compile(r"(?is)<form\b[^>]*>")
_INPUT_RE = re.compile(r"(?is)<input\b[^>]*>")
_JS_ENDPOINT_RE = re.compile(
    r"""(?is)(?:url\s*[:=]\s*|fetch\s*\(|axios\.\w+\s*\()\s*["']([^"']{1,180}(?:\.php\b|/api/?|api/|\?)[^"']*)["']"""
)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# 失败信号（VulnClaw _FAILURE_MARKERS 精简）
FAILURE_MARKERS = (
    "[!]", "traceback", "exception", "timed out", "timeout",
    "connection refused", "connection reset", "no route to host",
    "无法访问", "访问失败", "命令未找到", "command not found",
    "permission denied", "被拒绝", "超时",
)


def clip_text(value: str, limit: int, *, marker: str = "...[truncated]...") -> str:
    """确定性头/尾预览，超长文本不截断中间关键词。"""
    text = str(value or "")
    if limit <= 0 or len(text) <= limit:
        return text
    head = max(1, limit // 2)
    tail = max(1, limit - head - len(marker) - 2)
    return f"{text[:head].rstrip()}\n{marker}\n{text[-tail:].lstrip()}"


def one_line(value: str, limit: int = 240) -> str:
    """折叠空白并裁剪为单行（提示词安全）。"""
    return clip_text(re.sub(r"\s+", " ", str(value or "")).strip(), limit)


def extract_flags(text: str) -> list[str]:
    """提取 CTF flag 样式的 token（不断言真实性，真伪由证据闸门判定）。"""
    return list(dict.fromkeys(_FLAG_RE.findall(text or "")))


def extract_status_code(text: str) -> int:
    match = _STATUS_RE.search(text or "")
    return int(match.group(1)) if match else 0


def _important_lines(text: str, limit: int = 18) -> list[str]:
    """从大输出中挑出高信号行（带行号）。"""
    selected: list[str] = []
    for line_no, line in enumerate(str(text or "").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if any(marker in lower for marker in _IMPORTANT_MARKERS):
            selected.append(f"L{line_no}: {one_line(stripped, 260)}")
        if len(selected) >= limit:
            break
    return selected


def make_high_signal_preview(content: str, limit: int = DEFAULT_PREVIEW_CHARS) -> str:
    """有界预览：active context 只放高信号行，raw 全文另行保存。"""
    text = str(content or "")
    if limit <= 0 or len(text) <= limit:
        return text
    lines = _important_lines(text, limit=24)
    header = (
        "[active-context high-signal preview]\n"
        f"raw_size={len(text)} chars; 完整原文已存为证据，"
        "可用 evidence_view/evidence_search 回查。"
    )
    marker = "...[raw omitted from active context; use evidence_view for full body]..."
    if not lines:
        return header + "\n" + marker
    return header + "\n" + "\n".join(lines) + "\n" + marker


def _extract_sql_facts(text: str) -> list[str]:
    facts: list[str] = []
    for line in str(text or "").splitlines():
        lower = line.lower()
        if "select" not in lower or " from " not in lower:
            continue
        if not any(marker in lower for marker in (" where ", "$_get", " limit ", " union ")):
            continue
        facts.append(f"Source SQL: {one_line(line, 300)}")
        if len(facts) >= 4:
            break
    return list(dict.fromkeys(facts))


def _extract_form_facts(text: str) -> list[str]:
    facts: list[str] = []
    for tag in _FORM_RE.findall(text or "")[:4]:
        facts.append(f"HTML form: {one_line(tag, 200)}")
    for tag in _INPUT_RE.findall(text or "")[:8]:
        name = re.search(r"""name\s*=\s*["']?([^"'\s>]+)""", tag, re.I)
        if name:
            facts.append(f"HTML input: name={name.group(1)}")
    return facts[:8]


def _extract_js_endpoint_facts(text: str) -> list[str]:
    facts: list[str] = []
    for match in _JS_ENDPOINT_RE.finditer(text or ""):
        facts.append(f"JS/API endpoint: {one_line(match.group(1), 180)}")
        if len(facts) >= 6:
            break
    return facts


# crt.sh/子域枚举输出的裸域名行（如 "vpn.example.com"）
_DOMAIN_LINE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,24}$")


def _extract_domain_facts(text: str) -> list[str]:
    """从"每行一个域名"的输出里提取子域事实（crt.sh/dnsrecon 摘要）。"""
    facts: list[str] = []
    for line in str(text or "").splitlines():
        d = line.strip().lower()
        if not _DOMAIN_LINE_RE.match(d):
            continue
        if d.startswith(("http", "www.")):
            continue
        facts.append(f"Subdomain: {d}")
    return list(dict.fromkeys(facts))[:8]


def extract_pinned_facts(text: str) -> list[str]:
    """从工具输出提取长期可见事实（VulnClaw correction_layer 精华）。"""
    facts: list[str] = []
    for flag in extract_flags(text)[:3]:
        facts.append(f"Observed flag-like token: {flag}")
    facts.extend(_extract_sql_facts(text))
    facts.extend(_extract_form_facts(text))
    facts.extend(_extract_js_endpoint_facts(text))
    for url in list(dict.fromkeys(_URL_RE.findall(text or "")))[:5]:
        facts.append(f"Observed URL: {one_line(url, 160)}")
    facts.extend(_extract_domain_facts(text))
    status = extract_status_code(text)
    if status:
        facts.append(f"HTTP status observed: {status}")
    return list(dict.fromkeys(facts))[:12]


# ---------------------------------------------------------------------------
# Findings：白帽挖洞发现提取（漏洞/flag/CVE 结构化记录）
# ---------------------------------------------------------------------------
_VULN_MARKERS = (
    "vulnerable", "VULNERABLE", "is vulnerable", "漏洞", "存在漏洞",
    "bypass", "绕过", "injection", "注入",
    "exploitable", "可被利用", "weak password", "弱口令", "default cred",
    "phpinfo", "directory listing", "目录遍历",
)

# 未授权访问/信息泄露（SRC 高频高危，独立成类）
_UNAUTHORIZED_MARKERS = (
    "unauthorized", "未授权访问", "未授权", "exposed", "暴露",
    "no authentication", "无需认证", "missing auth", "访问控制",
    "actuator", "heapdump", "graphql", "swagger",
)


def extract_findings(text: str, evidence_id: str = "") -> list[dict[str, str]]:
    """从工具输出提取结构化发现（flag / CVE / 漏洞标记），供报告与持久化。"""
    findings: list[dict[str, str]] = []
    for flag in extract_flags(text)[:5]:
        findings.append({"type": "flag", "value": flag, "evidence": evidence_id})
    for cve in list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(text or "")))[:10]:
        findings.append({"type": "cve", "value": cve, "evidence": evidence_id})
    lowered = (text or "").lower()
    for marker in _UNAUTHORIZED_MARKERS:
        if marker.lower() in lowered:
            findings.append({"type": "unauthorized", "value": marker, "evidence": evidence_id})
            break
    for marker in _VULN_MARKERS:
        if marker.lower() in lowered:
            findings.append({"type": "vuln_marker", "value": marker, "evidence": evidence_id})
            break
    status = extract_status_code(text)
    if 400 <= status <= 599:
        findings.append({"type": "http_error", "value": str(status), "evidence": evidence_id})
    return findings


# 发现严重度（用于报告/快照排序，flag 最重，http_error 最轻）
FINDING_SEVERITY: dict[str, int] = {
    "flag": 5,
    "cve": 4,
    "unauthorized": 4,
    "vuln_marker": 3,
    "http_error": 1,
}


def severity_of(finding: dict[str, str]) -> int:
    return FINDING_SEVERITY.get(finding.get("type", ""), 2)


def sort_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    """按严重度降序 + 类型稳定排序。"""
    return sorted(findings, key=severity_of, reverse=True)


@dataclass
class EvidenceRecord:
    id: str
    tool: str
    arguments: dict[str, Any]
    content: str          # raw 完整输出（唯一可信证据）
    summary: str          # 首行摘要
    preview: str          # 高信号预览
    pinned: list[str]     # 从本证据提取的长期事实
    digest: str           # sha256 前 16 位
    size: int
    ts: float

    def to_index_line(self) -> str:
        return (
            f"{self.id}  tool={self.tool}  size={self.size}  "
            f"summary={one_line(self.summary, 120)}"
        )


class AgentMemory:
    """证据记忆：记录 / 预览 / 搜索 / 健康跟踪 / 重复调用检测。"""

    def __init__(self) -> None:
        self.evidence: list[EvidenceRecord] = []
        self.pinned_facts: list[str] = []
        self.findings: list[dict[str, str]] = []
        self._fact_sources: dict[str, str] = {}  # fact -> evidence id
        # 工具健康：tool -> {"fails": n, "calls": n, "degraded": bool}
        self.tool_health: dict[str, dict[str, Any]] = {}
        self._recent_calls: list[tuple[str, str, float]] = []  # (tool, args_json, ts)
        self._seen_digests: dict[str, str] = {}  # digest -> evidence id
        self._last_evidence_count = 0

    # ---------------- 记录 ----------------
    def record(self, tool: str, arguments: dict[str, Any], output: str) -> EvidenceRecord:
        text = str(output or "")
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]
        existing = self._seen_digests.get(digest)
        if existing is not None:
            # 相同输出去重：只保留引用，不重复占上下文
            rec = self._get(existing)
            if rec is not None:
                self._note_call(tool, arguments)
                self._update_health(tool, ok=True)
                return rec

        n = len(self.evidence) + 1
        rec = EvidenceRecord(
            id=f"e{n:03d}",
            tool=tool,
            arguments=arguments,
            content=text,
            summary=one_line(text.splitlines()[0] if text.splitlines() else "(空输出)", 160),
            preview=make_high_signal_preview(text),
            pinned=[],
            digest=digest,
            size=len(text),
            ts=time.time(),
        )
        self.evidence.append(rec)
        self._seen_digests[digest] = rec.id
        self._note_call(tool, arguments)
        self._update_health(tool, ok=True)

        for fact in extract_pinned_facts(text):
            if fact not in self.pinned_facts:
                if len(self.pinned_facts) >= MAX_PINNED_FACTS:
                    break  # 满员后不再接纳新事实（break 须在 append 之前）
                self.pinned_facts.append(fact)
                self._fact_sources[fact] = rec.id
        rec.pinned = [f for f in extract_pinned_facts(text) if f in self.pinned_facts]

        # 结构化发现（flag/CVE/漏洞标记）去重收集
        for finding in extract_findings(text, rec.id):
            key = (finding["type"], finding["value"])
            if not any((f["type"], f["value"]) == key for f in self.findings):
                if len(self.findings) >= 60:
                    break  # 满员后不再接纳新发现（break 须在 append 之前）
                self.findings.append(finding)

        if len(self.evidence) > MAX_STORED_EVIDENCE:
            self.evidence = self.evidence[-MAX_STORED_EVIDENCE:]
        return rec

    def record_failure(self, tool: str, arguments: dict[str, Any], error: str) -> None:
        """工具抛错/失败：记录健康但不污染证据池。"""
        self._note_call(tool, arguments)
        self._update_health(tool, ok=False)

    def _get(self, evidence_id: str) -> EvidenceRecord | None:
        for item in self.evidence:
            if item.id == evidence_id:
                return item
        return None

    def _note_call(self, tool: str, arguments: dict[str, Any]) -> None:
        try:
            args_json = json.dumps(arguments, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            args_json = str(arguments)
        self._recent_calls.append((tool, args_json, time.time()))
        if len(self._recent_calls) > 200:
            self._recent_calls = self._recent_calls[-200:]

    def _update_health(self, tool: str, ok: bool) -> None:
        health = self.tool_health.setdefault(tool, {"calls": 0, "fails": 0, "degraded": False})
        health["calls"] += 1
        if ok:
            health["fails"] = 0
            health["degraded"] = False
        else:
            health["fails"] += 1
            if health["fails"] >= 3:
                health["degraded"] = True

    # ---------------- 查询 ----------------
    def evidence_text(self) -> str:
        """拼接全部证据（证据闸门逐字符校验用）。"""
        return "\n".join(item.content for item in self.evidence)

    def evidence_ids(self) -> list[str]:
        return [item.id for item in self.evidence]

    def search(self, query: str, limit: int = 6) -> str:
        q = (query or "").lower()
        hits = [
            item
            for item in self.evidence
            if q in item.content.lower() or q in item.preview.lower()
        ][-limit:]
        if not hits:
            return f"证据中未找到包含 {query!r} 的内容（共 {len(self.evidence)} 条证据）。"
        lines = [item.to_index_line() for item in hits]
        return "命中证据:\n" + "\n".join(lines)

    def view(self, evidence_id: str, max_chars: int = 8000) -> str:
        item = self._get(evidence_id.strip().lower())
        if item is None:
            return f"无此证据: {evidence_id}（可用 evidence_list 查看全部）"
        return (
            f"=== {item.id} tool={item.tool} size={item.size} ===\n"
            f"{clip_text(item.content, max_chars)}"
        )

    def list_summary(self) -> str:
        if not self.evidence:
            return "（还没有任何证据）"
        return "\n".join(item.to_index_line() for item in self.evidence[-20:])

    # ---------------- 攻击面快照 ----------------
    _OPEN_PORT_RE = re.compile(r"(\d{1,5})/tcp\s+open\s+(\S+)", re.IGNORECASE)

    def attack_surface_gaps(self) -> list[str]:
        """未探索的高信号方向列表（快照/报告共用，确定性生成）。

        探索判定 = pinned facts + 近期证据预览（漏洞信号如 SQL error 也算已探索）。
        """
        explored = " ".join(f.lower() for f in self.pinned_facts)
        for item in self.evidence[-6:]:
            explored += " " + (item.preview or "")[:1200].lower()
        return [
            anchor for anchor in ("sql", "form", "endpoint", "flag", "admin", "token", "upload", "api")
            if anchor not in explored
        ]

    def attack_surface_summary(self) -> str:
        """确定性攻击面快照：从证据汇总开放服务/Web 目标/漏洞点/未探索方向。

        白帽场景价值：证据多时帮模型聚焦——先看全貌再决定下一步，
        避免在已探索区域重复打转。
        """
        if not self.evidence:
            return "（还没有任何工具证据——先做侦察：nmap 端口扫描、http_req 看页面等。）"

        lines: list[str] = ["## 攻击面快照（由已收集证据确定性生成）"]

        # 1. 开放端口/服务
        ports: list[str] = []
        for item in self.evidence:
            for m in self._OPEN_PORT_RE.finditer(item.content):
                entry = f"{m.group(1)}/tcp({m.group(2)})"
                if entry not in ports:
                    ports.append(entry)
        if ports:
            lines.append(f"- 开放端口/服务: {', '.join(ports[:24])}")
        else:
            lines.append("- 开放端口/服务: （证据中未解析到 nmap 风格端口输出）")

        # 2. Web 目标
        web_urls = [f for f in self.pinned_facts if f.lower().startswith("observed url")]
        if web_urls:
            lines.append("- Web 目标: " + " | ".join(f.replace("Observed URL: ", "") for f in web_urls[:6]))

        # 3. 已确认的高信号事实（SQL/表单/接口等潜在攻击点）
        hot = [
            f for f in self.pinned_facts
            if any(k in f.lower() for k in ("source sql", "html form", "html input", "js/api endpoint", "flag", "parser/filter"))
        ]
        if hot:
            lines.append("- 潜在攻击点:")
            for f in hot[:10]:
                lines.append(f"  · {f}")

        # 4. 已确认发现（findings，按严重度）
        if self.findings:
            top = sort_findings(self.findings)[:8]
            lines.append(f"- 已确认发现（{len(self.findings)}，按严重度）: " +
                         ", ".join(f"{f['type']}={f['value']}" for f in top))

        # 5. 未探索方向（基于高信号锚点去重）
        missing = self.attack_surface_gaps()
        if missing:
            lines.append(f"- 尚未出现的高信号方向: {', '.join(missing)}（若任务需要，优先探索）")

        # 6. 建议
        if self.findings:
            lines.append("- 建议: 优先验证已确认发现的可利用性（见漏洞影响证明 lore），再补全缺口方向。")
        elif ports or web_urls:
            lines.append("- 建议: 对开放服务逐个枚举（目录/接口/版本），用 nuclei/nikto 查已知漏洞，检测 WAF。")
        else:
            lines.append("- 建议: 先扩大侦察（更多端口/子域/路径），再聚焦可交互目标。")

        return "\n".join(lines)

    # ---------------- 纠偏信号 ----------------
    def repeat_hint(self, tool: str, arguments: dict[str, Any]) -> str:
        """重复调用检测：同工具同参数最近出现 >=2 次 → 提示低价值。"""
        try:
            args_json = json.dumps(arguments, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            args_json = str(arguments)
        recent = [
            item for item in self._recent_calls
            if item[0] == tool and item[1] == args_json
        ]
        if len(recent) >= 2:
            return (
                f"[纠偏] 工具 {tool} 的完全相同调用已出现 {len(recent)} 次；"
                "除非有新的理由，重复执行可能价值不高，建议换思路或先 evidence_view 回看上次结果。"
            )
        return ""

    def health_hint(self, tool: str) -> str:
        health = self.tool_health.get(tool)
        if health and health["degraded"]:
            return (
                f"[纠偏] {tool} 已连续失败 {health['fails']} 次（degraded）；"
                "请检查参数/环境，或改用其他工具，不要盲目重试。"
            )
        return ""

    def stall_hint(self) -> str:
        """连续 3 轮无新证据 → stall guard 提示。"""
        new = len(self.evidence) - self._last_evidence_count
        if new > 0:
            self._last_evidence_count = len(self.evidence)
            return ""
        if not self.evidence:
            return ""
        return (
            "[stall guard] 最近几轮没有产生新证据；如果只是在反复查看旧结果，"
            "请采取会产生新信息的行动（新命令、读文件、问用户），或给出最终结论。"
        )

    # ---------------- 按目标统计（多目标工作区视图） ----------------
    # 本机/内网不纳入目标分组（本地靶场/自测不污染工作区）
    # 仅排除本机自指（localhost/回环）；私有网段是合法白帽目标，须正常归类
    _LOCAL_HOST_RE = re.compile(
        r"^(?:localhost|::1|127\.\d|0\.0\.0\.0)",
        re.IGNORECASE,
    )

    def _host_from_args(self, arguments: dict[str, Any]) -> str:
        """从工具参数里提取目标主机（url/target/host/command 常见字段）。"""
        for key in ("url", "target", "host", "hostname", "domain"):
            value = str(arguments.get(key) or "")
            if value:
                m = re.search(r"https?://([^/\s:]+(?::\d{1,5})?)", value) or \
                    re.search(r"([a-zA-Z0-9.-]+(?::\d{1,5})?)", value)
                if m:
                    host = m.group(1).lower()
                    if not self._LOCAL_HOST_RE.match(host):
                        return host
        command = str(arguments.get("command") or "")
        if command:
            # 命令里找网络工具后的第一个目标 token
            words = command.split()
            for i, w in enumerate(words):
                low = w.lower()
                if low in ("nmap", "ping", "curl", "sqlmap", "hydra", "nikto", "dig", "ssh", "nc", "gobuster", "ffuf", "nuclei", "wpscan", "wafw00f", "masscan", "fping", "httpx"):
                    for t in words[i + 1:i + 3]:
                        t = t.strip("'\"")
                        if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*(\.[a-zA-Z]{2,})?$", t) and not t.startswith("-"):
                            host = t.lower().split(":")[0]
                            if not self._LOCAL_HOST_RE.match(host):
                                return host
                    break
        return ""

    def target_stats(self) -> list[dict[str, Any]]:
        """按目标聚合：证据数 / 发现数 / 高信号事实数（多目标工作区用）。"""
        stats: dict[str, dict[str, Any]] = {}
        for item in self.evidence:
            host = self._host_from_args(item.arguments)
            if not host:
                continue
            entry = stats.setdefault(host, {"evidence": 0, "findings": 0, "facts": 0})
            entry["evidence"] += 1
            entry["facts"] += len(item.pinned)
            for f in self.findings:
                if f.get("evidence") == item.id:
                    entry["findings"] += 1
        return [
            {"target": host, **stats[host]}
            for host in sorted(stats, key=lambda h: -stats[h]["evidence"])
        ]

    def targets_summary(self) -> str:
        """多目标工作区摘要文本（/targets 命令用）。"""
        stats = self.target_stats()
        if not stats:
            return "（还没有可归类的目标证据——先下达带目标的扫描任务）"
        lines = ["## 目标工作区（按证据数排序）"]
        for entry in stats[:15]:
            lines.append(
                f"- {entry['target']}: 证据 {entry['evidence']} · 发现 {entry['findings']} · 事实 {entry['facts']}"
            )
        lines.append("（授权范围见 /scope）")
        return "\n".join(lines)

    # ---------------- 序列化（会话恢复 / 跨会话续挖） ----------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence": [
                {
                    "id": e.id, "tool": e.tool, "arguments": e.arguments,
                    "content": e.content, "summary": e.summary, "preview": e.preview,
                    "pinned": e.pinned, "digest": e.digest, "size": e.size, "ts": e.ts,
                }
                for e in self.evidence
            ],
            "pinned_facts": self.pinned_facts,
            "fact_sources": self._fact_sources,
            "findings": self.findings,
            "tool_health": self.tool_health,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentMemory":
        mem = cls()
        for item in data.get("evidence", []):
            try:
                rec = EvidenceRecord(
                    id=item["id"], tool=item["tool"],
                    arguments=item.get("arguments", {}),
                    content=item.get("content", ""),
                    summary=item.get("summary", ""),
                    preview=item.get("preview", ""),
                    pinned=item.get("pinned", []),
                    digest=item.get("digest", ""),
                    size=item.get("size", 0),
                    ts=item.get("ts", 0.0),
                )
                mem.evidence.append(rec)
                mem._seen_digests[rec.digest] = rec.id
            except (KeyError, TypeError):
                continue
        mem.pinned_facts = [f for f in data.get("pinned_facts", []) if isinstance(f, str)]
        mem._fact_sources = {
            k: v for k, v in data.get("fact_sources", {}).items()
            if isinstance(k, str) and isinstance(v, str)
        }
        mem.findings = [
            f for f in data.get("findings", [])
            if isinstance(f, dict) and f.get("type") and f.get("value")
        ]
        mem.tool_health = {
            k: v for k, v in data.get("tool_health", {}).items()
            if isinstance(v, dict)
        }
        mem._last_evidence_count = len(mem.evidence)
        return mem

    # ---------------- 每轮注入 ----------------
    def to_prompt_block(self) -> str:
        """注入模型的"证据记忆"摘要块（VulnClaw to_prompt_summary 精简版）。"""
        parts: list[str] = []
        if self.pinned_facts:
            parts.append("## 已确认的高信号事实（pinned facts）")
            for fact in self.pinned_facts[-12:]:
                src = self._fact_sources.get(fact, "?")
                parts.append(f"- {fact}  [证据 {src}]")
        recent = self.evidence[-MAX_PREVIEW_EVIDENCE:]
        if recent:
            parts.append("## 近期工具证据（完整原文可用 evidence_view 回查）")
            for item in recent:
                parts.append(f"- {item.id} {item.tool}: {one_line(item.summary, 140)}")
        if not parts:
            return ""
        return "\n".join(parts)

    def reset(self) -> None:
        self.__init__()
