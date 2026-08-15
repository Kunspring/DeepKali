"""LLM 客户端 + 工具调用循环（OpenAI 兼容 API：DeepSeek / OpenAI / Ollama / 任意网关）。

Agent 一次 turn 的流程：
  user 消息 → API(带工具) → 若返回 tool_calls → 逐个执行 → 结果回填 → 循环
                         → 否则 → 最终文本流式返回给 UI

自 VulnClaw 移植的精华：
- 证据记忆（AgentMemory）：工具输出完整存 raw，上下文只注入高信号预览，
  大输出不反复污染上下文；pinned facts 长期可见
- 完成协议：FINAL: / NO_PATH: / ASK_USER: 标记 + 证据级反幻觉闸门——
  声称的 flag/结论必须逐字符出现在真实工具输出中，否则拒绝并回灌继续
- 近成功防误停：高信号证据未耗尽时，拒绝模型过早 NO_PATH 判死
- 轻量纠偏层：重复调用检测、工具健康跟踪（degraded）、stall guard
- Reflexion 反思升级：连续失败后按 L0-L4 渐进升级提示换思路
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Awaitable, Callable

import httpx

from .evidence import AgentMemory, extract_flags
from .prompts import build_system_prompt
from .tools import TOOL_SCHEMAS, Executor, NeedsApproval, ToolError, format_tool_result

# 事件回调：dict，type ∈ thinking | tool_start | tool_result | token | done | error
#           | evidence_gate | correction | report
EventCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


class LLMError(Exception):
    pass


# ---------------------------------------------------------------------------
# 完成协议与闸门（VulnClaw solver 精华移植）
# ---------------------------------------------------------------------------
_FINAL_MARKERS = ("FINAL:", "Final:", "final:", "DONE:", "[DONE]", "完成：", "最终结果：")
_NO_PATH_MARKERS = ("NO_PATH:", "No viable path:", "无法继续：", "没有可继续验证的路径：")
_ASK_MARKERS = ("ASK_USER:", "Ask user:", "ask_user:", "需要用户：")
_EVIDENCE_ID_RE = re.compile(r"\be\d{3,}\b", re.IGNORECASE)

# 真正的用户阻塞点（这些才值得中断取证去提问；VulnClaw _ASK_TRUE_BLOCKER_MARKERS 移植）
_TRUE_BLOCKER_MARKERS = (
    "scope", "authorization", "permission", "credential", "account",
    "login", "mfa", "otp", "target", "out of scope",
    "授权", "范围", "凭证", "账号", "密码", "目标", "越权",
)

# Bounty 报告：按发现类型的修复建议（确定性生成，不请求 LLM）
_FIX_SUGGESTIONS = {
    "flag": "CTF/凭证类：轮换暴露的密钥与口令，删除调试后门；若是靶场目标则记录即可",
    "cve": "升级受影响组件到修复版本；无法升级时用 WAF/ACL 缓解并确认资产暴露面",
    "unauthorized": "未授权访问/信息泄露：收紧访问控制（认证+鉴权+网络 ACL），"
                    "关闭 actuator/heapdump 等调试端点，暴露面最小化",
    "vuln_marker": "结合证据定位漏洞入口（注入点/未授权接口），修复输入校验与访问控制",
    "http_error": "检查服务配置与错误处理：隐藏堆栈/版本信息，5xx 应有兜底页与日志",
}

# 近成功闸门：出现这些高信号锚点说明探索还未穷尽（VulnClaw _NEAR_MISS_EVIDENCE_MARKERS 精简）
_NEAR_MISS_MARKERS = (
    "source", "sink", "highlight_file", "show_source", "form", "input",
    "param", "parameter", "api", "endpoint", "request=", "headers=",
    "cookies=", "body=", "sql", "select", "union", "where", "eval",
    "assert", "system(", "exec(", "shell_exec", "unserialize",
    "$_get", "$_post", "$_cookie", "admin", "token", "secret", "proof",
)
# NO_PATH 提前判死的典型措辞（VulnClaw _NO_PATH_PREMATURE_MARKERS 精简）
_PREMATURE_NO_PATH_MARKERS = (
    "same-body", "same body", "no visible", "no response", "no difference",
    "no effect", "does not trigger", "failed to trigger", "payload",
    "无回显", "没有回显", "未触发", "无差异", "响应相同", "无法触发",
)


def _after_marker(text: str, markers: tuple[str, ...]) -> str:
    for marker in markers:
        index = text.find(marker)
        if index >= 0:
            return text[index + len(marker):].strip()
    return ""


def _has_marker(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def _cited_evidence_ids(text: str) -> list[str]:
    return list(dict.fromkeys(m.lower() for m in _EVIDENCE_ID_RE.findall(text or "")))


def _goal_wants_flag(goal: str) -> bool:
    lowered = (goal or "").lower()
    return any(kw in lowered for kw in ("flag", "ctf", "getshell", "shell", "flag 文件", "拿 flag"))


class CompletionGate:
    """证据级反幻觉闸门：模型声称的结论必须能被真实证据支撑。"""

    def __init__(self, memory: AgentMemory, goal: str = "") -> None:
        self.memory = memory
        self.goal = goal

    def check(self, final_text: str) -> tuple[bool, str]:
        """返回 (通过?, 拒绝原因)。通过时拒绝原因为空。"""
        evidence_text = self.memory.evidence_text()
        cited = _cited_evidence_ids(final_text)
        known_ids = set(self.memory.evidence_ids())

        # 1. 引用未知证据 id → 拒绝
        missing = [item for item in cited if item not in known_ids]
        if missing:
            return False, f"完成结论引用了不存在的证据 id: {', '.join(missing)}"

        # 2. flag 目标：声称的 flag 必须逐字符出现在真实工具输出中
        flags_in_answer = extract_flags(final_text)
        if _goal_wants_flag(self.goal) or flags_in_answer:
            if not flags_in_answer:
                return False, "目标要求获取 flag，但最终结论没有给出任何 flag 格式的内容"
            ungrounded = [f for f in flags_in_answer if f not in evidence_text]
            if ungrounded:
                return (
                    False,
                    f"声称的 flag {ungrounded[0]} 未在真实工具输出中出现（证据闸门拒绝）"
                    "——请引用包含该 flag 的证据（evidence_list 查看），或继续探测取证。",
                )

        # 3. 无任何证据支撑的完成 → 拒绝
        if not self.memory.evidence:
            return False, "最终结论没有任何工具证据支撑"

        # 4. 引用了证据 id → 通过
        if cited:
            return True, ""

        # 5. 未引用 id：必须引用/复述证据中真实出现过的词（非 flag 目标）
        meaningful = [
            token for token in re.findall(r"[A-Za-z0-9_./:-]{5,}", final_text)
            if token.lower() in evidence_text.lower()
        ]
        if meaningful:
            return True, ""
        return False, "最终结论没有引用任何证据 id（如 e001）或复述证据中的关键内容——请基于真实工具输出总结"


class ReflexionLadder:
    """反思升级（VulnClaw ReflexionEngine L0-L4 精华移植）。"""

    LEVELS: dict[int, list[str]] = {
        0: ["直接使用原始 payload"],
        1: ["URL 编码", "关键字大小写变换", "插入空白字符"],
        2: ["双重 URL 编码", "内联注释 /*!*/", "HTML 实体编码"],
        3: ["Unicode 转义", "Hex 编码", "关键字拼接（'se'+'lect'）", "换用等价函数"],
        4: ["多层嵌套编码", "替代语法/协议", "盲打或带外（OOB）验证", "切换攻击面"],
    }

    def __init__(self) -> None:
        self.fail_count = 0
        self.failed_paths: list[str] = []

    def record_failure(self, path: str) -> None:
        self.fail_count += 1
        if path and path not in self.failed_paths:
            self.failed_paths.append(path)

    def record_success(self) -> None:
        self.fail_count = 0

    def level(self) -> int:
        return min(4, max(0, self.fail_count // 2))

    def prompt_block(self) -> str:
        if self.fail_count < 2:
            return ""
        level = self.level()
        tips = "、".join(self.LEVELS[level])
        return (
            f"[反思升级 L{level}] 已连续失败 {self.fail_count} 次"
            f"（失败路径: {', '.join(self.failed_paths[-4:]) or '无'}）。"
            "停止盲目重试，先审查假设；如需继续攻击，可考虑：" + tips + "。"
        )


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------
class Agent:
    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        temperature: float = 0.2,
        max_tokens: int = 4096,
        timeout: float = 120.0,
        workdir: str = "",
        user: str = "",
        extra_system_prompt: str = "",
        executor: Executor | None = None,
        emit: EventCallback | None = None,
        max_tool_rounds: int = 25,
        auto_report: bool = True,
        resume_path: str | None = None,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.workdir = workdir
        self.user = user
        self.extra_system_prompt = extra_system_prompt
        self.executor = executor or Executor()
        self.emit = emit or (lambda _e: None)
        self.max_tool_rounds = max_tool_rounds
        self.auto_report = auto_report
        self.resume_path = resume_path
        self.messages: list[dict[str, Any]] = []
        self.memory = AgentMemory()
        self.reflexion = ReflexionLadder()
        self._client: httpx.AsyncClient | None = None
        # 深度定制工具：schema 合并 + 执行器注册 + 按需 lore
        from .profiles import all_schemas, register_extensions

        self.tools = [*TOOL_SCHEMAS, *all_schemas()]
        register_extensions(self.executor)
        self._stall_rounds = 0
        self._last_goal = ""
        self._gate_depth = 0

    async def _emit(self, event: dict[str, Any]) -> None:
        result = self.emit(event)
        if result is not None:
            await result

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(base_url=self.base_url, headers=headers, timeout=self.timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ---------------- 单轮对话（含工具循环） ----------------
    async def chat(self, user_message: str) -> str:
        self.messages.append({"role": "user", "content": user_message})
        self._last_goal = user_message
        # 每轮重置闸门深度：跨消息不累积（防误触发"多次回灌停止"）
        self._gate_depth = 0
        try:
            return await self._chat_impl()
        finally:
            pass

    async def _chat_impl(self) -> str:
        for _round in range(self.max_tool_rounds):
            await self._emit({"type": "thinking"})
            resp = await self._request()
            msg = resp["message"]
            self.messages.append(msg)

            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                return await self._finalize(msg.get("content") or "")

            for call in tool_calls:
                fn = call.get("function", {})
                name = fn.get("name", "")
                try:
                    arguments = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    arguments = {"_raw": fn.get("arguments")}
                call_id = call.get("id", f"call_{_round}_{name}")

                await self._emit({"type": "tool_start", "name": name, "arguments": arguments})
                output, ok = await self._execute_tool(name, arguments)
                self.messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": format_tool_result(name, arguments, output),
                    }
                )
                await self._emit(
                    {"type": "tool_result", "name": name, "ok": ok, "output": output}
                )
            self._maybe_save_state()

        raise LLMError(f"工具循环超过 {self.max_tool_rounds} 轮，已停止")

    async def _execute_tool(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        """执行工具 + 证据记录 + 纠偏层（VulnClaw correction_layer 精华）。"""
        # 证据回查工具：直接查 AgentMemory（不经过 executor，也不重复记录）
        if name == "evidence_list":
            return self.memory.list_summary(), True
        if name == "evidence_search":
            query = str(arguments.get("query") or "")
            limit = max(1, min(int(arguments.get("limit") or 6), 20))
            return self.memory.search(query, limit=limit), True
        if name == "evidence_view":
            eid = str(arguments.get("evidence_id") or "")
            max_chars = max(500, int(arguments.get("max_chars") or 8000))
            return self.memory.view(eid, max_chars=max_chars), True
        if name == "attack_surface":
            return self.memory.attack_surface_summary(), True

        hints: list[str] = []
        # 重复调用 / 健康降级提示
        hint = self.memory.repeat_hint(name, arguments)
        if hint:
            hints.append(hint)
        health = self.memory.health_hint(name)
        if health:
            hints.append(health)
        if hints:
            await self._emit({"type": "correction", "hints": hints})

        t0 = time.monotonic()
        try:
            output = await self.executor.execute(name, arguments)
            ok = True
        except NeedsApproval as e:
            output = f"（{e.reason}，命令未执行）"
            ok = True  # 已作为结果回传，不算错误
        except ToolError as e:
            output = str(e)
            ok = False
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            output = f"未知错误: {e}"
            ok = False
        duration_ms = int((time.monotonic() - t0) * 1000)

        # ---- 证据记录 ----
        if ok:
            self.reflexion.record_success()
            rec = self.memory.record(name, arguments, output)
            if hints:
                output = output + "\n\n" + "\n".join(hints)
            # 大输出：active context 只回填高信号预览，raw 全文存证据
            if len(output) > 6000:
                preview = rec.preview
                if hints:
                    preview = preview + "\n\n" + "\n".join(hints)
                output = (
                    f"{preview}\n\n"
                    f"[完整输出 {rec.size} 字符已存为证据 {rec.id}；"
                    "需要更多细节用 evidence_view 查看]"
                )
        else:
            self.reflexion.record_failure(str(arguments.get("command") or name))
            self.memory.record_failure(name, arguments, output)
            if duration_ms >= 15_000:
                output += f"\n[纠偏] 该工具耗时 {duration_ms}ms，可能超时或网络问题。"
        return output, ok

    # ---------------- 完成协议 + 证据闸门 ----------------
    async def _finalize(self, text: str) -> str:
        """最终文本处理：FINAL/NO_PATH 协议 + 证据闸门 + 自动报告。"""
        cleaned = (text or "").strip()

        # 0. ASK_USER 先处理：无证据也剥离标记；有高信号且非真阻塞 → 拒绝过早提问
        if _has_marker(cleaned, _ASK_MARKERS):
            question = _after_marker(cleaned, _ASK_MARKERS)
            if not question:
                question = cleaned
                for marker in _ASK_MARKERS:
                    question = question.replace(marker, "").strip()
            low_q = question.lower()
            real_blocker = any(m in low_q for m in _TRUE_BLOCKER_MARKERS)
            reason = self._near_miss_reason()
            if reason and not real_blocker:
                await self._emit({"type": "evidence_gate", "verdict": "reject", "reason": reason})
                self.messages.append({
                    "role": "user",
                    "content": (
                        "[过早提问闸门] 你的提问被拒绝：证据中仍有未耗尽的高信号锚点"
                        f"（{reason}）。先继续取证，只有真正需要用户提供的信息"
                        "（授权/凭证/目标选择等）才提问。"
                    ),
                })
                return await self._retry_after_gate()
            return question  # 真正阻塞或无线索：剥离标记，把问题带给用户

        # 无证据的普通回答：直接返回（保持向后兼容，普通闲聊不拦）
        if not self.memory.evidence:
            return cleaned

        # 1. 近成功防误停：模型想提前判死，但高信号证据未耗尽 → 拒绝
        if _has_marker(cleaned, _NO_PATH_MARKERS):
            no_path_text = _after_marker(cleaned, _NO_PATH_MARKERS)
            reason = self._near_miss_reason()
            premature = any(m in (no_path_text or "").lower() for m in _PREMATURE_NO_PATH_MARKERS)
            if reason and (premature or not _looks_exhaustive(no_path_text)):
                await self._emit({"type": "evidence_gate", "verdict": "reject", "reason": reason})
                self.messages.append({
                    "role": "user",
                    "content": (
                        "[近成功闸门] 你的 NO_PATH 结论被拒绝：证据中仍有未耗尽的高信号锚点"
                        f"（{reason}）。请先验证这些锚点，或基于证据明确排除它们，再决定是否停止。"
                    ),
                })
                if self._gate_depth >= 2:
                    # 防递归：近成功闸门同样受深度上限约束
                    return (
                        cleaned + "\n\n"
                        "（注：近成功闸门多次拒绝 NO_PATH 结论，已停止回灌；"
                        "请人工核对剩余锚点是否值得继续验证。）"
                    )
                return await self._retry_after_gate()

        # 2. FINAL / flag：证据闸门校验
        wants_gate = _has_marker(cleaned, _FINAL_MARKERS) or bool(extract_flags(cleaned))
        if wants_gate:
            gate = CompletionGate(self.memory, goal=self._last_goal)
            ok, reject_reason = gate.check(cleaned)
            if not ok:
                await self._emit({"type": "evidence_gate", "verdict": "reject", "reason": reject_reason})
                self.messages.append({
                    "role": "user",
                    "content": (
                        f"[证据闸门] 完成结论被拒绝：{reject_reason}。"
                        "继续收集证据或修正结论，用 evidence_list 查看已有证据。"
                    ),
                })
                if self._gate_depth >= 2:
                    # 防递归：多次被拒后不再回灌，如实返回当前结论
                    return (
                        cleaned + "\n\n"
                        f"（注：结论未通过证据闸门：{reject_reason}。已多次尝试仍无法通过，已停止回灌。）"
                    )
                return await self._retry_after_gate()
            await self._emit({"type": "evidence_gate", "verdict": "pass"})

        # 3. 自动报告
        if self.auto_report:
            try:
                path = self.write_report(cleaned)
                await self._emit({"type": "report", "path": path})
            except OSError as e:
                await self._emit({"type": "error", "message": f"报告写入失败: {e}"})
        return cleaned

    async def _retry_after_gate(self) -> str:
        """闸门拒绝后继续工具循环（最多再跑几轮取证）。"""
        self._gate_depth += 1
        for _round in range(4):
            await self._emit({"type": "thinking"})
            resp = await self._request()
            msg = resp["message"]
            self.messages.append(msg)
            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                return await self._finalize(msg.get("content") or "")
            for call in tool_calls:
                fn = call.get("function", {})
                name = fn.get("name", "")
                try:
                    arguments = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    arguments = {"_raw": fn.get("arguments")}
                await self._emit({"type": "tool_start", "name": name, "arguments": arguments})
                output, ok = await self._execute_tool(name, arguments)
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": call.get("id", f"call_r{_round}_{name}"),
                    "content": format_tool_result(name, arguments, output),
                })
                await self._emit({"type": "tool_result", "name": name, "ok": ok, "output": output})
        return "（多次尝试后仍未通过证据闸门，已停止；请人工检查目标与证据。）"

    def _near_miss_reason(self) -> str:
        """从 pinned facts / 近期证据找未耗尽的高信号锚点。"""
        samples: list[str] = []
        for fact in self.memory.pinned_facts[-12:]:
            if any(m in fact.lower() for m in _NEAR_MISS_MARKERS):
                samples.append(fact)
        if not samples:
            for item in self.memory.evidence[-6:]:
                body = (item.summary + "\n" + item.preview[:1200]).lower()
                if any(m in body for m in _NEAR_MISS_MARKERS):
                    samples.append(f"证据 {item.id}: {item.summary}")
        return "; ".join(dict.fromkeys(samples[:3]))

    # ---------------- 报告生成（VulnClaw 自动复盘报告精华） ----------------
    def _impact_level(self) -> str:
        """基于发现类型确定性评估影响等级（Bounty 提交模板用）。"""
        types = {f["type"] for f in self.memory.findings}
        if "flag" in types:
            return "高（CTF/凭证泄露级）"
        if "cve" in types:
            return "中-高（已知 CVE，需确认资产暴露面）"
        if "unauthorized" in types:
            return "中-高（未授权访问/信息泄露，需确认暴露面）"
        if "vuln_marker" in types:
            return "中（存在漏洞特征标记，需验证可利用性）"
        if "http_error" in types:
            return "低（服务异常/错误暴露）"
        return "信息（未发现明确漏洞信号）"

    def _reproduction_steps(self) -> list[str]:
        """从证据链生成复现步骤（按时间序提取关键工具调用，确定性生成）。"""
        steps: list[str] = []
        for item in self.memory.evidence:
            try:
                arg_str = json.dumps(item.arguments, ensure_ascii=False)
            except (TypeError, ValueError):
                arg_str = str(item.arguments)
            arg_str = arg_str[:200]
            steps.append(f"执行 `{item.tool}`：{arg_str} → {item.summary}（证据 {item.id}）")
        return steps

    def write_report(self, final_answer: str = "", path: str | None = None) -> str:
        """基于证据确定性生成 Markdown 复盘报告（不请求 LLM）。

        同时保存 findings.json（白帽提交/整理发现用）。
        """
        import os
        from datetime import datetime

        if path is None:
            out_dir = os.path.join(self.workdir or ".", "kalitui-reports")
            os.makedirs(out_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            path = os.path.join(out_dir, f"report-{ts}.md")

        goal = self._last_goal or "（无）"
        lines = [
            "# KaliTUI 任务复盘报告",
            "",
            f"- 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"- 模型: {self.model}",
            f"- 任务目标: {goal}",
            f"- 影响等级: **{self._impact_level()}**",
            "",
            "## 任务结论",
            "",
            final_answer.strip() or "（模型未给出结论）",
            "",
        ]

        # 发现汇总（白帽提交要点，按严重度排序）
        if self.memory.findings:
            from .evidence import sort_findings

            lines.append(f"## 发现汇总（{len(self.memory.findings)} 条，按严重度）")
            lines.append("")
            for f in sort_findings(self.memory.findings):
                src = f"（证据 {f['evidence']}）" if f.get("evidence") else ""
                lines.append(f"- **{f['type']}**: `{f['value']}` {src}")
            lines.append("")

        # 侦察时间线（白帽复盘视角：什么时间跑了什么）
        timeline = self.memory.evidence[:10]
        if timeline:
            from datetime import datetime as _dt

            lines.append("## 侦察时间线（最早 10 步）")
            lines.append("")
            for item in timeline:
                try:
                    t = _dt.fromtimestamp(item.ts).strftime("%H:%M:%S")
                except (TypeError, ValueError, OSError):
                    t = "?"
                args = item.arguments or {}
                brief = str(args.get("command") or args.get("url") or args.get("target") or
                            args.get("path") or args.get("keyword") or "")
                if len(brief) > 80:
                    brief = brief[:80] + "…"
                lines.append(f"- `{t}` **{item.tool}** {brief} → [{item.id}] {item.summary[:60]}")
            lines.append("")
            lines.append("### 修复建议（按发现类型）")
            lines.append("")
            for f in self.memory.findings:
                lines.append(f"- `{f['value']}` → {_FIX_SUGGESTIONS.get(f['type'], '人工评估后确认处置')}")
            lines.append("")

        # 复现步骤（基于证据时间序确定性生成，不请求 LLM）
        steps = self._reproduction_steps()
        if steps:
            lines.append("## 复现步骤")
            lines.append("")
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        # 后续建议（白帽下一步：基于未探索的高信号方向，确定性生成）
        missing = self.memory.attack_surface_gaps()
        if missing:
            lines.append("## 后续建议")
            lines.append("")
            lines.append("证据中尚未出现以下高信号方向（若任务未完成，优先探索）：")
            lines.append("")
            lines.append("- " + "\n- ".join(missing))
            lines.append("")

        lines.append(f"## 工具调用与证据（共 {len(self.memory.evidence)} 条）")
        lines.append("")
        for item in self.memory.evidence:
            lines.append(f"### {item.id} · {item.tool}")
            try:
                arg_str = json.dumps(item.arguments, ensure_ascii=False)[:400]
            except (TypeError, ValueError):
                arg_str = str(item.arguments)[:400]
            lines.append(f"- 参数: `{arg_str}`")
            lines.append(f"- 摘要: {item.summary}")
            lines.append("")
            lines.append("```")
            lines.append(item.content[:4000])
            if len(item.content) > 4000:
                lines.append(f"...（原文 {item.size} 字符，已截断）")
            lines.append("```")
            lines.append("")
        if self.memory.pinned_facts:
            lines.append("## 高信号事实")
            lines.append("")
            for fact in self.memory.pinned_facts:
                lines.append(f"- {fact}")
            lines.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        # 结构化发现持久化（同目录 findings.json，方便后续整理/提交）
        try:
            findings_path = os.path.splitext(path)[0] + ".findings.json"
            with open(findings_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "goal": goal,
                        "generated": datetime.now().isoformat(),
                        "findings": self.memory.findings,
                        "evidence_count": len(self.memory.evidence),
                    },
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
        except OSError:
            pass  # 报告已保存，findings.json 失败不影响主流程
        return path

    # ---------------- 会话状态保存/恢复（白帽跨会话续挖） ----------------
    def state_dict(self) -> dict[str, Any]:
        """序列化完整会话状态（对话历史 + 证据记忆 + 反思状态）。"""
        return {
            "messages": self.messages,
            "memory": self.memory.to_dict(),
            "reflexion": {
                "fail_count": self.reflexion.fail_count,
                "failed_paths": self.reflexion.failed_paths,
            },
            "goal": self._last_goal,
        }

    def restore_state(self, data: dict[str, Any]) -> None:
        """恢复会话状态；坏数据静默忽略，不抛异常。"""
        if not isinstance(data, dict):
            return
        messages = data.get("messages")
        if isinstance(messages, list):
            self.messages = [
                m for m in messages
                if isinstance(m, dict) and isinstance(m.get("role"), str)
            ]
        memory = data.get("memory")
        if isinstance(memory, dict):
            self.memory = AgentMemory.from_dict(memory)
        refl = data.get("reflexion")
        if isinstance(refl, dict):
            self.reflexion.fail_count = max(0, int(refl.get("fail_count") or 0))
            self.reflexion.failed_paths = [
                p for p in refl.get("failed_paths", []) if isinstance(p, str)
            ]
        goal = data.get("goal")
        if isinstance(goal, str):
            self._last_goal = goal

    def save_state(self) -> bool:
        """保存状态到 resume_path（失败静默，返回是否成功）。"""
        if not self.resume_path:
            return False
        try:
            import os

            path = self.resume_path
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.state_dict(), f, ensure_ascii=False)
            return True
        except OSError:
            return False

    def _maybe_save_state(self) -> None:
        """工具循环每轮结束后自动保存（覆盖写，供中断后 /resume）。"""
        if self.resume_path:
            self.save_state()

    # ---------------- 请求 ----------------
    def _system_prompt(self, extra: str = "") -> str:
        from .profiles import inventory, lore_for

        dynamic = lore_for(self.messages)
        parts = [inventory(), dynamic, self.extra_system_prompt]
        if extra:
            parts.append(extra)
        joined = "\n\n".join(part for part in parts if part)
        return build_system_prompt(self.user, self.workdir, joined)

    def _context_blocks(self) -> str:
        """每轮注入的记忆/纠偏块（VulnClaw 上下文策略精华）。

        拼进 system prompt 而非追加 user 消息：不污染真实对话历史，
        模型看到的始终是当前最新的证据快照。
        """
        blocks: list[str] = []
        mem_block = self.memory.to_prompt_block()
        if mem_block:
            blocks.append(mem_block)
        refl = self.reflexion.prompt_block()
        if refl:
            blocks.append(refl)
        stall = self.memory.stall_hint()
        if stall:
            self._stall_rounds += 1
            blocks.append(stall)
        else:
            self._stall_rounds = 0
        return "\n\n".join(blocks)

    # ---------------- 上下文预算（VulnClaw context_budget 精华移植） ----------------
    def _estimate_tokens(self) -> int:
        """粗略估算 messages 的 token 占用（中文/英文混合粗估，够用即可）。

        按条数压缩不精确（一条大输出顶几十条小消息），token 估算
        让压缩以「实际占用」为准，兼容不同长度的工具输出。
        """
        total = 0
        for m in self.messages:
            total += 4  # 每条消息的角色/元数据开销
            content = m.get("content") or ""
            if isinstance(content, str):
                total += len(content) // 2  # 中文约 1 token/字，英文约 2 字/token
            else:
                total += 200  # 非文本内容保守估
            total += 60 * len(m.get("tool_calls") or [])
        return total

    def _compress_one_round(self) -> bool:
        """删除最早的一整轮 assistant(tool_calls)+tool 消息。返回是否删了。"""
        i = 1  # messages[0] 是任务目标，保留
        while i < len(self.messages):
            msg = self.messages[i]
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                j = i + 1
                while j < len(self.messages) and self.messages[j].get("role") == "tool":
                    j += 1
                del self.messages[i:j]
                return True
            i += 1
        return False

    def _compress_messages(self, limit: int = 50, token_limit: int = 60000) -> int:
        """消息超限时从最早开始整轮裁剪（assistant+tool 对），保留任务目标。

        两个阈值：条数超限先压到 limit；token 仍超 token_limit 继续压。
        裁剪必须按「assistant(tool_calls) + 跟随的 tool 消息」整组进行——
        孤儿 tool 消息会破坏 OpenAI 兼容 API 的关联校验。
        被裁细节已沉淀在证据记忆里，模型可通过 evidence_* 回查，信息不丢失。
        """
        removed = 0
        if len(self.messages) > limit:
            while len(self.messages) > limit and self._compress_one_round():
                removed += 1
        while self._estimate_tokens() > token_limit and self._compress_one_round():
            removed += 1
        if removed:
            self.messages.insert(
                1,
                {
                    "role": "user",
                    "content": (
                        f"[上下文压缩] 较早的 {removed} 轮工具调用已压缩进证据记忆"
                        "（evidence_list / evidence_view / evidence_search 可回查原文）。"
                        "基于已有证据继续任务，不要重复执行已做过的操作。"
                    ),
                },
            )
        return removed

    async def _request(self) -> dict[str, Any]:
        # 上下文预算：长会话先裁剪最早轮次，防 API 上下文超限
        self._compress_messages()
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self._system_prompt(self._context_blocks())},
                *self.messages,
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False,
            "tools": self.tools,
        }
        try:
            r = await self.client.post("/chat/completions", json=payload)
        except httpx.HTTPError as e:
            raise LLMError(f"请求 API 失败: {e}") from e
        if r.status_code != 200:
            detail = r.text[:500]
            raise LLMError(f"API 返回 {r.status_code}: {detail}")
        data = r.json()
        choices = data.get("choices") or []
        if not choices:
            raise LLMError(f"API 响应异常: {str(data)[:300]}")
        return choices[0]

    # ---------------- 发现导出（CSV，白帽提交/整理用） ----------------
    def _finding_target(self, finding: dict) -> str:
        """从发现对应的证据 arguments 中提取目标（target/url/host/rhost/ip）。"""
        eid = finding.get("evidence", "")
        if not eid:
            return ""
        rec = self.memory._get(eid)
        if rec is None:
            return ""
        for key in ("target", "url", "host", "rhost", "ip"):
            value = rec.arguments.get(key)
            if value:
                return str(value)
        return ""

    def export_findings_csv(self, path: str | None = None) -> str:
        """把 findings 导出为 CSV（按严重度排序，utf-8-sig 兼容 Excel）。"""
        import csv
        import os

        from .evidence import severity_of, sort_findings

        if path is None:
            out_dir = os.path.join(self.workdir or ".", "kalitui-reports")
            os.makedirs(out_dir, exist_ok=True)
            path = os.path.join(out_dir, "findings.csv")
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["severity", "type", "value", "target", "evidence"])
            for finding in sort_findings(self.memory.findings):
                writer.writerow([
                    severity_of(finding),
                    finding["type"],
                    finding["value"],
                    self._finding_target(finding),
                    finding.get("evidence", ""),
                ])
        return path

    # ---------------- 重置会话 ----------------
    def reset(self) -> None:
        self.messages.clear()
        self.memory.reset()
        self.reflexion = ReflexionLadder()
        self._stall_rounds = 0
        self._last_goal = ""


def _looks_exhaustive(no_path_text: str) -> bool:
    """NO_PATH 理由看起来已穷尽验证（排除锚点后放行）。"""
    lowered = (no_path_text or "").lower()
    exhaustive = ("exhausted", "verified", "checked", "已穷尽", "已验证", "已排除", "全部验证")
    premature = ("payload", "no visible", "no response", "无回显", "没有回显", "未触发", "无差异")
    has_exhaustive = any(m in lowered for m in exhaustive)
    has_premature = any(m in lowered for m in premature)
    return has_exhaustive and not has_premature
