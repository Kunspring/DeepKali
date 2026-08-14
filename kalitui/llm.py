"""LLM 客户端 + 工具调用循环（OpenAI 兼容 API：DeepSeek / OpenAI / Ollama / 任意网关）。

Agent 一次 turn 的流程：
  user 消息 → API(带工具) → 若返回 tool_calls → 逐个执行 → 结果回填 → 循环
                         → 否则 → 最终文本流式返回给 UI
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Awaitable, Callable

import httpx

from .prompts import build_system_prompt
from .tools import TOOL_SCHEMAS, Executor, NeedsApproval, ToolError, format_tool_result

# 事件回调：dict，type ∈ thinking | tool_start | tool_result | token | done | error
EventCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


class LLMError(Exception):
    pass


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
        self.messages: list[dict[str, Any]] = []
        self._client: httpx.AsyncClient | None = None
        # 深度定制工具：schema 合并 + 执行器注册 + 按需 lore
        from .profiles import all_schemas, register_extensions

        self.tools = [*TOOL_SCHEMAS, *all_schemas()]
        register_extensions(self.executor)

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
        for _round in range(self.max_tool_rounds):
            await self._emit({"type": "thinking"})
            resp = await self._request()
            msg = resp["message"]
            self.messages.append(msg)

            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                return msg.get("content") or ""

            for call in tool_calls:
                fn = call.get("function", {})
                name = fn.get("name", "")
                try:
                    arguments = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    arguments = {"_raw": fn.get("arguments")}
                call_id = call.get("id", f"call_{_round}_{name}")

                await self._emit({"type": "tool_start", "name": name, "arguments": arguments})
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

        raise LLMError(f"工具循环超过 {self.max_tool_rounds} 轮，已停止")

    # ---------------- 请求 ----------------
    def _system_prompt(self) -> str:
        from .profiles import inventory, lore_for

        dynamic = lore_for(self.messages)
        extra = "\n\n".join(
            part for part in (inventory(), dynamic, self.extra_system_prompt) if part
        )
        return build_system_prompt(self.user, self.workdir, extra)

    async def _request(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self._system_prompt()},
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

    # ---------------- 重置会话 ----------------
    def reset(self) -> None:
        self.messages.clear()
