#!/usr/bin/env python3
"""zen-proxy: OpenAI 兼容 → OpenCode Zen (Anthropic 兼容) 转换代理。

背景：OpenCode Zen 网关对 deepseek-v4-flash-free 的 OpenAI 端点返回 503，
Anthropic 端点（/zen/v1/messages）可用但 tools 参数路由损坏。
方案：剥离 tools 参数，把工具 schema 注入 system 提示，要求模型输出
单行 JSON（{"tool": name, "arguments": {...}}），代理解析后转成标准
OpenAI tool_calls 响应；工具结果以 user 消息回传。非流式。
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

UPSTREAM = "https://opencode.ai/zen/v1/messages"
API_KEY = sys.argv[1] if len(sys.argv) > 1 else ""
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8888
MODEL = "deepseek-v4-flash-free"

_client = httpx.Client(timeout=180)

_TOOL_PROMPT = """
你可以调用以下工具。当需要调用工具时，只输出一行 JSON（不要 Markdown、不要其他文字），格式：
{{"tool": "<工具名>", "arguments": {{<参数 JSON>}}}}

可用工具：
%%TOOLS%%

如果不需要工具，正常回复即可。
"""

_JSON_RE = re.compile(r'\{[^{}]*"tool"\s*:\s*"[^"]+"[^{}]*\}')


def _build_system(tools: list[dict], original_system: str) -> str:
    lines = []
    for t in tools:
        f = t.get("function", {})
        lines.append(json.dumps({
            "name": f.get("name", ""),
            "description": f.get("description", ""),
            "parameters": f.get("parameters", {"type": "object"}),
        }, ensure_ascii=False))
    return original_system + "\n" + _TOOL_PROMPT.replace("%%TOOLS%%", "\n".join(lines))


def _to_anthropic(payload: dict, has_tools: bool) -> dict:
    system_parts: list[str] = []
    msgs: list[dict] = []
    for m in payload.get("messages", []):
        role = m.get("role")
        content = m.get("content", "")
        if role == "system":
            system_parts.append(str(content))
            continue
        msgs.append({
            "role": "user" if role == "user" else "assistant",
            "content": [{"type": "text", "text": str(content)}],
        })
    out: dict = {
        "model": payload.get("model", MODEL),
        "max_tokens": payload.get("max_tokens", 4096),
        "messages": msgs,
    }
    tools = payload.get("tools") or []
    if has_tools and tools:
        system_parts.append(_TOOL_PROMPT.replace(
            "%%TOOLS%%",
            "\n".join(json.dumps({
                "name": t.get("function", {}).get("name", ""),
                "description": t.get("function", {}).get("description", ""),
                "parameters": t.get("function", {}).get("parameters", {"type": "object"}),
            }, ensure_ascii=False) for t in tools)))
    if system_parts:
        out["system"] = "\n".join(system_parts)
    if payload.get("temperature") is not None:
        out["temperature"] = payload["temperature"]
    return out


def _parse_tool_json(text: str) -> dict | None:
    """从文本里找工具调用 JSON（整行或 JSON 块）。"""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("```"):
            line = line.strip("`")
            if line.startswith("json"):
                line = line[4:].strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(d, dict) and "tool" in d:
                return d
    m = _JSON_RE.search(text)
    if m:
        try:
            d = json.loads(m.group(0))
            if isinstance(d, dict) and "tool" in d:
                return d
        except json.JSONDecodeError:
            pass
    return None


def _to_openai(aresp: dict, model: str, has_tools: bool) -> dict:
    content_blocks = aresp.get("content", [])
    text = "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text")
    msg: dict = {"role": "assistant", "content": text}
    finish = "stop"
    if has_tools:
        call = _parse_tool_json(text)
        if call:
            name = str(call.get("tool", ""))
            args = call.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"value": args}
            msg["tool_calls"] = [{
                "id": f"call_{uuid.uuid4().hex[:12]}",
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(args, ensure_ascii=False)},
            }]
            finish = "tool_calls"
            msg["content"] = None
    usage = aresp.get("usage", {})
    return {
        "id": aresp.get("id", f"chatcmpl-{uuid.uuid4().hex[:16]}"),
        "object": "chat.completion",
        "created": int(aresp.get("created_at", 0)),
        "model": model,
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": {
            "prompt_tokens": usage.get("input_tokens", 0),
            "completion_tokens": usage.get("output_tokens", 0),
            "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
        },
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        if not self.path.endswith("/chat/completions"):
            self._json({"error": "not found"}, 404)
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self._json({"error": "bad json"}, 400)
            return
        has_tools = bool(payload.get("tools"))
        try:
            resp = _client.post(
                UPSTREAM,
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json=_to_anthropic(payload, has_tools),
            )
            body = resp.json()
        except Exception as e:
            self._json({"error": f"upstream error: {e}"}, 502)
            return
        if resp.status_code != 200:
            self._json({"error": body.get("error", body)}, resp.status_code)
            return
        self._json(_to_openai(body, payload.get("model", MODEL), has_tools))

    def _json(self, obj: dict, code: int = 200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"zen-proxy listening on 127.0.0.1:{PORT} -> {UPSTREAM} ({MODEL})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
