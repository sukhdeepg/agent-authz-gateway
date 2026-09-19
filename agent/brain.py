"""The agent's decision-maker.

"Brain" is deliberately a small interface with one method: given the
conversation so far and the tools available, decide what to do next. Either
call a tool, or answer.

Two implementations:

* `OllamaBrain` runs a real open-weights model locally. This is the one that
  matters for the demo, because a real model really can be talked into things
  by text it reads.
* `ScriptedBrain` replays a fixed list of decisions. Tests and CI use it so the
  suite is deterministic and needs no model installed.

The gateway does not care which one is driving, and that is the point. A
gateway that only holds when the model is well-behaved would be worthless.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx
from mcp.types import Tool

OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "qwen2.5"


@dataclass
class ToolCall:
    """The model wants to invoke a tool."""

    name: str
    arguments: dict[str, Any]


@dataclass
class Reply:
    """The model is done and has an answer."""

    text: str


Decision = ToolCall | Reply


class Brain(Protocol):
    async def decide(self, messages: list[dict[str, Any]], tools: list[Tool]) -> Decision: ...


def _to_ollama_tools(tools: list[Tool]) -> list[dict[str, Any]]:
    """Translate MCP tool definitions into the shape Ollama expects."""
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description or "",
                "parameters": tool.input_schema or {"type": "object", "properties": {}},
            },
        }
        for tool in tools
    ]


@dataclass
class OllamaBrain:
    """A local open-weights model, reached over Ollama's HTTP API."""

    model: str = DEFAULT_MODEL
    url: str = OLLAMA_URL
    timeout: float = 120.0

    async def decide(self, messages: list[dict[str, Any]], tools: list[Tool]) -> Decision:
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": _to_ollama_tools(tools),
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json=payload)
            response.raise_for_status()
            message = response.json()["message"]

        tool_calls = message.get("tool_calls") or []
        if tool_calls:
            function = tool_calls[0]["function"]
            arguments = function.get("arguments") or {}
            return ToolCall(name=function["name"], arguments=dict(arguments))
        return Reply(text=message.get("content", ""))


@dataclass
class ScriptedBrain:
    """Replays a fixed sequence of decisions. For tests and offline demos."""

    decisions: list[Decision] = field(default_factory=list)
    _index: int = 0

    async def decide(self, messages: list[dict[str, Any]], tools: list[Tool]) -> Decision:
        if self._index >= len(self.decisions):
            return Reply(text="(scripted brain ran out of decisions)")
        decision = self.decisions[self._index]
        self._index += 1
        return decision
