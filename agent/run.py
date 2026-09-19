"""The agent loop.

Get a goal, ask the model what to do, do it, feed the result back, repeat.

Two things to notice. Every tool call goes through the gateway, because the
gateway is the only tool endpoint this agent knows about. And there is no
security logic in this file at all, which is the point: an agent that polices
itself is only as trustworthy as the last thing it read.
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp import Client
from mcp.server.lowlevel import Server
from mcp.types import CallToolResult, TextContent, Tool

from agent.brain import Brain, Reply, ToolCall
from gateway.wire import SVID_FIELD, meta

GATEWAY_URL = "http://127.0.0.1:8080/mcp"
SVID_PATH = Path("certs/agent.svid")
MAX_STEPS = 6

logger = logging.getLogger("agent")


def load_svid(path: Path = SVID_PATH) -> str:
    """Read the identity this agent was given."""
    if not path.exists():
        raise SystemExit("no identity found, run: uv run python scripts/issue_svid.py")
    return path.read_text().strip()


def text_of(result: CallToolResult) -> str:
    """Flatten a tool result down to its text.

    Results can carry images or files too. This agent only understands text,
    so everything else is ignored rather than guessed at.
    """
    return "".join(block.text for block in result.content if isinstance(block, TextContent))


@dataclass
class Step:
    tool: str
    arguments: dict[str, Any]
    result: str

    @property
    def refused(self) -> bool:
        return self.result.startswith("refused:")


@dataclass
class RunResult:
    answer: str
    steps: list[Step]

    @property
    def refusals(self) -> list[Step]:
        return [step for step in self.steps if step.refused]


async def run_agent(
    goal: str,
    brain: Brain,
    gateway: str | Server[Any] = GATEWAY_URL,
    svid: str | None = None,
    max_steps: int = MAX_STEPS,
) -> RunResult:
    """Chase `goal`, routing every tool call through the gateway."""
    identity = svid if svid is not None else load_svid()

    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "You are an assistant with access to tools. "
                "Use them to accomplish the user's goal, then answer."
            ),
        },
        {"role": "user", "content": goal},
    ]
    steps: list[Step] = []

    async with Client(gateway) as client:
        tools: list[Tool] = (await client.list_tools()).tools

        for _ in range(max_steps):
            decision = await brain.decide(messages, tools)

            if isinstance(decision, Reply):
                return RunResult(answer=decision.text, steps=steps)

            logger.info("calling %s %s", decision.name, decision.arguments)

            # The identity rides along with every call. The gateway checks it
            # every time, not once at connect.
            result = await client.call_tool(
                decision.name, decision.arguments, meta=meta(**{SVID_FIELD: identity})
            )
            text = text_of(result)

            steps.append(Step(tool=decision.name, arguments=decision.arguments, result=text))
            called = f"Calling {decision.name} with {decision.arguments}"
            messages.append({"role": "assistant", "content": called})
            messages.append({"role": "tool", "content": text})

        return RunResult(answer="(gave up, hit the step limit)", steps=steps)


__all__ = ["RunResult", "Step", "ToolCall", "load_svid", "run_agent", "text_of"]
