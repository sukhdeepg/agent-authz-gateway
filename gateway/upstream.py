"""The gateway's connection to the real tool server.

The gateway plays two roles at once and this is one half of it:

    agent  ->  [ MCP server | GATEWAY | MCP client ]  ->  tool server

To the agent it looks like a tool server. To the tool server it looks like an
ordinary client. That sandwich is what makes a checkpoint possible, because
every call has to pass through the middle.

The tool server is launched as a subprocess over stdio, so nothing else on the
machine can reach it. The only way in is through the gateway.
"""

import os
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from mcp import Client, StdioServerParameters
from mcp.types import CallToolResult, ListToolsResult

from gateway.wire import TOKEN_FIELD, meta


def toolserver_params(cert_dir: Path | None = None) -> StdioServerParameters:
    """How to launch the tool server.

    The tool server needs the same trust domain key as the gateway to check
    tokens, so the key directory is handed down through the environment.
    """
    env = dict(os.environ)
    if cert_dir is not None:
        env["AUTHZ_CERT_DIR"] = str(cert_dir)
    return StdioServerParameters(
        command="uv",
        args=["run", "python", "-m", "toolserver.server"],
        env=env,
    )


class Upstream:
    """A started-and-stopped connection to the downstream tool server."""

    def __init__(
        self,
        params: StdioServerParameters | None = None,
        cert_dir: Path | None = None,
    ) -> None:
        self._params = params or toolserver_params(cert_dir)
        self._stack = AsyncExitStack()
        self._client: Client | None = None

    async def start(self) -> None:
        self._client = await self._stack.enter_async_context(Client(self._params))

    async def stop(self) -> None:
        await self._stack.aclose()
        self._client = None

    @property
    def client(self) -> Client:
        if self._client is None:
            raise RuntimeError("Upstream.start() has not been called")
        return self._client

    async def list_tools(self) -> ListToolsResult:
        return await self.client.list_tools()

    async def call_tool(
        self, name: str, arguments: dict[str, Any], action_token: str
    ) -> CallToolResult:
        """Forward a call, carrying the token that says it was approved."""
        return await self.client.call_tool(
            name, arguments, meta=meta(**{TOKEN_FIELD: action_token})
        )
