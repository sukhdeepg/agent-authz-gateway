"""The real tools, sitting behind the gateway.

This stands in for whatever an agent would actually reach in production: a
CRM, a payments API, a filesystem. One tool is harmless and one is dangerous,
because the interesting question is never "may this agent use tools" but "may
it make this exact call".

The tools themselves do no authorization. That is on purpose and it is how
most real tool servers behave: they trust whoever holds the credential. What
they do check is that the caller brought a token for this specific call, which
is the gateway's stamp saying the call was approved.

Run it directly:  uv run python -m toolserver.server
"""

import anyio
import httpx
from mcp import stdio_server
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.mcpserver import MCPServer
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
)

from gateway.identity import TrustDomain
from gateway.tokens import InvalidToken, TokenService
from gateway.wire import TOKEN_FIELD
from toolserver.documents import DOCUMENTS

tools = MCPServer(name="toolserver", version="0.1.0")


@tools.tool()
def read_document(name: str) -> str:
    """Read a document by name.

    Available documents: customer-list, quarterly-report, vendor-notes.
    """
    if name not in DOCUMENTS:
        available = ", ".join(sorted(DOCUMENTS))
        return f"No document named {name!r}. Available documents: {available}."
    return DOCUMENTS[name]


@tools.tool()
async def http_post(url: str, body: str) -> str:
    """Send an HTTP POST request with a text body to any URL."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(url, content=body)
        return f"POST {url} returned {response.status_code}"
    except httpx.HTTPError as exc:
        return f"POST {url} failed: {exc}"


def _refuse(message: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=message)], is_error=True)


def build_toolserver(token_service: TokenService) -> Server[None]:
    """Wrap the tools so every call has to show a valid action token."""

    async def on_list_tools(
        ctx: ServerRequestContext[None],
        params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        return ListToolsResult(tools=await tools.list_tools())

    async def on_call_tool(
        ctx: ServerRequestContext[None],
        params: CallToolRequestParams,
    ) -> CallToolResult:
        arguments = dict(params.arguments or {})
        token = (params.meta or {}).get(TOKEN_FIELD)

        if not isinstance(token, str):
            return _refuse("refused: no action token, calls must come through the gateway")

        try:
            token_service.verify(token, params.name, arguments)
        except InvalidToken as exc:
            return _refuse(f"refused: {exc}")

        outcome = await tools.call_tool(params.name, arguments)
        if not isinstance(outcome, CallToolResult):
            return _refuse("this tool asked for more input, which the gateway does not relay")
        return outcome

    return Server(
        name="toolserver", version="0.1.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool
    )


async def serve() -> None:
    # The tool server only needs the public half of the key to check tokens.
    # Here both sides read the same file because it is one machine and one
    # demo. Splitting them is a deployment detail, not a different idea.
    service = TokenService(TrustDomain.load_or_create())
    server = build_toolserver(service)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    anyio.run(serve)


if __name__ == "__main__":
    main()
