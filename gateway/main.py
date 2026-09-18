"""Runs the gateway.

    uv run python -m gateway.main

The agent connects to http://127.0.0.1:8080/mcp and, as far as it can tell, is
talking to an ordinary tool server.

Two extra routes let a person deal with calls that are waiting on approval:

    curl localhost:8080/approvals
    curl -X POST localhost:8080/approvals/<id>/approve
    curl -X POST localhost:8080/approvals/<id>/deny
"""

import logging

import uvicorn
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from gateway.proxy import Gateway, build_default, build_server

HOST = "127.0.0.1"
PORT = 8080


def approval_routes(gateway: Gateway) -> list[Route]:
    async def waiting(request: Request) -> JSONResponse:
        return JSONResponse(
            [
                {
                    "id": r.id,
                    "agent": r.agent,
                    "tool": r.tool,
                    "arguments": r.arguments,
                    "reason": r.reason,
                }
                for r in gateway.approvals.waiting()
            ]
        )

    async def decide(request: Request) -> JSONResponse:
        request_id = request.path_params["request_id"]
        approved = request.url.path.endswith("/approve")
        found = gateway.approvals.resolve(request_id, approved)
        if not found:
            return JSONResponse({"error": "no request with that id"}, status_code=404)
        return JSONResponse({"id": request_id, "approved": approved})

    return [
        Route("/approvals", waiting, methods=["GET"]),
        Route("/approvals/{request_id}/approve", decide, methods=["POST"]),
        Route("/approvals/{request_id}/deny", decide, methods=["POST"]),
    ]


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    gateway = build_default()
    server = build_server(gateway)
    app = server.streamable_http_app(
        json_response=True,
        custom_starlette_routes=approval_routes(gateway),
    )
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
