"""The extra fields we hang off an MCP call.

MCP calls carry an open `_meta` object for things the protocol itself does not
define. Two of ours ride along in there:

    svid          the agent proving who it is, on every call
    action_token  the gateway's stamp saying this one call was approved

The type is narrow in the SDK but the field is open on the wire, so the cast
here is deliberate rather than a workaround.
"""

from typing import Any, cast

from mcp.types import RequestParamsMeta

SVID_FIELD = "svid"
TOKEN_FIELD = "action_token"


def meta(**fields: Any) -> RequestParamsMeta:
    return cast(RequestParamsMeta, dict(fields))
