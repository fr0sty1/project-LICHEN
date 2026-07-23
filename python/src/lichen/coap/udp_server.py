# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""UDP CoAP server binding for LICHEN nodes.

Exposes a Node's CoAP resources (/status, /neighbors, /config) on a real
UDP port so external tools (like the Rust TUI) can query simulated nodes
the same way they query real hardware.

Usage:
    node = Node(identity, radio)
    await node.start()
    ctx = await bind_coap_udp(node, port=5683)
    # ... node is now queryable via coap://[::1]:5683/status
    await ctx.shutdown()
"""
# ponytail: thin wrapper, aiocoap does the heavy lifting

from __future__ import annotations

from typing import Any

import aiocoap

from lichen.coap.resources import NodeInfo, build_site


async def bind_coap_udp(
    node: Any,
    port: int = 5683,
    bind: str = "::1",
    *,
    allow_config_write: bool = False,
) -> aiocoap.Context:
    """Bind a Node's CoAP resources to a real UDP port.

    Args:
        node: A Node instance implementing get_status/get_neighbors/get_config.
        port: UDP port to bind (default 5683).
        bind: Address to bind (default "::1" for localhost).
        allow_config_write: Explicitly permit PUT requests to /config.

    Returns:
        An aiocoap.Context that must be shutdown() when done.
    """
    site = build_site(node, allow_config_write=allow_config_write)
    # ponytail: aiocoap wants explicit address, not "::"
    context = await aiocoap.Context.create_server_context(site, bind=(bind, port))
    return context
