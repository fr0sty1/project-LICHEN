# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Native LICHEN client TUI client factories and entry point."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from lichen.client import (
    AiocoapResourceTransport,
    BlePacketTransport,
    IpCoapConfig,
    LciClient,
    PacketCoapConfig,
    PacketCoapResourceTransport,
)

from .app import NativeClientApp
from .models import (
    ConnectionClientFactory,
    LinkMode,
    MessagingClient,
    ShellStatus,
    UiState,
)


def build_messaging_client(
    base_uri: str | None,
    *,
    ble_address: str | None = None,
    ble_local_host: str = "fe80::2",
    ble_node_host: str = "fe80::1",
) -> MessagingClient | None:
    """Build a messaging client for IP/CoAP or BLE packet-backed LCI."""
    if ble_address is not None:
        packet_transport = BlePacketTransport(ble_address)
        transport = PacketCoapResourceTransport(
            packet_transport,
            config=PacketCoapConfig(local_host=ble_local_host, peer_host=ble_node_host),
        )
        return LciClient(transport)
    if base_uri is None:
        return None
    transport = AiocoapResourceTransport(config=IpCoapConfig(base_uri=base_uri))
    return LciClient(transport)


def build_connection_factory(
    *,
    coap_base_uri: str | None = None,
    ble_address: str | None = None,
    ble_local_host: str = "fe80::2",
    ble_node_host: str = "fe80::1",
) -> ConnectionClientFactory:
    """Return a picker factory for Demo, BLE, and IP/CoAP modes."""

    def factory(mode: LinkMode) -> MessagingClient | None:
        if mode is LinkMode.DEMO:
            return None
        if mode is LinkMode.BLE:
            if ble_address is None:
                return None
            return build_messaging_client(
                None,
                ble_address=ble_address,
                ble_local_host=ble_local_host,
                ble_node_host=ble_node_host,
            )
        if mode is LinkMode.IP and coap_base_uri is not None:
            return build_messaging_client(coap_base_uri)
        return None

    return factory


def main(argv: Sequence[str] | None = None) -> None:
    """Run the native client shell."""
    parser = argparse.ArgumentParser(description="Run the LICHEN native LCI TUI")
    parser.add_argument(
        "--coap-base-uri",
        help="Base IP/CoAP URI for a local LCI endpoint, for example coap://[fe80::1]",
    )
    parser.add_argument("--ble-address", help="BLE address for a SLIP/IPv6 LCI endpoint")
    parser.add_argument("--ble-local-host", default="fe80::2")
    parser.add_argument("--ble-node-host", default="fe80::1")
    parser.add_argument("--inbox-path", default="/msg/inbox")
    parser.add_argument("--send-path", default="/msg/inbox")
    args = parser.parse_args(argv)
    connection_factory = build_connection_factory(
        coap_base_uri=args.coap_base_uri,
        ble_address=args.ble_address,
        ble_local_host=args.ble_local_host,
        ble_node_host=args.ble_node_host,
    )
    client = build_messaging_client(
        args.coap_base_uri,
        ble_address=args.ble_address,
        ble_local_host=args.ble_local_host,
        ble_node_host=args.ble_node_host,
    )
    mode = LinkMode.DEMO
    if args.ble_address is not None:
        mode = LinkMode.BLE
    elif client is not None:
        mode = LinkMode.IP
    status = ShellStatus(
        mode=mode,
        state=UiState.SYNCED if client is not None else UiState.DISCONNECTED,
    )
    NativeClientApp(
        status,
        client=client,
        connection_factory=connection_factory,
        inbox_path=args.inbox_path,
        send_path=args.send_path,
    ).run()
