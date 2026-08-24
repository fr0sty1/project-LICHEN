# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP resources for a LICHEN node (spec section 7, RFC 6690).

The implementation lives in the :mod:`lichen.coap.resources` package beside
this file; this module preserves the historical single-module entry point and
its source-level documentation contract.

Exposes ``/.well-known/core`` (resource discovery), ``/status``, ``/neighbors``,
and ``/config``. Payloads use CBOR (content-format 60), the compact encoding
appropriate for constrained LoRa links.

Also provides optional :class:`~lichen.coap.resources.proxy.ProxyResource`
compatibility support for local transports that cannot route directly to mesh
IPv6 addresses. The authoritative LCI mesh access model remains direct IPv6 +
CoAP routing through the local node.

Observable resources (RFC 7641):

* ``SenMLSensorsResource`` — ``/sensors`` — SenML+CBOR pack of all current
  sensor readings; clients subscribe with ``Observe: 0`` and receive pushed
  updates whenever the node calls its ``update()`` method.

* ``SenMLLocationResource`` — ``/location`` — SenML+CBOR lat/lon/alt pack;
  updated by calling its ``update()`` method.

* ``PresenceResource`` — ``/presence`` — CBOR list of recently-heard neighbour
  nodes; updated by calling ``seen()`` whenever a beacon arrives from a mesh
  peer.

* ``SosResource`` — ``/sos`` — emergency beacon. POST activates SOS; DELETE
  cancels; GET and Observe let any node monitor the state.

Optional forward proxy resource:

* ``ProxyResource`` — ``/proxy`` — RFC 7252 section 5.7 forward proxy for
  local transports without direct mesh reachability, advertising
  ``rt = "proxy"`` in its link description.
"""
