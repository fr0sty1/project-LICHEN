# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP resources for a LICHEN node (spec section 7, RFC 6690).

The implementation lives in the :mod:`lichen.coap.resources` package beside
this file; this module preserves the historical single-module entry point and
its source-level documentation contract.

Exposes ``/.well-known/core`` (resource discovery), ``/status``, ``/neighbors``,
and ``/config``. Payloads use CBOR (content-format 60), the compact encoding
appropriate for constrained LoRa links.

Provides :class:`~lichen.coap.resources.proxy.ProxyResource` for LCI baseline
mesh access. Clients with link-local reachability to the gateway use ``/proxy``
with RFC 7252 Proxy-Uri to reach native 0200::/8 mesh nodes.

Observable resources (RFC 7641):

* ``SenMLSensorsResource`` — ``/sensors`` — SenML+CBOR pack of all current
  sensor readings; clients subscribe with ``Observe: 0`` and receive pushed
  updates whenever the node calls its ``update()`` method.

* ``SenMLLocationResource`` — ``/sensors/location`` — observable SenML+CBOR
  position pack; updated by calling its ``update()`` method. ``/location``
  remains a compatibility alias.

* ``PresenceResource`` — ``/presence`` — own presence GET/PUT (status, activity,
  msg, battery, ts); Observe notifies on change (spec 18.5).

* ``PresenceCacheResource`` — ``/presence/cache`` — known neighbour presence
  with ``age_s``; updated by ``record()``.

* ``SosResource`` — ``/sos`` — emergency beacon. POST activates SOS; DELETE
  cancels; GET and Observe let any node monitor the state.

Forward proxy resource:

* ``ProxyResource`` — ``/proxy`` — RFC 7252 section 5.7 forward proxy for
  LCI baseline mesh access, advertising ``rt = "proxy"`` in its link
  description.
"""
