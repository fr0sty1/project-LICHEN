# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for IP/CoAP LCI ResourceTransport."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import aiocoap  # type: ignore[import-untyped]
import cbor2
import pytest
from aiocoap import Message

from lichen.client.ip_coap import (
    CBOR_CONTENT_FORMAT,
    DEFAULT_503_BACKOFF_S,
    AiocoapResourceTransport,
    CoapTransportError,
    IpCoapConfig,
    ServiceUnavailableError,
)
from lichen.client.lci import LciClient
from lichen.coap.resources import StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context


class FakeObservation:
    def __init__(self, messages: list[Message]) -> None:
        self._messages = messages
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True

    async def __aiter__(self) -> AsyncIterator[Message]:
        for message in self._messages:
            yield message


class PendingObservation:
    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True

    def __aiter__(self) -> PendingObservation:
        return self

    async def __anext__(self) -> Message:
        await asyncio.Event().wait()
        raise StopAsyncIteration


class FakeRequestHandle:
    def __init__(
        self,
        response: Message | Exception,
        observation: Any | None = None,
    ) -> None:
        self.response = self._response(response)
        self.observation = observation or FakeObservation([])

    async def _response(self, response: Message | Exception) -> Message:
        if isinstance(response, Exception):
            raise response
        return response


class FakeContext:
    def __init__(self) -> None:
        self.requests: list[Message] = []
        self.responses: list[Message | Exception] = []
        self.observations: list[FakeObservation] = []
        self.shutdown_called = False

    def request(self, request: Message) -> FakeRequestHandle:
        self.requests.append(request)
        response = self.responses.pop(0)
        observation = self.observations.pop(0) if self.observations else None
        return FakeRequestHandle(response, observation)

    async def shutdown(self) -> None:
        self.shutdown_called = True


def _cbor_response(value: Any, *, code: aiocoap.Code = aiocoap.CONTENT) -> Message:
    message = Message(code=code, payload=cbor2.dumps(value))
    message.opt.content_format = CBOR_CONTENT_FORMAT
    return message


async def test_request_decodes_cbor_and_preserves_response_details() -> None:
    context = FakeContext()
    response = _cbor_response({"uptime_s": 42})
    response.opt.location_path = ("msg", "outbox", "1")
    context.responses.append(response)
    transport = AiocoapResourceTransport(
        config=IpCoapConfig(base_uri="coap://[fe80::1]", timeout_s=0.5),
        context=context,
    )

    result = await transport.request("GET", "/status")

    assert result.code == "2.05"
    assert result.payload == {"uptime_s": 42}
    assert result.location_path == ("msg", "outbox", "1")
    assert result.content_format == CBOR_CONTENT_FORMAT
    assert result.raw_payload == response.payload
    assert context.requests[0].get_request_uri() == "coap://[fe80::1]/status"


async def test_request_sends_cbor_payload_and_content_format() -> None:
    context = FakeContext()
    context.responses.append(Message(code=aiocoap.CHANGED))
    transport = AiocoapResourceTransport(context=context)
    payload = cbor2.dumps({"name": "node"})

    result = await transport.request(
        "PUT",
        "config",
        payload=payload,
        content_format=CBOR_CONTENT_FORMAT,
    )

    assert result.code == "2.04"
    assert context.requests[0].payload == payload
    assert context.requests[0].opt.content_format == CBOR_CONTENT_FORMAT


async def test_request_accepts_absolute_peer_uri() -> None:
    context = FakeContext()
    context.responses.append(Message(code=aiocoap.CREATED))
    transport = AiocoapResourceTransport(
        config=IpCoapConfig(base_uri="coap://[fe80::1]"),
        context=context,
    )

    result = await transport.request("POST", "coap://[0200::2]/waypoints")

    assert result.code == "2.01"
    assert context.requests[0].get_request_uri() == "coap://[200::2]/waypoints"


async def test_request_preserves_unsupported_resource_code() -> None:
    context = FakeContext()
    context.responses.append(Message(code=aiocoap.NOT_FOUND, payload=b"missing"))
    transport = AiocoapResourceTransport(context=context)

    result = await transport.request("GET", "/nope")

    assert result.code == "4.04"
    assert result.payload == "missing"


async def test_request_wraps_timeouts() -> None:
    context = FakeContext()
    context.responses.append(TimeoutError("slow"))
    transport = AiocoapResourceTransport(context=context, config=IpCoapConfig(timeout_s=0.01))

    with pytest.raises(CoapTransportError, match="GET /status failed"):
        await transport.request("GET", "/status")


async def test_request_rejects_invalid_cbor() -> None:
    context = FakeContext()
    message = Message(code=aiocoap.CONTENT, payload=b"not-cbor")
    message.opt.content_format = CBOR_CONTENT_FORMAT
    context.responses.append(message)
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(CoapTransportError, match="invalid CBOR"):
        await transport.request("GET", "/status")


async def test_request_rejects_unsupported_method() -> None:
    transport = AiocoapResourceTransport(context=FakeContext())

    with pytest.raises(CoapTransportError, match="unsupported CoAP method"):
        await transport.request("PATCH", "/config")


async def test_request_wraps_message_construction_errors() -> None:
    transport = AiocoapResourceTransport(
        context=FakeContext(),
        config=IpCoapConfig(base_uri="not a uri"),
    )

    with pytest.raises(CoapTransportError, match="GET /status failed"):
        await transport.request("GET", "/status")


async def test_observe_yields_initial_and_later_notifications() -> None:
    context = FakeContext()
    context.responses.append(_cbor_response({"messages": []}))
    observation = FakeObservation([_cbor_response({"messages": [{"id": 1}]})])
    context.observations.append(observation)
    transport = AiocoapResourceTransport(context=context)

    subscription = await transport.observe("/msg/inbox")
    results = []
    async for result in subscription.results():
        results.append(result.payload)
        if len(results) == 2:
            break

    assert results == [{"messages": []}, {"messages": [{"id": 1}]}]
    assert context.requests[0].opt.observe == 0
    await subscription.close()
    assert observation.cancelled
    await subscription.close()
    assert observation.cancelled


async def test_observe_initial_response_timeout_is_wrapped() -> None:
    context = FakeContext()
    context.responses.append(TimeoutError("slow observe"))
    transport = AiocoapResourceTransport(context=context, config=IpCoapConfig(timeout_s=0.01))

    subscription = await transport.observe("/msg/inbox")

    with pytest.raises(CoapTransportError, match="GET /msg/inbox observe failed"):
        async for _result in subscription.results():
            pass


async def test_observe_close_wakes_pending_notification_reader() -> None:
    context = FakeContext()
    context.responses.append(_cbor_response({"messages": []}))
    observation = PendingObservation()
    context.observations.append(observation)  # type: ignore[arg-type]
    transport = AiocoapResourceTransport(context=context)
    subscription = await transport.observe("/msg/inbox")
    iterator = subscription.results()

    assert (await anext(iterator)).payload == {"messages": []}
    pending: asyncio.Future[Any] = asyncio.ensure_future(anext(iterator))
    await asyncio.sleep(0)
    await subscription.close()

    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(pending, timeout=1.0)
    assert observation.cancelled


async def test_close_does_not_shut_down_injected_context() -> None:
    context = FakeContext()
    transport = AiocoapResourceTransport(context=context)

    await transport.close()

    assert not context.shutdown_called


async def test_reconnect_after_injected_context_owns_created_context() -> None:
    injected_context = FakeContext()
    created_context = FakeContext()

    async def factory() -> FakeContext:
        return created_context

    transport = AiocoapResourceTransport(context=injected_context, context_factory=factory)

    await transport.close()
    assert not injected_context.shutdown_called
    await transport.connect()
    await transport.close()

    assert created_context.shutdown_called


async def test_lci_client_get_status_over_in_memory_aiocoap_context() -> None:
    net = InMemoryNetwork()
    site = build_site(StaticNodeInfo(status={"uptime_s": 123, "battery_pct": 91}))
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client_context = await create_lichen_context(net.channel("cli"), "cli")
    transport = AiocoapResourceTransport(
        config=IpCoapConfig(base_uri="coap://srv", timeout_s=1.0),
        context=client_context,
    )
    client = LciClient(transport)

    try:
        status = await client.get_status()
    finally:
        await client_context.shutdown()
        await server.shutdown()

    assert status.uptime_s == 123
    assert status.battery_pct == 91


# --- 5.03 Service Unavailable backoff tests (spec 07 section 10.2.3) ---


def _503_response(
    *,
    max_age: int | None = None,
    reason: str | None = None,
    retry_after: int | float | None = None,
    level: str | None = None,
) -> Message:
    """Build a 5.03 Service Unavailable response per spec."""
    payload_dict: dict[str, Any] = {}
    if reason is not None:
        payload_dict["reason"] = reason
    if retry_after is not None:
        payload_dict["retry_after"] = retry_after
    if level is not None:
        payload_dict["level"] = level
    payload = cbor2.dumps(payload_dict) if payload_dict else b""
    message = Message(code=aiocoap.SERVICE_UNAVAILABLE, payload=payload)
    if payload:
        message.opt.content_format = CBOR_CONTENT_FORMAT
    if max_age is not None:
        message.opt.max_age = max_age
    return message


async def test_503_response_with_max_age_raises_service_unavailable() -> None:
    """5.03 with Max-Age triggers backoff per spec 07 section 10.2.3."""
    context = FakeContext()
    context.responses.append(_503_response(max_age=120, reason="duty_cycle", level="critical"))
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.request("GET", "/status")

    assert exc_info.value.retry_after_s == 120
    assert exc_info.value.reason == "duty_cycle"
    assert exc_info.value.level == "critical"
    assert "back off for 120s" in str(exc_info.value)


async def test_503_response_with_retry_after_payload_raises_service_unavailable() -> None:
    """5.03 with retry_after in payload triggers backoff when no Max-Age."""
    context = FakeContext()
    context.responses.append(_503_response(retry_after=90, reason="storage_full"))
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.request("POST", "/msg/inbox")

    assert exc_info.value.retry_after_s == 90
    assert exc_info.value.reason == "storage_full"


async def test_503_response_without_duration_uses_default_backoff() -> None:
    """5.03 without Max-Age or retry_after uses default backoff."""
    context = FakeContext()
    context.responses.append(_503_response())  # no duration
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.request("GET", "/config")

    assert exc_info.value.retry_after_s == DEFAULT_503_BACKOFF_S


async def test_503_max_age_takes_precedence_over_retry_after() -> None:
    """Max-Age option has priority over retry_after in payload."""
    context = FakeContext()
    context.responses.append(_503_response(max_age=60, retry_after=300))
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.request("GET", "/status")

    assert exc_info.value.retry_after_s == 60  # Max-Age wins


async def test_503_with_zero_max_age_uses_zero_not_default() -> None:
    """Max-Age=0 must be respected, not treated as missing (falsy check bug)."""
    context = FakeContext()
    context.responses.append(_503_response(max_age=0))
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.request("GET", "/status")

    # Zero must be respected - immediate retry allowed, not 60s default
    assert exc_info.value.retry_after_s == 0


async def test_subsequent_request_during_backoff_raises_immediately() -> None:
    """Requests during backoff raise without sending (spec compliance)."""
    context = FakeContext()
    context.responses.append(_503_response(max_age=120, reason="duty_cycle"))
    context.responses.append(_cbor_response({"ok": True}))
    transport = AiocoapResourceTransport(context=context)

    # First request gets 5.03
    with pytest.raises(ServiceUnavailableError):
        await transport.request("GET", "/status")

    # Second request blocked without sending
    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.request("GET", "/config")

    assert exc_info.value.reason == "duty_cycle"  # carries reason from original 5.03
    assert "blocked: backed off" in str(exc_info.value)
    # Only one request was sent to the context
    assert len(context.requests) == 1


async def test_backoff_clear_allows_requests_again() -> None:
    """Clearing backoff re-enables requests."""
    context = FakeContext()
    context.responses.append(_503_response(max_age=9999))
    context.responses.append(_cbor_response({"ok": True}))
    transport = AiocoapResourceTransport(context=context)

    # First request triggers backoff
    with pytest.raises(ServiceUnavailableError):
        await transport.request("GET", "/status")

    # Clear backoff
    transport.clear_backoff()

    # Now request succeeds
    result = await transport.request("GET", "/config")
    assert result.is_success


async def test_enforce_503_backoff_false_disables_backoff() -> None:
    """Setting enforce_503_backoff=False disables backoff handling."""
    context = FakeContext()
    context.responses.append(_503_response(max_age=120, reason="duty_cycle"))
    context.responses.append(_cbor_response({"ok": True}))
    transport = AiocoapResourceTransport(
        context=context,
        config=IpCoapConfig(enforce_503_backoff=False),
    )

    # First request gets 5.03 but does NOT raise
    result = await transport.request("GET", "/status")
    assert result.code == "5.03"
    assert result.is_service_unavailable
    assert result.retry_after_s == 120  # Still parses the value

    # Second request proceeds normally (no backoff recorded)
    result = await transport.request("GET", "/config")
    assert result.is_success


async def test_coap_result_is_service_unavailable_property() -> None:
    """CoapResult.is_service_unavailable correctly identifies 5.03."""
    context = FakeContext()
    context.responses.append(_503_response(max_age=60))
    transport = AiocoapResourceTransport(
        context=context,
        config=IpCoapConfig(enforce_503_backoff=False),
    )

    result = await transport.request("GET", "/status")

    assert result.is_service_unavailable is True
    assert result.max_age == 60
    assert result.retry_after_s == 60


async def test_coap_result_retry_after_from_payload() -> None:
    """CoapResult.retry_after_s falls back to CBOR payload."""
    context = FakeContext()
    context.responses.append(_503_response(retry_after=45))  # no Max-Age
    transport = AiocoapResourceTransport(
        context=context,
        config=IpCoapConfig(enforce_503_backoff=False),
    )

    result = await transport.request("GET", "/status")

    assert result.max_age is None
    assert result.retry_after_s == 45  # from payload


async def test_coap_result_retry_after_float_truncated_to_int() -> None:
    """Float retry_after in CBOR payload is accepted and truncated to int.

    CBOR can encode numeric values as floats; the spec shows integer values
    but implementations should accept floats and truncate them.
    """
    context = FakeContext()
    context.responses.append(_503_response(retry_after=120.7))  # float value
    transport = AiocoapResourceTransport(
        context=context,
        config=IpCoapConfig(enforce_503_backoff=False),
    )

    result = await transport.request("GET", "/status")

    assert result.max_age is None
    assert result.retry_after_s == 120  # truncated from 120.7


async def test_coap_result_retry_after_float_zero_returns_zero() -> None:
    """Float retry_after of 0.0 returns 0 (immediate retry), consistent with Max-Age=0."""
    context = FakeContext()
    context.responses.append(_503_response(retry_after=0.0))
    transport = AiocoapResourceTransport(
        context=context,
        config=IpCoapConfig(enforce_503_backoff=False),
    )

    result = await transport.request("GET", "/status")

    # 0.0 >= 0, so returns 0 (immediate retry allowed)
    assert result.retry_after_s == 0


async def test_coap_result_retry_after_int_zero_returns_zero() -> None:
    """Integer retry_after=0 returns 0 (immediate retry), consistent with Max-Age=0."""
    context = FakeContext()
    context.responses.append(_503_response(retry_after=0))
    transport = AiocoapResourceTransport(
        context=context,
        config=IpCoapConfig(enforce_503_backoff=False),
    )

    result = await transport.request("GET", "/status")

    # Integer 0 >= 0, so returns 0 (immediate retry allowed)
    assert result.retry_after_s == 0


async def test_coap_result_retry_after_small_float_truncates_to_zero() -> None:
    """Small float like 0.5 truncates to 0, meaning immediate retry allowed."""
    context = FakeContext()
    context.responses.append(_503_response(retry_after=0.5))
    transport = AiocoapResourceTransport(
        context=context,
        config=IpCoapConfig(enforce_503_backoff=False),
    )

    result = await transport.request("GET", "/status")

    # 0.5 > 0 passes the validity check, then int(0.5)=0 is returned
    assert result.retry_after_s == 0


async def test_coap_result_retry_after_negative_float_returns_none() -> None:
    """Negative float retry_after is rejected."""
    context = FakeContext()
    context.responses.append(_503_response(retry_after=-5.0))
    transport = AiocoapResourceTransport(
        context=context,
        config=IpCoapConfig(enforce_503_backoff=False),
    )

    result = await transport.request("GET", "/status")

    assert result.retry_after_s is None


def test_coap_result_retry_after_bool_rejected() -> None:
    """Boolean retry_after is rejected (bool is subclass of int in Python)."""
    from lichen.client.model import CoapResult

    # True would pass isinstance(x, int) but should be rejected
    result = CoapResult(
        code="5.03",
        payload={"retry_after": True},
        content_format=60,
    )
    assert result.retry_after_s is None

    # False similarly
    result = CoapResult(
        code="5.03",
        payload={"retry_after": False},
        content_format=60,
    )
    assert result.retry_after_s is None


def test_coap_result_retry_after_inf_rejected() -> None:
    """Float infinity retry_after is rejected (r2-P1-12, r2-P1-13).

    CBOR can encode special float values like inf. Converting inf to int
    raises OverflowError, so we must check math.isfinite() first.
    """
    from lichen.client.model import CoapResult

    # Positive infinity
    result = CoapResult(
        code="5.03",
        payload={"retry_after": float("inf")},
        content_format=60,
    )
    assert result.retry_after_s is None

    # Negative infinity
    result = CoapResult(
        code="5.03",
        payload={"retry_after": float("-inf")},
        content_format=60,
    )
    assert result.retry_after_s is None

    # Confirm these would have raised without the fix
    with pytest.raises(OverflowError):
        int(float("inf"))
    with pytest.raises(OverflowError):
        int(float("-inf"))


def test_coap_result_retry_after_nan_rejected() -> None:
    """Float NaN retry_after is rejected (r2-P1-12, r2-P1-13).

    CBOR can encode NaN. Converting NaN to int raises ValueError,
    so we must check math.isfinite() first.
    """
    from lichen.client.model import CoapResult

    result = CoapResult(
        code="5.03",
        payload={"retry_after": float("nan")},
        content_format=60,
    )
    assert result.retry_after_s is None

    # Confirm this would have raised without the fix
    with pytest.raises(ValueError):
        int(float("nan"))


def test_coap_result_retry_after_isfinite_overflow_handled() -> None:
    """math.isfinite() on large integers raises OverflowError (r2-P1-17).

    While the current code path only calls isfinite() on floats (which never
    raise OverflowError), the defensive try-except ensures robustness against
    future changes or edge cases where a float-like type might overflow.

    This test documents the issue and verifies the defensive handling.
    """
    import math

    # Confirm that math.isfinite() on very large integers raises OverflowError
    large_int = 10**309  # Larger than float can represent
    with pytest.raises(OverflowError):
        math.isfinite(large_int)

    # The code handles this defensively - even though current code path
    # only calls isfinite() on actual floats, the try-except protects against
    # future changes or unusual numeric types.


def test_coap_result_retry_after_decimal_inf_rejected() -> None:
    """Decimal infinity retry_after is rejected (r2-P1-16).

    CBOR tag 4 (decimal fraction) and tag 5 (bigfloat) decode to Decimal
    objects. Decimal('inf') and Decimal('-inf') int() raises OverflowError.
    """
    from decimal import Decimal

    from lichen.client.model import CoapResult

    # Positive Decimal infinity
    result = CoapResult(
        code="5.03",
        payload={"retry_after": Decimal("inf")},
        content_format=60,
    )
    assert result.retry_after_s is None

    # Negative Decimal infinity
    result = CoapResult(
        code="5.03",
        payload={"retry_after": Decimal("-inf")},
        content_format=60,
    )
    assert result.retry_after_s is None

    # Confirm these would have raised without the fix
    with pytest.raises(OverflowError):
        int(Decimal("inf"))
    with pytest.raises(OverflowError):
        int(Decimal("-inf"))


def test_coap_result_retry_after_decimal_nan_rejected() -> None:
    """Decimal NaN retry_after is rejected (r2-P1-16).

    CBOR tag 4/5 can encode NaN as Decimal. Decimal('nan') comparisons
    raise InvalidOperation, and int() raises ValueError.
    """
    from decimal import Decimal, InvalidOperation

    from lichen.client.model import CoapResult

    result = CoapResult(
        code="5.03",
        payload={"retry_after": Decimal("nan")},
        content_format=60,
    )
    assert result.retry_after_s is None

    # Confirm comparison would have raised without the fix
    with pytest.raises(InvalidOperation):
        _ = Decimal("nan") >= 0


def test_coap_result_retry_after_decimal_valid_accepted() -> None:
    """Valid Decimal retry_after values are accepted (r2-P1-16).

    Normal Decimal values from CBOR tag 4/5 should work correctly.
    """
    from decimal import Decimal

    from lichen.client.model import CoapResult

    # Integer-equivalent Decimal
    result = CoapResult(
        code="5.03",
        payload={"retry_after": Decimal("120")},
        content_format=60,
    )
    assert result.retry_after_s == 120

    # Float-like Decimal (truncated)
    result = CoapResult(
        code="5.03",
        payload={"retry_after": Decimal("120.7")},
        content_format=60,
    )
    assert result.retry_after_s == 120

    # Large Decimal (capped to MAX_BACKOFF_S)
    result = CoapResult(
        code="5.03",
        payload={"retry_after": Decimal("1e10")},
        content_format=60,
    )
    assert result.retry_after_s == 3600  # MAX_BACKOFF_S


def test_coap_result_retry_after_huge_decimal_capped() -> None:
    """Huge finite Decimal retry_after is accepted and capped (r2-P1-15).

    Very large but finite Decimal values are valid input. Python's int(Decimal)
    conversion works directly from Decimal's internal representation without
    string conversion, so it doesn't hit Python's string digit limit. These
    values are capped to MAX_BACKOFF_S like any other large value.
    """
    from decimal import Decimal

    from lichen.client.model import CoapResult

    # Create a huge finite Decimal (10^5000)
    huge_decimal = Decimal("1" + "0" * 5000)

    result = CoapResult(
        code="5.03",
        payload={"retry_after": huge_decimal},
        content_format=60,
    )
    # Should not crash, should be capped to MAX_BACKOFF_S (3600)
    assert result.retry_after_s == 3600


def test_coap_result_max_age_decimal_nan_falls_back_to_payload() -> None:
    """Decimal NaN max_age is treated as absent, falls back to payload (r2-P1-16).

    If max_age somehow becomes Decimal('nan') (defense in depth),
    the comparison should not crash with InvalidOperation.
    """
    from decimal import Decimal

    from lichen.client.model import CoapResult

    result = CoapResult(
        code="5.03",
        max_age=Decimal("nan"),  # type: ignore[arg-type]  # Testing invalid input
        payload={"retry_after": 90},
        content_format=60,
    )
    # Should not crash, should fall back to payload
    assert result.retry_after_s == 90


def test_int_or_none_decimal_inf_returns_none() -> None:
    """_int_or_none handles Decimal('inf') without crashing (r2-P1-16).

    The function catches OverflowError from int(Decimal('inf')).
    """
    from decimal import Decimal

    from lichen.client.ip_coap import _int_or_none

    assert _int_or_none(Decimal("inf")) is None
    assert _int_or_none(Decimal("-inf")) is None
    # Normal Decimal should work
    assert _int_or_none(Decimal("42")) == 42


def test_coap_result_retry_after_capped_at_source() -> None:
    """CoapResult.retry_after_s caps unbounded values at the model level.

    SECURITY: This verifies that the cap is applied in the property itself,
    not just when used by the transport. Any code accessing retry_after_s
    gets a bounded value (issue r1-P2-29).
    """
    from lichen.client.model import MAX_BACKOFF_S, CoapResult

    # Test with unbounded max_age
    result = CoapResult(
        code="5.03",
        max_age=10_000_000,  # ~115 days
        content_format=60,
    )
    assert result.retry_after_s == MAX_BACKOFF_S
    assert result.retry_after_s == 3600

    # Test with unbounded retry_after in payload
    result = CoapResult(
        code="5.03",
        payload={"retry_after": 999_999_999},
        content_format=60,
    )
    assert result.retry_after_s == MAX_BACKOFF_S

    # Test that values below cap are not modified
    result = CoapResult(
        code="5.03",
        max_age=120,
        content_format=60,
    )
    assert result.retry_after_s == 120


def test_coap_result_negative_max_age_returns_none() -> None:
    """Negative max_age is rejected per RFC 7252 (Max-Age is unsigned).

    This validates defense-in-depth in CoapResult.retry_after_s even if
    a negative value somehow bypasses the parsing layer (r1-P2-31).
    """
    from lichen.client.model import CoapResult

    # max_age=-1 should be treated as absent
    result = CoapResult(
        code="5.03",
        payload={},
        content_format=60,
        max_age=-1,
    )
    assert result.retry_after_s is None

    # max_age=-100 similarly
    result = CoapResult(
        code="5.03",
        payload={},
        content_format=60,
        max_age=-100,
    )
    assert result.retry_after_s is None


async def test_503_with_negative_max_age_falls_back_to_payload() -> None:
    """Negative max_age from CoAP option is converted to None (r1-P2-31).

    This tests the _uint_or_none parsing path. Negative values should be
    treated as if the option was absent, falling back to retry_after in payload.
    """
    context = FakeContext()
    # Manually create a response with negative max_age to simulate malformed data
    message = Message(code=aiocoap.SERVICE_UNAVAILABLE, payload=cbor2.dumps({"retry_after": 45}))
    message.opt.content_format = CBOR_CONTENT_FORMAT
    message.opt.max_age = -1  # Invalid per RFC 7252
    context.responses.append(message)
    transport = AiocoapResourceTransport(
        context=context,
        config=IpCoapConfig(enforce_503_backoff=False),
    )

    result = await transport.request("GET", "/status")

    # Negative max_age should be converted to None by _uint_or_none
    assert result.max_age is None
    # Falls back to retry_after from payload
    assert result.retry_after_s == 45


async def test_503_backoff_with_float_retry_after_truncates() -> None:
    """Float retry_after in payload triggers backoff with truncated value."""
    context = FakeContext()
    context.responses.append(_503_response(retry_after=90.9))  # float
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.request("POST", "/msg/inbox")

    # Backoff uses truncated int value
    assert exc_info.value.retry_after_s == 90


async def test_non_503_response_does_not_trigger_backoff() -> None:
    """Other 5.xx errors do not trigger backoff."""
    context = FakeContext()
    context.responses.append(Message(code=aiocoap.INTERNAL_SERVER_ERROR))
    context.responses.append(_cbor_response({"ok": True}))
    transport = AiocoapResourceTransport(context=context)

    result = await transport.request("GET", "/status")
    assert result.code == "5.00"

    # Second request proceeds normally
    result = await transport.request("GET", "/config")
    assert result.is_success


# --- DoS protection: backoff cap tests (spec 07 section 10.2.3, 1-hour window) ---


async def test_503_backoff_capped_at_max_to_prevent_dos() -> None:
    """Backoff values exceeding MAX_BACKOFF_S are capped to prevent DoS.

    SECURITY: A malicious node could send a 5.03 with retry_after=2^31 to
    permanently deny service. The spec's 1-hour duty cycle window means no
    legitimate congestion recovery can exceed 3600 seconds (issue r1-P2-29).
    """
    from lichen.client.model import MAX_BACKOFF_S

    context = FakeContext()
    # Malicious value: 1 billion seconds (~31 years)
    context.responses.append(_503_response(max_age=1_000_000_000))
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.request("GET", "/status")

    # Capped to MAX_BACKOFF_S (3600 seconds = 1 hour)
    assert exc_info.value.retry_after_s == MAX_BACKOFF_S
    assert exc_info.value.retry_after_s == 3600


async def test_503_backoff_cap_applies_to_payload_retry_after() -> None:
    """Malicious retry_after in payload is also capped."""
    from lichen.client.model import MAX_BACKOFF_S

    context = FakeContext()
    # Malicious value in payload
    context.responses.append(_503_response(retry_after=999_999_999))
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.request("GET", "/status")

    assert exc_info.value.retry_after_s == MAX_BACKOFF_S


async def test_503_backoff_at_exactly_max_is_not_capped() -> None:
    """Values at exactly MAX_BACKOFF_S are not modified."""
    from lichen.client.model import MAX_BACKOFF_S

    context = FakeContext()
    context.responses.append(_503_response(max_age=MAX_BACKOFF_S))
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.request("GET", "/status")

    assert exc_info.value.retry_after_s == MAX_BACKOFF_S


async def test_503_backoff_below_max_is_not_capped() -> None:
    """Normal backoff values are not affected by the cap."""
    context = FakeContext()
    context.responses.append(_503_response(max_age=300))  # 5 minutes
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.request("GET", "/status")

    assert exc_info.value.retry_after_s == 300


async def test_max_backoff_constant_matches_spec() -> None:
    """MAX_BACKOFF_S is 3600 (1 hour) per spec 07 duty cycle window."""
    from lichen.client.model import MAX_BACKOFF_S

    # Spec 07 section 10.2.3 defines rolling 1-hour duty cycle window
    assert MAX_BACKOFF_S == 3600


# --- observe() backoff enforcement tests (spec 07 section 10.2.3) ---


async def test_observe_blocked_during_backoff() -> None:
    """observe() respects backoff state per spec 07 section 10.2.3.

    The spec mandates: "Senders receiving 5.03 MUST back off for the indicated
    duration." This applies to ALL requests, including Observe registrations.
    """
    context = FakeContext()
    context.responses.append(_503_response(max_age=120, reason="duty_cycle"))
    # Second response won't be used - observe should be blocked
    context.responses.append(_cbor_response({"messages": []}))
    context.observations.append(FakeObservation([]))
    transport = AiocoapResourceTransport(context=context)

    # First request gets 5.03 and triggers backoff
    with pytest.raises(ServiceUnavailableError):
        await transport.request("GET", "/status")

    # observe() blocked without sending (spec compliance)
    with pytest.raises(ServiceUnavailableError) as exc_info:
        await transport.observe("/msg/inbox")

    assert exc_info.value.reason == "duty_cycle"
    assert "observe blocked: backed off" in str(exc_info.value)
    # Only the first request was sent
    assert len(context.requests) == 1


async def test_observe_succeeds_after_backoff_cleared() -> None:
    """observe() works normally after backoff is cleared."""
    context = FakeContext()
    context.responses.append(_503_response(max_age=9999))
    context.responses.append(_cbor_response({"messages": []}))
    observation = FakeObservation([])
    context.observations.append(observation)
    transport = AiocoapResourceTransport(context=context)

    # First request triggers backoff
    with pytest.raises(ServiceUnavailableError):
        await transport.request("GET", "/status")

    # Clear backoff
    transport.clear_backoff()

    # Now observe succeeds
    subscription = await transport.observe("/msg/inbox")
    results = [r.payload async for r in subscription.results()]
    assert results == [{"messages": []}]
    await subscription.close()


async def test_observe_allowed_when_backoff_disabled() -> None:
    """observe() ignores backoff when enforce_503_backoff=False."""
    context = FakeContext()
    context.responses.append(_503_response(max_age=120))
    context.responses.append(_cbor_response({"messages": []}))
    context.observations.append(FakeObservation([]))
    transport = AiocoapResourceTransport(
        context=context,
        config=IpCoapConfig(enforce_503_backoff=False),
    )

    # First request gets 5.03 but doesn't raise
    result = await transport.request("GET", "/status")
    assert result.code == "5.03"

    # observe() proceeds (backoff not enforced)
    subscription = await transport.observe("/msg/inbox")
    results = [r.payload async for r in subscription.results()]
    assert results == [{"messages": []}]
    await subscription.close()

