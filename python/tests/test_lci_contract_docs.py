from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def read_repo_text(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_lci_spec_is_authoritative_over_legacy_native_cbor() -> None:
    lci = read_repo_text("spec/11-lci.md")

    assert "authoritative native application" in lci
    assert "spec/lichen-native/" in lci
    assert "MUST NOT use its `0xC1` framing" in lci
    assert "`raw_tx`, or `raw_rx` messages" in lci


def test_legacy_native_specs_are_marked_non_authoritative() -> None:
    for path in sorted((REPO_ROOT / "spec/lichen-native").glob("*.md")):
        text = path.read_text(encoding="utf-8")
        assert "historical draft" in text, path
        assert "non-authoritative" in text, path
        assert "../11-lci.md" in text, path


def test_lci_raw_diagnostics_have_coap_security_model() -> None:
    lci = read_repo_text("spec/11-lci.md")

    for required in (
        "GET /diag",
        "GET /diag/raw/rx",
        "GET /diag/raw/rx/events",
        "PUT /diag/raw/rx",
        "POST /diag/raw/tx",
        "CoAP Observe",
        "finite arming lifetime",
        "MUST NOT divert frames from the normal IPv6 stack",
        "local administrative authorization",
        "LE Secure Connections",
        "OSCORE",
        "MUST rate-limit raw",
        "build-time",
        "diagnostic enablement",
        "excludes `/diag/raw/*`",
    ):
        assert required in lci


def test_legacy_raw_rx_key_points_to_lci_diagnostics() -> None:
    config = read_repo_text("spec/lichen-native/04-config.md")
    raw = read_repo_text("spec/lichen-native/10-raw-frame.md")

    assert "`64` (`raw_rx_enable`)" in config
    assert "not part of the authoritative LCI" in config
    assert "/diag/raw/*" in raw
    assert "MUST NOT be implemented by" in raw


def test_zephyr_native_cbor_library_is_marked_legacy() -> None:
    for path in (
        "lichen/lib/native/native.c",
        "lichen/lib/native/include/lichen/native.h",
        "lichen/lib/native/Kconfig",
        "python/src/lichen/interface/__init__.py",
        "python/src/lichen/interface/serial.py",
        "python/src/lichen/interface/tcp.py",
        "python/src/lichen/interface/handler.py",
    ):
        text = read_repo_text(path)
        assert "Legacy" in text or "historical" in text, path
        assert "spec/11-lci.md" in text, path
