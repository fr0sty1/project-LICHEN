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
        # ponytail: acceptance criteria says "frozen/prototype-only" not "non-authoritative"
        assert "FROZEN / PROTOTYPE-ONLY" in text or "Historical" in text, path
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
    # ponytail: simplified to "Do not implement" in status banner
    assert "Do not implement" in raw or "MUST NOT be implemented" in raw


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


def test_lci_messaging_paths_use_msg_inbox_contract() -> None:
    lci = read_repo_text("spec/11-lci.md")
    apps = read_repo_text("spec/12-apps.md")
    readme = read_repo_text("README.md")
    support = read_repo_text("docs/python-native-tui-support.md")
    meshtastic = read_repo_text("docs/meshtastic-compat-dev.md")

    assert "POST /msg/inbox" in lci
    assert "GET /msg/inbox" in lci
    assert "</msg/ack>;rt=\"msg.ack\";ct=60" in lci
    assert "POST coap://[destination]/msg/inbox" in apps
    assert "GET coap://[node]/msg/inbox" in apps
    assert "POST coap://[sender]/msg/ack" in apps
    assert "POST coap://[node]/msg/inbox" in readme
    assert "GET  coap://[node]/msg/inbox" in readme
    assert "POST /msg/inbox" in support
    assert "GET /msg/inbox" in support
    assert "POST /msg/ack" in support
    assert "`TEXT_MESSAGE_APP` (1) | `/msg/inbox`" in meshtastic
    assert "Zephyr `/msg/inbox`" in meshtastic
    assert "POST /msg\n" not in lci
    assert "/msg/outbox" not in lci
    assert "legacy Python demo `/messages` resource is not part of LCI" in lci


def test_top_level_readme_describes_native_lci_not_legacy_cbor() -> None:
    readme = read_repo_text("README.md")

    assert "LICHEN Native LCI" in readme
    assert "IPv6 + CoAP resources from `spec/11-lci.md`" in readme
    assert "retained only for historical prototype compatibility" in readme
    assert "Clean-sheet design: CBOR" not in readme
    assert "identical framing across BLE/USB/serial/IP" not in readme


def test_lci_mesh_access_prefers_direct_ipv6_with_optional_proxy() -> None:
    lci = read_repo_text("spec/11-lci.md")
    lci_words = " ".join(lci.split())
    resources = read_repo_text("python/src/lichen/coap/resources.py")

    assert "direct IPv6 + CoAP path is the authoritative" in lci_words
    assert "No special proxy resource is required" in lci_words
    assert "`/mesh` is not an LCI forward-proxy resource" in lci_words
    assert "optional RFC 7252 forward proxy at `/proxy`" in lci_words
    assert "Clients MUST NOT require `/proxy`" in lci_words
    assert "direct mesh CoAP reachability, optional `/proxy`" in lci_words
    assert '</mesh>;rt="proxy"' not in lci
    assert "mesh proxy" not in lci

    assert "authoritative LCI mesh access model remains direct IPv6" in resources
    assert 'rt = "proxy"' in resources
