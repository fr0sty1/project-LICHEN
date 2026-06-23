LICHEN Rust Workspace
====================

Rust implementation of the LICHEN protocol stack (LoRa IPv6 CoAP Hybrid Extended Network). This workspace contains no_std library crates for the embedded protocol stack (lichen-core, lichen-link, lichen-schc, lichen-coap, lichen-senml, lichen-node) and std-requiring crates for the Linux border router, network simulator, and CLI utilities (lichen-gateway, lichen-sim, lichen-apps). All implementations must produce identical output for the test vectors in `test/vectors/`.
