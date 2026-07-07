"""Test configuration for legacy LICHEN Native CBOR interface tests.

Enables legacy CBOR protocol support to suppress deprecation warnings during tests.
"""

import os

# Enable legacy CBOR protocol for tests in this directory
os.environ["LICHEN_LEGACY_CBOR"] = "1"
