"""Thin re-export: the synthetic PE32+ .NET CLI image builder lives in
``obfuscate.synth`` (package-side fixtures for R7 synthetic-tree CLI mode).

Kept so every existing ``from tests.fixtures import pe_builder`` /
``pe_builder.X`` site keeps working; the canonical implementation is
``obfuscate.synth``.
"""

from obfuscate.synth import *  # noqa: F401,F403
from obfuscate.synth import (  # noqa: F401
    PeBuilder,
    BuildResult,
    Layout,
    StreamInfo,
    TableInfo,
    build_apollo_sample,
    DEFAULT_USER_STRINGS,
    SIGNATURE_BLOCK_SIZE,
)