"""Thin re-export: the Apollo-shaped sample fixture and its constants live in
``obfuscate.synth`` (package-side fixtures for R7 synthetic-tree CLI mode).

Kept so every existing ``from tests.fixtures import samples`` /
``from tests.fixtures.samples import ...`` site keeps working; the canonical
implementation is ``obfuscate.synth``.
"""

from obfuscate.synth import *  # noqa: F401,F403
from obfuscate.synth import (  # noqa: F401
    sample_result,
    sample_bytes,
    sample_layout,
    LAYOUT,
    write_sample_to,
    # Names the test modules import directly by `from tests.fixtures.samples import`.
    DEFAULT_ASSEMBLY_NAME,
    DEFAULT_CALLBACK_URL,
    DEFAULT_COMPANY,
    DEFAULT_COPYRIGHT,
    DEFAULT_MODULE_NAME,
    DEFAULT_PIPE_NAME,
    DEFAULT_PRODUCT,
    DEFAULT_USER_AGENT,
    SAMPLE_ASSEMBLY_VERSION,
    SAMPLE_MODULE_GUID,
    SAMPLE_MVID,
)