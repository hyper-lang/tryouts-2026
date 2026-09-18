"""Thin re-export: the synthetic ``agent_code``-tree builder lives in
``obfuscate.synth`` (package-side fixtures for R7 synthetic-tree CLI mode).

Kept so every existing ``from tests.fixtures.agent_code_tree import ...`` site
keeps working; the canonical implementation is ``obfuscate.synth``.
"""

from obfuscate.synth import *  # noqa: F401,F403
from obfuscate.synth import (  # noqa: F401
    AgentCodeTree,
    build_agent_code_tree,
)