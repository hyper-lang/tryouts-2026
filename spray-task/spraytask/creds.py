"""Credentials model, --hash parsing, precedence resolution, and masking (R2).

A ``Credential`` holds a domain, a user, and exactly one authentication secret:
either a password or an NT hash (for pass-the-hash). It is immutable and never
exposes its secret through ``repr``/``str`` or the ``masked_repr``/``redact``
helpers, which the CLI/report layers reuse so passwords and hashes never reach
stdout, the JSON report, or logs.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Optional

#: Byte-for-byte the null LM hash impacket compares an empty LM response against.
NULL_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"

_HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_HASH_PAIR_RE = re.compile(r"^([0-9a-fA-F]{32}):([0-9a-fA-F]{32})$")

_MASKED = "<redacted>"

#: Public alias of the masking marker so the report/CLI layers reuse creds'
#: replacement value instead of defining their own (R2)--- never re-implement
#: masking outside this module.
MASKED = _MASKED


def parse_nt_hash(raw: str) -> str:
    """Normalize ``--hash`` input into a canonical ``<lm>:<nt>`` pair string.

    Accepts the pair form ``aad3b435b51404eeaad3b435b51404ee:<NTLMHASH>`` or a
    bare 32-hex NT hash. A bare NT hash is paired with the standard null LM
    hash constant, so the result is always immediately usable as impacket's
    pass-the-hash ``hash=`` parameter. Hex digits are lowercased.
    """
    if not isinstance(raw, str):
        raise TypeError(f"hash must be a string, got {type(raw).__name__}")
    stripped = raw.strip()
    pair = _HASH_PAIR_RE.fullmatch(stripped)
    if pair:
        return f"{pair.group(1).lower()}:{pair.group(2).lower()}"
    if _HEX32_RE.fullmatch(stripped):
        return f"{NULL_LM_HASH}:{stripped.lower()}"
    raise ValueError(
        "--hash must be a 32-hex NT hash or a '<lm32hex>:<nt32hex>' pair, "
        f"got {stripped!r}"
    )


def masked_repr(cred: Optional["Credential"]) -> str:
    """A representation that never contains the password or hash."""
    if cred is None:
        return "Credential(<none>)"
    if cred.password is not None:
        secret = f"password={_MASKED}"
    else:
        secret = f"nt_hash={_MASKED}"
    return f"Credential(domain={cred.domain!r}, user={cred.user!r}, {secret})"


def redact(cred: Optional["Credential"]) -> Optional[dict]:
    """Safe dict form for reports/logs: identity fields only, never the secret.

    ``auth_type`` is ``"password"`` or ``"nt_hash"`` so a reader can tell the
    authentication kind without ever seeing the secret value.
    """
    if cred is None:
        return None
    return {
        "domain": cred.domain,
        "user": cred.user,
        "auth_type": cred.auth_type,
    }


@dataclass(frozen=True, repr=False)
class Credential:
    """Domain/user plus exactly one secret: a password or an NT hash.

    ``nt_hash`` is normalized to canonical ``<lm>:<nt>`` pair form on
    construction (see :func:`parse_nt_hash`). The raw fields are the only way
    to reach the secret; every string representation is masked.
    """

    domain: str = ""
    user: str = ""
    password: Optional[str] = None
    nt_hash: Optional[str] = None

    def __post_init__(self) -> None:
        if (self.password is None) == (self.nt_hash is None):
            raise ValueError("Credential requires exactly one of password or nt_hash")
        if self.nt_hash is not None:
            object.__setattr__(self, "nt_hash", parse_nt_hash(self.nt_hash))

    @property
    def auth_type(self) -> str:
        return "password" if self.password is not None else "nt_hash"

    @property
    def lm_hash(self) -> Optional[str]:
        """LM half of the hash pair, or None for password credentials."""
        if self.nt_hash is None:
            return None
        return self.nt_hash.split(":", 1)[0]

    @property
    def nthash(self) -> Optional[str]:
        """NT half of the hash pair, or None for password credentials."""
        if self.nt_hash is None:
            return None
        return self.nt_hash.split(":", 1)[1]

    def __repr__(self) -> str:
        return masked_repr(self)


def resolve_for_host(
    host_key: str,
    overrides: Mapping[str, Credential],
    global_cred: Optional[Credential] = None,
) -> Optional[Credential]:
    """Return the credential to use for a host (R2 precedence).

    A per-host override from the host list file wins over the global CLI
    credential; hosts without an override use the global credential (which may
    itself be None when the tool is given only per-host creds).
    """
    override = overrides.get(host_key)
    return override if override is not None else global_cred