"""Apollo/Mythic fingerprint catalog: versioned, tiered full-string + fragment entries (R4).

This module is the single authority shared by ``inspect``, ``harden``, and
``verify``.  It contains two tiers of entries:

- **Full-string entries**: exact plaintext literals found in .NET metadata,
  ``#Strings``, ``#Blob``, or ``#US`` heaps.  Each entry carries an encoding
  hint (UTF-8 for ``#Strings``/``#Blob``/metadata, UTF-16LE for ``#US``), a
  mitigation category, and flags controlling whether the pass is allowed to
  scrub or rename the entry in-place.

- **Fragment entries**: partial/segmented substrings that Apollo may assemble
  at runtime.  These match as substrings during scanning so that a
  deliberately-split literal cannot pass verification by being absent in its
  full form.  Fragment status is conservative: any fragment that *might* be
  required for agent function is protect-by-default (reported, never edited).

Public API:

- ``CATALOG``: the full ordered list of entries.
- ``CATALOG_VERSION``: bumped when the catalog changes.
- ``by_mitigation(mitigation)``: entries matching exactly one mitigation.
- ``scrubbable_entries()``: full-string entries where ``scrubbable=True``.
- ``all_fragments()``: fragment-tier entries.

Keys are never logged; AESPSK material only appears as a sha256 prefix hash
in reports.
"""

from __future__ import annotations

from typing import List, Literal, Sequence, Union


# ---------------------------------------------------------------------------
# Catalog version — bump when entries change.
# ---------------------------------------------------------------------------

CATALOG_VERSION = "1.1"

# Mitigation categories per R4.
Mitigation = Literal["metadata", "attributes", "string_scrub", "rebuild_config", "runtime", "none"]

# Encoding hint for full-string entries.
Encoding = Literal["utf-8", "utf-16le"]


# ---------------------------------------------------------------------------
# Entry types
# ---------------------------------------------------------------------------


class EntryBase:
    """Shared fields for both full-string and fragment entries."""

    __slots__ = ("text", "mitigation", "scrubbable", "rename_safe", "reflect_sensitive")

    def __init__(
        self,
        text: str,
        mitigation: Mitigation,
        scrubbable: bool,
        rename_safe: bool,
        reflect_sensitive: bool,
    ):
        self.text = text
        self.mitigation = mitigation
        self.scrubbable = scrubbable
        self.rename_safe = rename_safe
        self.reflect_sensitive = reflect_sensitive

    def to_dict(self) -> dict:
        d: dict = {
            "text": self.text,
            "mitigation": self.mitigation,
            "scrubbable": self.scrubbable,
            "rename_safe": self.rename_safe,
            "reflect_sensitive": self.reflect_sensitive,
        }
        if isinstance(self, FullStringEntry):
            d["encoding"] = self.encoding
        return d


class FullStringEntry(EntryBase):
    """Full-string entry: exact literal with an encoding hint."""

    __slots__ = ("encoding",)

    def __init__(
        self,
        text: str,
        encoding: Encoding,
        mitigation: Mitigation,
        scrubbable: bool,
        rename_safe: bool,
        reflect_sensitive: bool = False,
    ):
        super().__init__(text, mitigation, scrubbable, rename_safe, reflect_sensitive)
        self.encoding = encoding


class FragmentEntry(EntryBase):
    """Fragment entry: partial literal matched as a substring during scans."""

    def __init__(
        self,
        text: str,
        mitigation: Mitigation,
        scrubbable: bool,
        rename_safe: bool,
        reflect_sensitive: bool = False,
    ):
        super().__init__(text, mitigation, scrubbable, rename_safe, reflect_sensitive)


# Type alias for the catalog.
Entry = Union[FullStringEntry, FragmentEntry]


# ---------------------------------------------------------------------------
# Catalog — versioned, authoritative list of Apollo/Mythic indicators (R4).
#
# Full-string entries carry an encoding that tells the scan which byte
# representation to search for in the binary.  Fragment entries are always
# matched as raw UTF-8 substrings (the scan layer decides the encoding
# context).
# ---------------------------------------------------------------------------


def _fs(
    text: str,
    encoding: Encoding,
    mitigation: Mitigation,
    scrubbable: bool,
    rename_safe: bool,
    reflect_sensitive: bool = False,
) -> FullStringEntry:
    return FullStringEntry(text, encoding, mitigation, scrubbable, rename_safe, reflect_sensitive)


def _frag(
    text: str,
    mitigation: Mitigation,
    scrubbable: bool,
    rename_safe: bool,
    reflect_sensitive: bool = False,
) -> FragmentEntry:
    return FragmentEntry(text, mitigation, scrubbable, rename_safe, reflect_sensitive)


# ---- Metadata / identity (UTF-8 in #Strings / #Blob) --------------------

_METADATA_ENTRIES: List[Entry] = [
    # Assembly/namespace/type identifiers — reflect-sensitive: never edited
    # in place.  Renamed at Mythic build time (rebuild_config), never via the
    # metadata/attributes/string_scrub passes (R4).
    _fs("Apollo", "utf-8", "rebuild_config", False, False, True),
    _fs("Apollo.exe", "utf-8", "rebuild_config", False, False, True),
    _fs("ApolloInterop", "utf-8", "rebuild_config", False, False, True),
    _fs("Mythic.Rest", "utf-8", "rebuild_config", False, False, True),
    _fs("Mythic.Structs", "utf-8", "rebuild_config", False, False, True),
    _fs("Mythic", "utf-8", "rebuild_config", False, False, True),
    # Public key token — fingerprint, not secret.
    _fs("b03f5f7f11d50a3a", "utf-8", "metadata", False, False),
    # Target framework.
    _fs(".NETFramework,Version=v4.0", "utf-8", "metadata", False, False),
    # Strong-name marker in assembly flags.
    _fs("StrongNameIdentity", "utf-8", "metadata", False, False),
    # Program entry type — reflect-sensitive.
    _fs("Program", "utf-8", "rebuild_config", False, False, True),
    # mscorlib assembly reference.
    _fs("mscorlib", "utf-8", "metadata", False, False),
    # Reflected interface/type names — reflect-sensitive.
    _fs("ICommand", "utf-8", "rebuild_config", False, False, True),
    _fs("HttpRestClient", "utf-8", "rebuild_config", False, False, True),
    _fs("JsonObject", "utf-8", "rebuild_config", False, False, True),
    # .NET framework 4.8 marker (enables CLR-level AMSI-on-.NET).
    _fs(".NETFramework,Version=v4.8", "utf-8", "metadata", False, False),
]

# ---- #Strings / #Blob attribute text (UTF-8) ----------------------------

_ATTRIBUTE_ENTRIES: List[Entry] = [
    _fs("Mythic Apollo Operations Team", "utf-8", "attributes", False, False),
    _fs("Apollo Agent", "utf-8", "attributes", False, False),
    _fs(
        "Copyright (c) 2026 MythicDev. Authorized red-team exercise use only.",
        "utf-8",
        "attributes",
        False,
        False,
    ),
    _fs(".NETFramework,Version=v4.0", "utf-8", "attributes", False, False),
    # DebuggableAttribute is detected by name (metadata) and value (attributes).
    _fs("DebuggableAttribute", "utf-8", "attributes", False, False),
    # .rsrc VS_VERSION_INFO StringFileInfo values (equal-length in-place scrub).
    _fs("Mythic Apollo Operations Team", "utf-8", "attributes", False, False),
    _fs("Apollo Agent", "utf-8", "attributes", False, False),
    _fs("Apollo.exe", "utf-8", "attributes", False, False),
    _fs(
        "Copyright (c) 2026 MythicDev. Authorized red-team exercise use only.",
        "utf-8",
        "attributes",
        False,
        False,
    ),
    _fs("4.0.0.0", "utf-8", "attributes", False, False),
]

# ---- #US heap strings (UTF-16LE) ----------------------------------------

_US_ENTRIES: List[Entry] = [
    # Well-known default user-agent — scrubbable.
    _fs(
        "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
        "utf-16le",
        "string_scrub",
        True,
        True,
    ),
    # Config-critical values — rebuild at Mythic build time.
    _fs("https://192.168.10.20:8443", "utf-16le", "rebuild_config", False, False),
    _fs("/api/v1.4/agent/", "utf-16le", "rebuild_config", False, False),
    _fs("killdate", "utf-16le", "string_scrub", True, True),
    _fs("encrypted_exchange_check", "utf-16le", "rebuild_config", False, False),
    _fs(r"\\.\pipe\Mythic_Agent", "utf-16le", "rebuild_config", False, False),
    _fs("MythicSession", "utf-16le", "rebuild_config", False, False),
    _fs("q", "utf-16le", "rebuild_config", False, False),
    # Scrubbable agent-facing strings.
    _fs(
        "Apollo -- Malleable C2 Profile Agent",
        "utf-16le",
        "string_scrub",
        True,
        True,
    ),
    _fs(
        "Invalid command. Use 'help' to list available commands.",
        "utf-16le",
        "string_scrub",
        True,
        True,
    ),
    _fs(
        "An error occurred while processing the command.",
        "utf-16le",
        "string_scrub",
        True,
        True,
    ),
    # Manufacturer marker.
    _fs("Mythic", "utf-16le", "string_scrub", True, True),
]

# ---- .rsrc VS_VERSION_INFO (UTF-16LE in StringFileInfo) -----------------

_VS_VERSION_ENTRIES: List[Entry] = [
    _fs("CompanyName", "utf-16le", "attributes", False, False),
    _fs("FileDescription", "utf-16le", "attributes", False, False),
    _fs("FileVersion", "utf-16le", "attributes", False, False),
    _fs("InternalName", "utf-16le", "attributes", False, False),
    _fs("OriginalFilename", "utf-16le", "attributes", False, False),
    _fs("ProductName", "utf-16le", "attributes", False, False),
    _fs("ProductVersion", "utf-16le", "attributes", False, False),
    _fs("Assembly Version", "utf-16le", "attributes", False, False),
    _fs("Copyright", "utf-16le", "attributes", False, False),
]

# ---- Fragment tier (partial / segmented literals) ------------------------
#
# These are substrings that Apollo may assemble at runtime (URL/API-path
# prefixes, mid-string pieces, `-`/`/` delimited segments).  They are
# matched as substrings during scanning so that a deliberately-split literal
# cannot pass verification by being absent in its full form.
#
# Fragment status is conservative by default: any fragment that *might* be
# required for agent function is reported, never edited.

_FRAGMENT_ENTRIES: List[Entry] = [
    # URL prefix fragment (callback config) — protect-by-default, rebuild.
    _frag("https://", "rebuild_config", False, False),
    # Callback-host / port fragments — config-critical, rebuild.
    _frag("192.168.10.20", "rebuild_config", False, False),
    _frag(":8443", "rebuild_config", False, False),
    # API-path prefix.
    _frag("/api/", "rebuild_config", False, False),
    # API-path versioned segment.
    _frag("/v1.4/", "rebuild_config", False, False),
    # API-path endpoint.
    _frag("/agent/", "rebuild_config", False, False),
    # Mythic HTTP API path family markers — rebuild (malleable paths).
    _frag("checkin", "rebuild_config", False, False),
    _frag("login", "rebuild_config", False, False),
    _frag("submit", "rebuild_config", False, False),
    _frag("download", "rebuild_config", False, False),
    # Pipe-name prefix — config-critical, rebuild.
    _frag("\\\\.\\pipe\\", "rebuild_config", False, False),
    # Config key names — protect-by-default, rebuild.
    _frag("AESPSK", "rebuild_config", False, False),
    _frag("payload_uuid", "rebuild_config", False, False),
    # Split killdate fragments — too generic to scrub individually.
    # Reported as `none` (never edited); the intact `killdate` full-string
    # remains scrubbable.
    _frag("kill", "none", False, False),
    _frag("date", "none", False, False),
    # Mythic encrypts marker.
    _frag("mythic_encrypts", "none", False, False),
    # encryption-related substrings.
    _frag("encrypt", "none", False, False),
    _frag("decrypt", "none", False, False),
    # Assembly culture (default empty; reported, never edited).
    _frag("neutral", "none", False, False),
    # Embedded resource markers.
    _frag(".resources", "none", False, False),
]


# ---------------------------------------------------------------------------
# Catalog — flat, ordered, versioned.
# ---------------------------------------------------------------------------

CATALOG: List[Entry] = (
    _METADATA_ENTRIES
    + _ATTRIBUTE_ENTRIES
    + _US_ENTRIES
    + _VS_VERSION_ENTRIES
    + _FRAGMENT_ENTRIES
)


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def by_mitigation(mitigation: str) -> List[Entry]:
    """Return entries whose ``mitigation`` matches exactly."""
    return [e for e in CATALOG if e.mitigation == mitigation]


def scrubbable_entries() -> List[FullStringEntry]:
    """Return full-string entries where ``scrubbable=True``."""
    return [e for e in CATALOG if isinstance(e, FullStringEntry) and e.scrubbable]


def all_fragments() -> List[FragmentEntry]:
    """Return all fragment-tier entries."""
    return [e for e in CATALOG if isinstance(e, FragmentEntry)]
