"""Report building: stable JSON schema, authorization_note, masked secret material (R2/R6).

Single output contract shared by every command.  A `Report` accumulates typed
findings sections (pe, metadata, config, fingerprints, hardening, verify,
canary) and emits a deterministic JSON document with a fixed top-level schema:
`schema_version`, `command`, `tool_version`, `target_image`,
`authorization_note`, and `findings`.  Every section is stamped with the
schema version it was produced under, so findings are self-describing across
schema bumps ("version-stamped findings").

Key hygiene is a hard invariant: AESPSK/key material is only ever emitted as a
deterministic sha256 prefix hash via `mask_key()`.  The JSON boundary performs
a defensive `redact()` of known secret field names on every emission, so raw
key bytes cannot reach a report document, a written file, or a human render.

`dump`/`dumps`/`load`/`loads` are the load/patch-agnostic JSON round-trip
helpers; they are the only JSON path in the package.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile

from obfuscate import __version__

SCHEMA_VERSION = "1.0"

AUTHORIZATION_NOTE = (
    "Authorized CCDC-tryout exercise use only; produced for team-owned or "
    "explicitly authorized infrastructure. Findings are evidence-based lab "
    "observations, never claims of evasion."
)

SECTIONS = ("pe", "metadata", "config", "fingerprints", "hardening", "verify", "canary")

_SECRET_TOKENS = ("aespsk", "psk")
_SECRET_EXACT = frozenset(
    {
        "enckey",
        "deckey",
        "encryptionkey",
        "decryptionkey",
        "encryptkey",
        "decryptkey",
        "passphrase",
        "password",
    }
)


def _normalize_name(name):
    return "".join(ch for ch in str(name).lower() if ch.isalnum())


def _is_sensitive_field(name):
    normalized = _normalize_name(name)
    return any(token in normalized for token in _SECRET_TOKENS) or normalized in _SECRET_EXACT


def mask_key(value, prefix=16):
    """Deterministic masked digest of secret/key material.

    Returns the leading `prefix` hex characters of sha256 of the UTF-8 raw
    value.  The raw value never appears in the output, so the returned string
    is safe for reports and logs.  Same input always yields the same mask.
    """
    if not isinstance(prefix, int) or prefix <= 0:
        raise ValueError("mask_key prefix must be a positive integer")
    if isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raw = str(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:prefix]


def redact(obj):
    """Recursively mask secret field values in a JSON-compatible object.

    Dict values whose field name matches a known secret name (AESPSK/enc-dec
    key material, passphrase, password) are replaced by their masked hash.
    Nested dicts and lists are traversed; all other leaves are left untouched.
    Non-secret fields such as a strong-name public key token are never masked.
    """
    if isinstance(obj, dict):
        return {
            key: (mask_key(value) if _is_sensitive_field(key) else redact(value))
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [redact(item) for item in obj]
    return obj


def dumps(doc):
    """Deterministic JSON text: sorted keys, compact separators, ASCII-safe.

    The same document always serializes to the same bytes, independent of
    platform or Python version.
    """
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def loads(text):
    """Parse JSON text produced by `dumps` (or any JSON document)."""
    return json.loads(text)


def dump(doc, path):
    """Write `doc` as deterministic JSON text to `path`.

    Written atomically (temp file + os.replace) so a partial report never
    appears at the target path.
    """
    text = dumps(doc) + "\n"
    path = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def load(path):
    """Read a JSON document written by `dump` into a plain dict."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def tool_versions():
    """Version stamp: obfuscate, Python, and dnfile (when importable)."""
    versions = {"obfuscate": __version__, "python": platform.python_version()}
    try:
        import dnfile
    except ImportError:
        versions["dnfile"] = None
    else:
        versions["dnfile"] = getattr(dnfile, "__version__", None) or "unknown"
    return versions


def _value_schema(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        if not value:
            return {"list": "empty"}
        shapes = []
        for item in value:
            shape = _value_schema(item)
            if shape not in shapes:
                shapes.append(shape)
        return {"list": shapes}
    if isinstance(value, dict):
        entries = []
        for key in sorted(value, key=str):
            entries.append((str(key), _value_schema(value[key])))
        return {"dict": entries}
    raise TypeError(f"unsupported value type in JSON document: {type(value).__name__}")


def _as_doc(value):
    if isinstance(value, Report):
        return value.to_dict()
    if isinstance(value, dict):
        return value
    raise TypeError("expected a Report or a JSON-compatible dict")


def schema_of(doc):
    """Canonical structural schema of a JSON-compatible object or Report.

    Maps every value to its value type, dicts to their sorted key->schema
    mapping, and lists to the unique schemas of their elements.  Two documents
    with equal structure (regardless of content values) have equal schemas.
    """
    return _value_schema(_as_doc(doc))


def schema_is_stable(a, b):
    """True when two reports/documents have identical JSON structure.

    Structure means key sets and value types only; content values are ignored,
    so runs with different random content compare equal as long as the schema
    is fixed.  Accepts Report objects or plain dicts (e.g. loaded via `load`).
    """
    return schema_of(a) == schema_of(b)


class Report:
    """Accumulates typed findings and emits deterministic JSON and human text.

    Top-level JSON schema is fixed; `findings` always carries every section
    key, with sections a command does not produce left as null.  Mutating
    methods return `self` for chaining.
    """

    def __init__(
        self,
        command,
        *,
        tool_version=None,
        target_image=None,
        schema_version=SCHEMA_VERSION,
    ):
        if not isinstance(command, str) or not command:
            raise ValueError("Report requires a non-empty command name")
        self._command = command
        self._schema_version = schema_version
        self._tool_version = dict(tool_version) if tool_version else tool_versions()
        self._target_image = target_image
        self._sections = {
            name: ([] if name in ("fingerprints", "verify") else None) for name in SECTIONS
        }

    def _stamp(self, obj):
        return {**dict(obj), "schema_version": self._schema_version}

    def _set(self, name, section):
        if section is None:
            self._sections[name] = None
        elif isinstance(section, dict):
            self._sections[name] = self._stamp(section)
        else:
            raise TypeError(f"{name} section must be a dict or None")
        return self

    def _append(self, name, entry):
        if not isinstance(entry, dict):
            raise TypeError(f"{name} entries must be dicts")
        self._sections[name].append(self._stamp(entry))
        return self

    def with_pe(self, section):
        """Record the PE identity section (R2)."""
        return self._set("pe", section)

    def with_metadata(self, section):
        """Record the .NET CLI metadata identity section (R2)."""
        return self._set("metadata", section)

    def with_config(self, section):
        """Record the extracted embedded C2 config section (R2)."""
        return self._set("config", section)

    def add_fingerprint(self, finding):
        """Append one catalog match with evidence offset + mitigation (R2/R4)."""
        return self._append("fingerprints", finding)

    def with_hardening(self, section):
        """Record the hardening summary for the run (R3)."""
        return self._set("hardening", section)

    def add_assertion(self, assertion):
        """Append one verify assertion result (R6)."""
        return self._append("verify", assertion)

    def with_canary(self, section):
        """Record the lab canary harness run (R6)."""
        return self._set("canary", section)

    def to_dict(self):
        """The full redacted document; the only source for JSON and text output."""
        findings = {
            name: (list(self._sections[name]) if isinstance(self._sections[name], list) else self._sections[name])
            for name in SECTIONS
        }
        return redact(
            {
                "schema_version": self._schema_version,
                "command": self._command,
                "tool_version": dict(self._tool_version),
                "target_image": self._target_image,
                "authorization_note": AUTHORIZATION_NOTE,
                "findings": findings,
            }
        )

    def json(self):
        """Deterministic JSON text of the redacted report."""
        return dumps(self.to_dict())

    def json_bytes(self):
        return self.json().encode("utf-8")

    def write(self, path):
        """Write the redacted report as deterministic JSON to `path`."""
        dump(self.to_dict(), path)

    def render_text(self):
        """Human-readable rendering of the redacted report (no raw material)."""
        doc = self.to_dict()
        out = [
            f"obfuscate {doc['command']} report",
            f"schema_version: {doc['schema_version']}",
            f"authorization_note: {doc['authorization_note']}",
            f"target_image: {doc['target_image']}",
            "tool_version:",
        ]
        for key in sorted(doc["tool_version"]):
            out.append(f"  {key}: {doc['tool_version'][key]}")
        for name in SECTIONS:
            value = doc["findings"][name]
            if value is None:
                continue
            if isinstance(value, (dict, list)) and not value:
                continue
            out.append("")
            out.append(f"## {name}")
            _emit(value, out)
        return "\n".join(out) + "\n"

    def __str__(self):
        return self.render_text()

    def __bytes__(self):
        return self.json_bytes()


def _emit(value, out, indent=0):
    pad = "  " * indent
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            item = value[key]
            if isinstance(item, (dict, list)):
                out.append(f"{pad}{key}:")
                _emit(item, out, indent + 1)
            else:
                out.append(f"{pad}{key}: {item}")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                out.append(f"{pad}-")
                _emit(item, out, indent + 1)
            else:
                out.append(f"{pad}- {item}")