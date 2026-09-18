"""JSON report writer (R5 / acceptance 4): stable, masked, atomic.

``write_report`` serializes one run into a single JSON document whose schema
does not move between runs, so QA can diff it directly:

* ``metadata`` -- ISO ``timestamp``, the CLI arguments under ``cli_args`` with
  every secret masked, and a ``secrets_masked: true`` marker;
* ``hosts``    -- one record per host: ``address``, ``port``, the backend
  ``methods`` attempted in order, the final ``status``, and a ``detail``;
* ``summary``  -- ``status_counts`` (every R5 status, zero-filled, in
  canonical order) and ``elapsed_seconds``.

Secret handling reuses :mod:`spraytask.creds`: credential objects go through
``redact()`` and argv strings that equal a raw ``-p/--password`` or ``--hash``
value are replaced with the ``MASKED`` marker. Masking is never re-implemented
here; the final byte-level sweep also scrubs seeded secrets from any embedded
text (e.g. a command line that happened to quote the password).

The file is written atomically -- the document is dumped to a temp file in the
destination directory and then ``os.replace``\\ d into place -- so a crash
mid-write can never corrupt a previously written report.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from spraytask.creds import Credential, MASKED, redact

#: Default report path used by the CLI when ``--report`` is not given (R5).
DEFAULT_REPORT_PATH = "spray-task-report.json"

#: Canonical per-status order for ``summary.status_counts`` (R5), identical to
#: ``spraytask.backends.base.ALL_STATUSES``. Pinned here deliberately: the
#: report schema must not depend on backend-internal modules, and the seven
#: values are the R5 spec, not re-implemented masking.
_STATUS_ORDER: tuple[str, ...] = (
    "ok",
    "auth_failed",
    "no_admin",
    "unreachable",
    "payload_too_large",
    "method_error",
    "error",
)

#: Argument/field names whose values are secrets and must become ``MASKED``.
_SECRET_KEYS = frozenset(
    {"password", "pass", "pwd", "hash", "nt_hash", "nthash", "secret"}
)


def _iso_now() -> str:
    """Current UTC time in ISO 8601 form."""
    return datetime.now(timezone.utc).isoformat()


# --- secret gathering & masking -------------------------------------------------


def _collect_secrets(node: Any, secrets: set[str]) -> None:
    """Seed ``secrets`` with every secret value reachable in ``node``.

    Walks mappings, sequences, dataclasses and plain objects; a
    ``Credential`` contributes its password or NT hash, and any field or key
    whose name is in ``_SECRET_KEYS`` contributes its string value (the raw
    ``-p/--password`` / ``--hash`` argv fragments). These values are later
    scrubbed out of the serialized document byte-for-byte. Leaf values
    (including enum members, whose ``__objclass__`` would otherwise point
    back at the enum class and recurse forever) terminate the walk.
    """
    if isinstance(node, (str, bytes, int, float, bool, type, enum.Enum)):
        return
    if isinstance(node, Credential):
        if node.password:
            secrets.add(node.password)
        if node.nt_hash:
            secrets.add(node.nt_hash)
        return
    if isinstance(node, Mapping):
        for key, value in node.items():
            if isinstance(key, str) and key.lower() in _SECRET_KEYS:
                if isinstance(value, str) and value:
                    secrets.add(value)
                else:
                    _collect_secrets(value, secrets)
            else:
                _collect_secrets(value, secrets)
        return
    if isinstance(node, (list, tuple)):
        for value in node:
            _collect_secrets(value, secrets)
        return
    if dataclasses.is_dataclass(node):
        for field in dataclasses.fields(type(node)):
            field_value = getattr(node, field.name)
            if field.name.lower() in _SECRET_KEYS:
                if isinstance(field_value, str) and field_value:
                    secrets.add(field_value)
                else:
                    _collect_secrets(field_value, secrets)
            else:
                _collect_secrets(field_value, secrets)
        return
    if hasattr(node, "__dict__"):
        _collect_secrets(vars(node), secrets)


def _mask_dataclass(node: Any, secrets: set[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field in dataclasses.fields(type(node)):
        field_value = getattr(node, field.name)
        if field.name.lower() in _SECRET_KEYS:
            out[field.name] = MASKED if field_value is not None else None
        else:
            out[field.name] = _mask_node(field_value, secrets)
    return out


def _mask_node(node: Any, secrets: set[str]) -> Any:
    """Mask secrets anywhere in ``node``, producing only JSON-safe values.

    * credential objects are replaced by ``redact()`` output,
    * keys named like secrets get ``MASKED`` (None stays None),
    * any string equal to a seeded secret becomes ``MASKED``,
    * dataclasses and plain objects are walked field-by-field.
    """
    if isinstance(node, Credential):
        return redact(node)
    if isinstance(node, Mapping):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if (
                isinstance(key, str)
                and key.lower() in _SECRET_KEYS
                and value is not None
            ):
                out[key] = MASKED
            else:
                out[key] = _mask_node(value, secrets)
        return out
    if isinstance(node, (list, tuple)):
        return [_mask_node(value, secrets) for value in node]
    if isinstance(node, str):
        return MASKED if node and node in secrets else node
    if node is None or isinstance(node, (int, float, bool)):
        return node
    if dataclasses.is_dataclass(node):
        return _mask_dataclass(node, secrets)
    if hasattr(node, "__dict__"):
        return _mask_node(vars(node), secrets)
    return str(node)


def _scrub_substrings(text: str, secrets: set[str]) -> str:
    """Salt the serialized JSON so no seeded secret survives as a substring.

    Replaces both the raw secret and its JSON-escaped form (matters when the
    value contains quotes or backslashes). Longer secrets first, so a secret
    that prefixes another cannot leave a remainder behind.
    """
    forms: set[str] = set(secrets)
    for secret in secrets:
        forms.add(json.dumps(secret, ensure_ascii=False)[1:-1])
    for form in sorted(forms, key=len, reverse=True):
        text = text.replace(form, MASKED)
    return text


# --- document sections -----------------------------------------------------------


def _coerce_status(raw: Any) -> str:
    """A stable status string; ``None``/unknown input cannot yield ``None``.

    Enum members are unwrapped to their ``.value`` first: a ``str``-mixed
    enum (``Status.OK == "ok"``) is still an ``Enum`` and ``str(member)``
    would yield the member *name* (e.g. ``"Status.OK"``), not the value.
    """
    if raw is None:
        return "error"
    if isinstance(raw, enum.Enum):
        raw = raw.value
    elif hasattr(raw, "value") and not isinstance(
        raw, (str, bytes, list, dict, tuple)
    ):
        raw = raw.value
    return str(raw)


def _host_record(item: Any) -> dict[str, Any]:
    """Normalize one host result into the fixed ``hosts`` record shape.

    Accepts a mapping (``address``/``port``/``methods``/``status``/``detail``)
    or any object exposing those attributes (e.g. a ``BackendResult`` plus a
    host reference). ``methods`` keeps the attempted-backend order.
    """
    if isinstance(item, Mapping):
        address = item.get("address")
        if address is None:
            address = item.get("host")
        port = item.get("port", None)
        raw_methods = item.get("methods")
        if raw_methods is None:
            raw_methods = item.get("attempted_methods")
        if raw_methods is None:
            raw_methods = item.get("method")
        status = _coerce_status(item.get("status"))
        detail = item.get("detail")
    else:
        address = getattr(item, "address", None)
        if address is None:
            address = getattr(item, "host", None)
        port = getattr(item, "port", None)
        raw_methods = getattr(item, "methods", None)
        if raw_methods is None:
            raw_methods = getattr(item, "method", None)
        status = _coerce_status(getattr(item, "status", None))
        detail = getattr(item, "detail", None)
    if raw_methods is None:
        methods: list[str] = []
    elif isinstance(raw_methods, str):
        methods = [raw_methods]
    else:
        methods = [str(method) for method in raw_methods]
    return {
        "address": str(address) if address is not None else "",
        "port": int(port) if port is not None else None,
        "methods": methods,
        "status": status,
        "detail": str(detail) if detail is not None else "",
    }


def _metadata_dict(run_meta: Any, secrets: set[str]) -> dict[str, Any]:
    """The ``metadata`` section: timestamp, masked CLI args, marker."""
    timestamp = _iso_now()
    cli_args: Any = {}
    if isinstance(run_meta, Mapping):
        raw_timestamp = run_meta.get("timestamp")
        if isinstance(raw_timestamp, str) and raw_timestamp:
            timestamp = raw_timestamp
        cli_args = run_meta.get("cli_args", {})
    if not isinstance(cli_args, Mapping):
        cli_args = vars(cli_args) if hasattr(cli_args, "__dict__") else {}
    meta: dict[str, Any] = {
        "timestamp": timestamp,
        "cli_args": _mask_node(cli_args, secrets),
        "secrets_masked": True,
    }
    if isinstance(run_meta, Mapping):
        for key, value in run_meta.items():
            if key in ("timestamp", "cli_args", "secrets_masked"):
                continue
            meta[key] = _mask_node(value, secrets)
    return meta


def _summary_dict(
    summary: Any, records: Sequence[dict[str, Any]], secrets: set[str]
) -> dict[str, Any]:
    """The ``summary`` section: zero-filled status counts + elapsed seconds.

    ``status_counts`` from ``summary`` wins when present (the runner
    aggregates); otherwise the counts come from the host records so the
    schema is identical on empty runs and fallback callers.
    """
    counts: dict[str, int] = {status: 0 for status in _STATUS_ORDER}
    provided: Any = None
    elapsed: Any = 0.0
    if isinstance(summary, Mapping):
        provided = summary.get("status_counts")
        elapsed = summary.get("elapsed_seconds", 0.0)
    if isinstance(provided, Mapping):
        for raw_status, count in provided.items():
            key = _coerce_status(raw_status)
            if key not in counts:
                continue
            try:
                counts[key] = int(count)
            except (TypeError, ValueError):
                counts[key] = 0
    else:
        for record in records:
            key = record["status"]
            if key in counts:
                counts[key] += 1
    try:
        elapsed_seconds = float(elapsed)
    except (TypeError, ValueError):
        elapsed_seconds = 0.0
    return {
        "status_counts": counts,
        "elapsed_seconds": elapsed_seconds,
    }


# --- atomic write ----------------------------------------------------------------


def _atomic_write(path: Any, text: str) -> None:
    """Write ``text`` to ``path`` via a same-directory temp file + rename.

    On any failure the temp file is removed and the previous report at
    ``path`` (if any) is left untouched.
    """
    path = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(path))
    prefix = f"{os.path.basename(path)}."
    fd, tmp_path = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# --- public entry point ------------------------------------------------------------


def write_report(
    path: Any,
    *,
    run_meta: Any,
    host_results: Sequence[Any],
    summary: Any,
) -> str:
    """Serialise one run to ``path`` and return the resolved path.

    ``run_meta`` supplies ``timestamp`` (ISO string, optional) and ``cli_args``
    (the raw CLI arguments, secrets masked on output); ``host_results`` is a
    sequence of per-host records (see :func:`_host_record`); ``summary`` holds
    ``status_counts`` and ``elapsed_seconds``.
    """
    secrets: set[str] = set()
    _collect_secrets(run_meta, secrets)
    _collect_secrets(host_results, secrets)
    _collect_secrets(summary, secrets)

    records = [_host_record(item) for item in host_results]
    document = {
        "metadata": _metadata_dict(run_meta, secrets),
        "hosts": records,
        "summary": _summary_dict(summary, records, secrets),
    }
    text = json.dumps(document, indent=2, ensure_ascii=False)
    text = _scrub_substrings(text, secrets) + "\n"
    _atomic_write(path, text)
    return os.fspath(path)


__all__ = ["DEFAULT_REPORT_PATH", "write_report"]