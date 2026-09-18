"""R1 host-list parsing for spray-task.

Grammar per non-comment, non-blank line of a host file:

* bare address: ``host`` or ``host:port``
* IPv6 literal: ``[addr]`` or ``[addr]:port`` -- bracketed so it can never
  collide with the credential syntax
* credential override: ``[domain\\]user:password@host[:port]``

A raw ``@`` marks a credential override; without one the line is a bare
address, so IPv6 literals like ``[::1]`` are always hosts. In an override the
password must not contain a raw ``@``, ``:``, or ``\\`` -- percent-encode them
as ``%40``, ``%3A``, ``%5C`` and they are decoded after splitting. A ``%`` that
is not a valid escape is passed through untouched.

Parsing is strict: malformed lines are surfaced as :class:`HostLineError`
(never silently dropped) and :func:`load_host_file` reports every one of them
with its line number and reason.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from urllib.parse import unquote

_HOSTNAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
MAX_PORT = 65535


@dataclass(frozen=True)
class HostLineError(ValueError):
    """A malformed host-file line (``line_no`` 1-based, ``text`` the stripped
    line, ``reason`` a stable human-readable explanation)."""

    line_no: int
    text: str
    reason: str

    def __str__(self) -> str:
        return f"line {self.line_no}: {self.reason} (host line: {self.text!r})"


@dataclass(frozen=True)
class Credential:
    """Per-host credential override parsed from the host file."""

    domain: str | None
    username: str
    password: str


@dataclass(frozen=True)
class HostEntry:
    """One target host. ``address`` is the network-connectable form: IPv6
    literals are stored without the input brackets (e.g. ``[::1]`` becomes
    ``::1``)."""

    address: str
    port: int | None
    credential: Credential | None = None


def _err(line: str, line_no: int, reason: str) -> HostLineError:
    return HostLineError(line_no=line_no, text=line, reason=reason)


def _parse_host_target(line: str, line_no: int) -> tuple[str, int | None]:
    """Parse the target part (``host`` / ``host:port`` / ``[v6]`` /
    ``[v6]:port``) into a connect-able (address, port) pair."""
    if line.startswith("["):
        end = line.find("]")
        if end == -1:
            raise _err(line, line_no, "missing closing ']' for IPv6 literal")
        inner = line[1:end]
        rest = line[end + 1 :]
        if not inner:
            raise _err(line, line_no, "empty IPv6 literal")
        try:
            ipaddress.IPv6Address(inner)
        except ValueError:
            raise _err(line, line_no, f"invalid IPv6 address {inner!r}") from None
        port: int | None = None
        if rest:
            if not rest.startswith(":"):
                raise _err(
                    line, line_no, f"unexpected text {rest!r} after IPv6 address"
                )
            port = _parse_port(line, line_no, rest[1:])
        return _validate_host(line, line_no, inner), port
    if line.count(":") == 0:
        return _validate_host(line, line_no, line), None
    if line.count(":") == 1:
        host, _, port_raw = line.partition(":")
        return _validate_host(line, line_no, host), _parse_port(line, line_no, port_raw)
    raise _err(line, line_no, "IPv6 addresses must be bracketed, e.g. [::1]")


def _parse_port(line: str, line_no: int, raw: str) -> int:
    if not raw or not raw.isdigit():
        raise _err(line, line_no, f"invalid port {raw!r} (must be 1-65535)")
    port = int(raw)
    if not 1 <= port <= MAX_PORT:
        raise _err(line, line_no, f"invalid port {port} (must be 1-65535)")
    return port


def _validate_host(line: str, line_no: int, host: str) -> str:
    if not host:
        raise _err(line, line_no, "empty host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.fullmatch(host):
            raise _err(line, line_no, f"invalid host {host!r}") from None
    return host


def _parse_override(line: str, line_no: int) -> HostEntry:
    if line.count("@") != 1:
        raise _err(line, line_no, "credential override must contain exactly one '@'")
    raw_creds, _, raw_target = line.partition("@")
    if raw_creds.count(":") != 1:
        raise _err(line, line_no, "credential part must be '[domain\\]user:password'")
    user_part, _, raw_password = raw_creds.partition(":")
    domain: str | None = None
    if "\\" in user_part:
        if user_part.count("\\") != 1:
            raise _err(line, line_no, "credential part must be '[domain\\]user:password'")
        domain, _, username = user_part.partition("\\")
        if not domain:
            raise _err(line, line_no, "credential domain must not be empty")
    else:
        username = user_part
    if not username:
        raise _err(line, line_no, "credential user must not be empty")
    if "\\" in raw_password:
        raise _err(
            line, line_no, "password must not contain a raw backslash (use %5C)"
        )
    try:
        address, port = _parse_host_target(raw_target, line_no)
    except HostLineError as exc:
        raise _err(line, line_no, exc.reason) from None
    return HostEntry(
        address=address,
        port=port,
        credential=Credential(
            domain=domain,
            username=username,
            password=unquote(raw_password),
        ),
    )


def parse_host_line(line: str, line_no: int = 1) -> HostEntry | None:
    """Parse a single host-file line.

    Returns ``None`` for blank and ``#`` comment lines, a
    :class:`HostEntry` for valid hosts, and raises :class:`HostLineError`
    for malformed lines.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if "@" in stripped:
        return _parse_override(stripped, line_no)
    address, port = _parse_host_target(stripped, line_no)
    return HostEntry(address=address, port=port, credential=None)


def load_host_file(
    path: str | os.PathLike[str],
) -> tuple[list[HostEntry], list[HostLineError]]:
    """Read a host file (UTF-8, optional BOM).

    Returns ``(entries, errors)``. Blank lines and ``#`` comment lines are
    ignored; every malformed line is reported in ``errors`` with its 1-based
    line number and a reason -- nothing is silently dropped. An I/O failure
    (e.g. missing file) propagates to the caller.
    """
    entries: list[HostEntry] = []
    errors: list[HostLineError] = []
    with open(path, "r", encoding="utf-8-sig") as fh:
        for line_no, line in enumerate(fh, start=1):
            try:
                entry = parse_host_line(line, line_no)
            except HostLineError as exc:
                errors.append(exc)
            else:
                if entry is not None:
                    entries.append(entry)
    return entries, errors