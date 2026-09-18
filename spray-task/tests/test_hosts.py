"""Unit tests for the R1 host-list parser (spraytask.hosts)."""

import pytest

from spraytask import hosts


# --- known-good bare addresses ----------------------------------------------

@pytest.mark.parametrize(
    ("line", "address", "port"),
    [
        ("192.168.1.10", "192.168.1.10", None),
        ("ws001.corp.local", "ws001.corp.local", None),
        ("host", "host", None),
        ("192.168.1.10:8445", "192.168.1.10", 8445),
        ("ws001.corp.local:445", "ws001.corp.local", 445),
        ("srv01:1445", "srv01", 1445),
    ],
)
def test_bare_address(line, address, port):
    entry = hosts.parse_host_line(line, 1)
    assert entry is not None
    assert entry.address == address
    assert entry.port == port
    assert entry.credential is None


# --- known-good IPv6 literals -------------------------------------------------

@pytest.mark.parametrize(
    ("line", "address", "port"),
    [
        ("[::1]", "::1", None),
        ("[::1]:445", "::1", 445),
        ("[2001:db8::1]", "2001:db8::1", None),
        ("[2001:db8::1]:445", "2001:db8::1", 445),
    ],
)
def test_ipv6_literal(line, address, port):
    entry = hosts.parse_host_line(line, 1)
    assert entry is not None
    assert entry.address == address
    assert entry.port == port
    assert entry.credential is None


# --- known-good credential overrides ------------------------------------------

@pytest.mark.parametrize(
    ("line", "domain", "username", "password", "address", "port"),
    [
        ("admin:S3cret@10.0.0.1", None, "admin", "S3cret", "10.0.0.1", None),
        ("CORP\\admin:S3cret@10.0.0.1", "CORP", "admin", "S3cret", "10.0.0.1", None),
        ("admin:pass@10.0.0.1:1445", None, "admin", "pass", "10.0.0.1", 1445),
        ("admin:pw@[::1]:445", None, "admin", "pw", "::1", 445),
        ("DOM\\u:p@host", "DOM", "u", "p", "host", None),
        ("admin:@10.0.0.1", None, "admin", "", "10.0.0.1", None),
    ],
)
def test_credential_override(line, domain, username, password, address, port):
    entry = hosts.parse_host_line(line, 1)
    assert entry is not None
    assert entry.address == address
    assert entry.port == port
    assert entry.credential is not None
    assert entry.credential.domain == domain
    assert entry.credential.username == username
    assert entry.credential.password == password


# --- percent-encoding round trip ---------------------------------------------

@pytest.mark.parametrize(
    ("encoded", "decoded"),
    [
        ("pa%40ss", "pa@ss"),
        ("pa%3Ass", "pa:ss"),
        ("pa%3ass", "pa:ss"),
        ("pa%5Css", "pa\\ss"),
        ("p%40ss%3Aword%5Cpct", "p@ss:word\\pct"),
        ("mixed%40and%3Aand%5C", "mixed@and:and\\"),
        ("has%25percent", "has%percent"),
        ("pmax%7E", "pmax~"),
    ],
)
def test_percent_encoded_password_round_trip(encoded, decoded):
    entry = hosts.parse_host_line(f"admin:{encoded}@10.0.0.1", 1)
    assert entry is not None
    assert entry.credential is not None
    assert entry.credential.password == decoded


def test_combined_delimiter_round_trip():
    line = "admin:p%40ss%3Aword%5Cpct50%25@host"
    entry = hosts.parse_host_line(line, 1)
    assert entry is not None
    assert entry.address == "host"
    assert entry.credential is not None
    assert entry.credential.password == "p@ss:word\\pct50%"


# --- comment and blank lines --------------------------------------------------

@pytest.mark.parametrize(
    "line",
    ["", "   ", "\t", "# comment", "  # comment with leading space", "#", "\n"],
)
def test_comment_and_blank_lines_ignored(line):
    assert hosts.parse_host_line(line, 1) is None


# --- malformed lines ----------------------------------------------------------

@pytest.mark.parametrize(
    ("line", "reason_fragment"),
    [
        ("admin@10.0.0.1", "credential part"),
        ("admin:se:cret@10.0.0.1", "credential part"),
        ("a:b@c@d", "exactly one '@'"),
        ("admin:x@another@host", "exactly one '@'"),
        ("user:p\\ass@10.0.0.1", "raw backslash"),
        ("admin:secret@:445", "empty host"),
        ("admin:secret@10.0.0.1:99999", "1-65535"),
        ("admin:secret@10.0.0.1:abc", "must be 1-65535"),
        ("10.0.0.1:0", "1-65535"),
        ("10.0.0.1:", "must be 1-65535"),
        ("[::1", "closing ']'"),
        ("[]", "empty IPv6 literal"),
        ("[zz::1]", "invalid IPv6 address"),
        ("::1", "must be bracketed"),
        ("2001:db8::1", "must be bracketed"),
        ("host two", "invalid host"),
        ("10.0.0.1 # trailing", "invalid host"),
        (":pass@host", "user must not be empty"),
        ("\\user:pass@host", "domain must not be empty"),
        ("dom1\\dom2\\user:pass@host", "credential part"),
        ("admin:secret@[::1]x", "unexpected text"),
    ],
)
def test_malformed_lines_raise(line, reason_fragment):
    with pytest.raises(hosts.HostLineError, match=reason_fragment):
        hosts.parse_host_line(line, 7)


def test_host_line_error_fields_and_str():
    with pytest.raises(hosts.HostLineError) as exc_info:
        hosts.parse_host_line("bad line", 12)
    exc = exc_info.value
    assert exc.line_no == 12
    assert exc.text == "bad line"
    assert exc.reason == "invalid host 'bad line'"
    assert str(exc) == "line 12: invalid host 'bad line' (host line: 'bad line')"


# --- file-level parsing -------------------------------------------------------

def test_load_host_file_mixed(tmp_path):
    path = tmp_path / "hosts.txt"
    path.write_text(
        "192.168.1.10\n"
        "# a comment\n"
        "\n"
        "  srv01:1445\n"
        "CORP\\admin:p%40ss@10.0.0.2\n"
        "admin:secret@[::1\n",
        encoding="utf-8",
    )
    entries, errors = hosts.load_host_file(path)
    assert [e.address for e in entries] == ["192.168.1.10", "srv01", "10.0.0.2"]
    assert entries[1].port == 1445
    cred = entries[2].credential
    assert cred is not None
    assert (cred.domain, cred.username, cred.password) == ("CORP", "admin", "p@ss")
    assert len(errors) == 1
    assert errors[0].line_no == 6
    assert "closing" in errors[0].reason
    assert "admin:secret@[::1" in errors[0].text


def test_load_host_file_only_comments(tmp_path):
    path = tmp_path / "hosts.txt"
    path.write_text("# nothing\n\n  # here\n", encoding="utf-8")
    assert hosts.load_host_file(path) == ([], [])


def test_load_host_file_utf8_bom(tmp_path):
    path = tmp_path / "hosts.txt"
    path.write_bytes(b"\xef\xbb\xbf10.0.0.1\n10.0.0.2\n")
    entries, errors = hosts.load_host_file(path)
    assert errors == []
    assert [e.address for e in entries] == ["10.0.0.1", "10.0.0.2"]


def test_load_host_file_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        hosts.load_host_file(tmp_path / "nope.txt")