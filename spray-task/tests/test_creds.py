"""Unit tests for the credentials model, --hash parsing, precedence, and masking."""

import pytest

from spraytask.creds import (
    NULL_LM_HASH,
    Credential,
    masked_repr,
    parse_nt_hash,
    redact,
    resolve_for_host,
)

NT_HASH_SECRET = "0123456789abcdef0123456789abcdef"
PASSWORD_SECRET = "s3cret-Pass!#word"


# --- parse_nt_hash ------------------------------------------------------------

def test_parse_bare_nt_hash_gets_null_lm_pair():
    assert parse_nt_hash(NT_HASH_SECRET) == f"{NULL_LM_HASH}:{NT_HASH_SECRET}"


def test_parse_pair_form_is_normalized_lowercase():
    pair = f"{NULL_LM_HASH.upper()}:{NT_HASH_SECRET.upper()}"
    assert parse_nt_hash(pair) == f"{NULL_LM_HASH}:{NT_HASH_SECRET}"


def test_parse_pair_with_nonstandard_lm_part_is_preserved():
    lm = "00112233445566778899aabbccddeeff"
    assert parse_nt_hash(f"{lm}:{NT_HASH_SECRET}") == f"{lm}:{NT_HASH_SECRET}"


def test_parse_strips_surrounding_whitespace():
    assert parse_nt_hash(f"  {NT_HASH_SECRET}  ") == f"{NULL_LM_HASH}:{NT_HASH_SECRET}"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "xyz",
        "0123456789abcdef",  # 16 chars, not 32
        "0123456789abcdef0123456789abcdef0",  # 33 chars
        "0123456789abcdef0123456789abcdeg",  # non-hex char
        f"{NT_HASH_SECRET}:{NT_HASH_SECRET}:extra",  # three parts
        "lm16hex:0123456789abcdef0123456789abcdef",  # lm half not 32 hex
    ],
)
def test_parse_invalid_hash_raises_value_error(bad):
    with pytest.raises(ValueError):
        parse_nt_hash(bad)


def test_parse_non_string_raises_type_error():
    with pytest.raises(TypeError):
        parse_nt_hash(b"0123456789abcdef0123456789abcdef")  # type: ignore[arg-type]


# --- Credential dataclass -----------------------------------------------------

def test_password_credential_fields():
    cred = Credential(domain="CORP", user="alice", password=PASSWORD_SECRET)
    assert cred.domain == "CORP"
    assert cred.user == "alice"
    assert cred.password == PASSWORD_SECRET
    assert cred.nt_hash is None
    assert cred.auth_type == "password"
    assert cred.lm_hash is None
    assert cred.nthash is None


def test_hash_credential_is_normal_to_pair_form():
    cred = Credential(user="bob", nt_hash=NT_HASH_SECRET)
    assert cred.nt_hash == f"{NULL_LM_HASH}:{NT_HASH_SECRET}"
    assert cred.auth_type == "nt_hash"
    assert cred.lm_hash == NULL_LM_HASH
    assert cred.nthash == NT_HASH_SECRET


def test_credential_requires_exactly_one_secret():
    with pytest.raises(ValueError):
        Credential(user="alice")
    with pytest.raises(ValueError):
        Credential(user="alice", password=PASSWORD_SECRET, nt_hash=NT_HASH_SECRET)


def test_credential_rejects_invalid_hash_on_construction():
    with pytest.raises(ValueError):
        Credential(user="alice", nt_hash="not-a-hash")


# --- masking ------------------------------------------------------------------

def test_repr_masks_password():
    cred = Credential(user="alice", password=PASSWORD_SECRET)
    rendered = repr(cred)
    assert PASSWORD_SECRET not in rendered
    assert "password=<redacted>" in rendered
    assert "alice" in rendered


def test_str_masks_password():
    cred = Credential(user="alice", password=PASSWORD_SECRET)
    rendered = str(cred)
    assert PASSWORD_SECRET not in rendered
    assert "<redacted>" in rendered


def test_repr_masks_hash():
    cred = Credential(user="bob", nt_hash=f"{NULL_LM_HASH}:{NT_HASH_SECRET}")
    rendered = repr(cred)
    assert NULL_LM_HASH not in rendered
    assert NT_HASH_SECRET not in rendered
    assert "nt_hash=<redacted>" in rendered


def test_repr_none():
    rendered = masked_repr(None)
    assert rendered == "Credential(<none>)"
    assert PASSWORD_SECRET not in rendered
    assert "password=" not in rendered


def test_redact_password_never_leaks():
    cred = Credential(domain="CORP", user="alice", password=PASSWORD_SECRET)
    safe = redact(cred)
    assert safe == {"domain": "CORP", "user": "alice", "auth_type": "password"}
    assert PASSWORD_SECRET not in repr(safe)


def test_redact_hash_never_leaks():
    cred = Credential(user="bob", nt_hash=f"{NULL_LM_HASH}:{NT_HASH_SECRET}")
    safe = redact(cred)
    assert safe == {"domain": "", "user": "bob", "auth_type": "nt_hash"}
    assert NULL_LM_HASH not in repr(safe)
    assert NT_HASH_SECRET not in repr(safe)


def test_redact_none():
    assert redact(None) is None


def test_no_secret_plaintext_in_any_output_form():
    creds = [
        Credential(user="alice", password=PASSWORD_SECRET),
        Credential(user="bob", nt_hash=f"{NULL_LM_HASH}:{NT_HASH_SECRET}"),
    ]
    outputs = []
    for cred in creds:
        outputs.extend([repr(cred), str(cred), masked_repr(cred), repr(redact(cred))])
    blob = "|".join(outputs)
    assert PASSWORD_SECRET not in blob
    assert NULL_LM_HASH not in blob
    assert NT_HASH_SECRET not in blob


# --- precedence & resolution --------------------------------------------------

GLOBAL_PASS = Credential(domain="CORP", user="svc", password=PASSWORD_SECRET)
GLOBAL_HASH = Credential(user="svc", nt_hash=NT_HASH_SECRET)


def test_per_host_override_wins_over_global():
    override = Credential(domain="LOCAL", user="admin", password="override-pass")
    assert resolve_for_host("10.0.0.5", {"10.0.0.5": override}, GLOBAL_PASS) is override


def test_override_wins_across_secret_types():
    override = Credential(user="admin", password="override-pass")
    resolved = resolve_for_host("h1", {"h1": override}, GLOBAL_HASH)
    assert resolved is override
    assert resolved.auth_type == "password"


def test_global_used_when_no_override():
    assert resolve_for_host("10.0.0.6", {}, GLOBAL_PASS) is GLOBAL_PASS


def test_global_hash_used_when_no_override():
    resolved = resolve_for_host("10.0.0.6", {"10.0.0.7": GLOBAL_PASS}, GLOBAL_HASH)
    assert resolved is GLOBAL_HASH
    assert resolved.auth_type == "nt_hash"


def test_unrelated_override_key_ignored():
    other = Credential(user="other", password="other-pass")
    assert resolve_for_host("h2", {"h1": other}, GLOBAL_PASS) is GLOBAL_PASS


def test_none_global_returns_none_when_no_override():
    assert resolve_for_host("h3", {}) is None
    assert resolve_for_host("h3", {}, None) is None


def test_override_keyed_exactly_by_host_string():
    override = Credential(user="admin", password="override-pass")
    assert resolve_for_host("host:445", {"host": override}, GLOBAL_PASS) is GLOBAL_PASS
    assert resolve_for_host("host", {"host": override}, GLOBAL_PASS) is override