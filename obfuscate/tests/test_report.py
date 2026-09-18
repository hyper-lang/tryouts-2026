"""Report module tests (R2/R6): stable schema, authorization_note, key masking.

Covers the shared output contract: fixed top-level schema, mandatory
authorization_note, masked secret material in JSON and human renders, JSON
round-trip helpers, schema stability across runs with different content, and
the "report.py is the only JSON path in the package" invariant.
"""

import random
import re
import string

import pytest

from obfuscate import __version__
from obfuscate.report import (
    AUTHORIZATION_NOTE,
    SCHEMA_VERSION,
    SECTIONS,
    Report,
    dump,
    dumps,
    load,
    loads,
    mask_key,
    redact,
    schema_is_stable,
    schema_of,
)

COMMANDS = ("inspect", "harden", "inject-patch", "build-host", "verify")

TOP_LEVEL_KEYS = {
    "authorization_note",
    "command",
    "findings",
    "schema_version",
    "target_image",
    "tool_version",
}


def _hex(rng, length=32):
    return "".join(rng.choice(string.hexdigits) for _ in range(length))


def _version(rng):
    return ".".join(str(rng.randint(0, 9)) for _ in range(4))


def _random_report(command="inspect", *, rng):
    tool_version = {"obfuscate": __version__, "python": "3.13.1", "dnfile": "0.18.0"}
    report = Report(
        command,
        tool_version=tool_version,
        target_image="Server 2019 default 4.7.2",
    )
    report.with_pe(
        {
            "image_base": rng.randint(0x400000, 0x140000000),
            "timestamp": rng.randint(0x50000000, 0x7FFFFFFF),
            "checksum": rng.randint(0, 0xFFFFFFFF),
            "sections": [
                {"name": ".text", "size": rng.randint(0x1000, 0x100000)},
                {"name": ".rsrc", "size": rng.randint(0x1000, 0x100000)},
            ],
        }
    )
    report.with_metadata(
        {
            "mvid": _hex(rng),
            "module_guid": _hex(rng),
            "assembly_version": _version(rng),
            "flags": rng.choice(["strong_name", "default"]),
            "public_key_token": _hex(rng, 16),
        }
    )
    report.with_config(
        {
            "payload_uuid": _hex(rng, 24),
            "callback_url": f"https://{_hex(rng, 8)}/{_hex(rng, 8)}",
            "aespsk_enc": _hex(rng, 64),
            "aespsk_dec": _hex(rng, 64),
            "query_param": _hex(rng, 6),
            "pipe_name": _hex(rng, 10),
        }
    )
    for _ in range(2):
        report.add_fingerprint(
            {
                "catalog_id": _hex(rng, 8),
                "mitigation": rng.choice(["metadata", "string_scrub", "none"]),
                "evidence_offset": rng.randint(0, 0x1FFFFF),
                "encoding": rng.choice(["utf-16le", "utf-8"]),
            }
        )
    report.with_hardening(
        {
            "seed": rng.randint(0, 0xFFFF),
            "passes": ["metadata", "attributes"],
            "checksum": "zero",
        }
    )
    for _ in range(2):
        report.add_assertion(
            {"assertion_id": _hex(rng, 8), "status": rng.choice(["pass", "fail"])}
        )
    report.with_canary(
        {
            "mode": rng.choice(["A", "B"]),
            "baseline": {"amsi": rng.choice([True, False])},
            "patched": {"amsi": rng.choice([True, False])},
        }
    )
    return report


class TestSchema:
    def test_fixed_top_level_keys(self):
        doc = _random_report("inspect", rng=random.Random(0)).to_dict()
        assert set(doc) == TOP_LEVEL_KEYS
        assert doc["schema_version"] == SCHEMA_VERSION
        assert list(doc["findings"]) == list(SECTIONS)
        for name in SECTIONS:
            assert name in doc["findings"]

    def test_deterministic_json_bytes_same_seed(self):
        rng = random.Random(7)
        first = _random_report(rng=rng)
        rng = random.Random(7)
        second = _random_report(rng=rng)
        assert first.json() == second.json()
        assert first.json_bytes() == second.json_bytes()

    def test_schema_stable_across_different_random_content(self):
        r1 = _random_report(rng=random.Random(1))
        r2 = _random_report(rng=random.Random(999))
        assert r1.json() != r2.json()
        assert schema_is_stable(r1, r2)
        assert schema_of(r1) == schema_of(r2)

    def test_schema_stable_against_round_tripped_document(self):
        rng = random.Random(2)
        report = _random_report("harden", rng=rng)
        loaded = loads(report.json())
        assert schema_is_stable(report, loaded)
        assert schema_is_stable(report.to_dict(), loaded)

    def test_sections_stamped_with_schema_version(self):
        report = _random_report(rng=random.Random(3))
        doc = report.to_dict()
        assert doc["findings"]["pe"]["schema_version"] == SCHEMA_VERSION
        assert doc["findings"]["config"]["schema_version"] == SCHEMA_VERSION
        assert doc["findings"]["fingerprints"][0]["schema_version"] == SCHEMA_VERSION
        assert doc["findings"]["verify"][0]["schema_version"] == SCHEMA_VERSION

    def test_schema_is_stable_rejects_non_documents(self):
        with pytest.raises(TypeError):
            schema_of(["not", "a", "document"])

    def test_report_requires_command_name(self):
        with pytest.raises(ValueError):
            Report("")


class TestAuthorizationNote:
    @pytest.mark.parametrize("command", COMMANDS)
    def test_note_present_in_document(self, command):
        doc = _random_report(command, rng=random.Random(0)).to_dict()
        assert doc["authorization_note"] == AUTHORIZATION_NOTE
        assert doc["authorization_note"]

    @pytest.mark.parametrize("command", COMMANDS)
    def test_note_survives_emission_and_round_trip(self, command, tmp_path):
        report = _random_report(command, rng=random.Random(0))
        path = tmp_path / "r.json"
        report.write(path)
        loaded = load(path)
        assert loaded["authorization_note"] == AUTHORIZATION_NOTE
        assert "authorization_note" in loads(report.json())

    @pytest.mark.parametrize("command", COMMANDS)
    def test_note_visible_in_human_render(self, command):
        text = _random_report(command, rng=random.Random(0)).render_text()
        assert AUTHORIZATION_NOTE in text


class TestMaskKey:
    KEYS = ["AESPSK_base64==", "m3G9sA==xmTX9qA==", "some-plaintext-ish key"]

    def test_deterministic(self):
        for key in self.KEYS:
            assert mask_key(key) == mask_key(key)
            assert mask_key(key * 2) == mask_key(key * 2)

    def test_no_raw_key_bytes_in_output(self):
        for key in self.KEYS:
            masked = mask_key(key)
            assert key not in masked
            assert key.encode("utf-8") not in masked.encode("utf-8")

    def test_distinct_inputs_distinct_output(self):
        assert mask_key("AAAA-key") != mask_key("BBBB-key")

    def test_prefix_length(self):
        assert len(mask_key("content", prefix=8)) == 8
        assert len(mask_key("content", prefix=64)) == 64

    def test_bytes_and_str_agree(self):
        assert mask_key(b"raw-bytes") == mask_key("raw-bytes")

    def test_rejects_bad_prefix(self):
        with pytest.raises(ValueError):
            mask_key("content", prefix=0)


class TestRedaction:
    SECRETS = {
        "aespsk_enc": "RAW_KEY_ENC",
        "AESPSK_dec": "RAW_KEY_DEC",
        "encryption_key": "RAW_KEY_SECOND",
        "passphrase": "p4ssphrase-value",
    }

    def test_json_boundary_never_contains_raw_keys(self):
        rng = random.Random(4)
        report = _random_report(rng=rng).with_config(dict(self.SECRETS))
        blob = report.json()
        assert "RAW_KEY_ENC" not in blob
        assert "RAW_KEY_DEC" not in blob
        assert "RAW_KEY_SECOND" not in blob
        assert "p4ssphrase-value" not in blob

    def test_masked_forms_are_present(self):
        rng = random.Random(5)
        report = _random_report(rng=rng).with_config(dict(self.SECRETS))
        doc = report.to_dict()
        for field, raw in self.SECRETS.items():
            assert doc["findings"]["config"][field] == mask_key(raw)

    def test_human_render_contains_no_key_material(self):
        rng = random.Random(6)
        report = _random_report(rng=rng).with_config(dict(self.SECRETS))
        text = report.render_text()
        for raw in self.SECRETS.values():
            assert raw not in text
        assert mask_key("RAW_KEY_ENC") in text

    def test_public_key_token_not_masked(self):
        doc = redact(
            {
                "metadata": {"public_key_token": "0024000004800000940000000602000000240000"},
                "config": {"aespsk_dec": "secret"},
            }
        )
        assert doc["metadata"]["public_key_token"].startswith("0024")
        assert doc["config"]["aespsk_dec"] == mask_key("secret")

    def test_redact_walks_nested_structures(self):
        doc = redact(
            {
                "config": {"group": [{"enc_key": "nested-secret"}, {"pub": "ok"}]},
                "pe": {"offsets": [1, 2, 3]},
            }
        )
        assert doc["config"]["group"][0]["enc_key"] == mask_key("nested-secret")
        assert doc["config"]["group"][1]["pub"] == "ok"
        assert doc["pe"]["offsets"] == [1, 2, 3]


class TestRoundTrip:
    def test_dumps_loads_canonical(self):
        rng = random.Random(8)
        report = _random_report("verify", rng=rng)
        assert loads(report.json()) == loads(dumps(loads(dumps(loads(report.json())))))

    def test_write_and_load_are_byte_stable(self, tmp_path):
        rng = random.Random(9)
        report = _random_report(rng=rng)
        path = tmp_path / "report.json"
        report.write(path)
        written = path.read_text(encoding="utf-8")
        assert written == report.json() + "\n"
        assert load(path) == loads(report.json())
        assert schema_is_stable(report, load(path))

    def test_render_text_reproduces_all_sections(self):
        report = _random_report(rng=random.Random(10))
        text = report.render_text()
        for name in SECTIONS:
            assert f"## {name}" in text
        assert text.endswith("\n")


class TestOnlyJsonPath:
    def test_only_report_module_imports_json(self):
        import pathlib

        import obfuscate

        pkg_dir = pathlib.Path(obfuscate.__file__).resolve().parent
        pattern = re.compile(r"^\s*(import json|from json\s+import)", re.MULTILINE)
        for path in sorted(pkg_dir.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            uses_json = pattern.search(source)
            if path.name == "report.py":
                assert uses_json, "report.py must be the module that imports json"
            else:
                assert not uses_json, f"{path.name} imports json; report.py is the only JSON path"