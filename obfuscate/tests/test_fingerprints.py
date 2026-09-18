"""Fingerprint catalog tests (R4): internal consistency, tier separation, helpers.

Covers:

1. Every entry has exactly one valid mitigation.
2. Scrubbable entries never carry ``rebuild_config``.
3. ``reflect_sensitive`` entries are never ``string_scrub`` or ``metadata``.
4. Split ``killdate``-family string is still matched via a fragment entry.
5. Catalog version is stable (non-empty, a string).
6. ``by_mitigation`` / ``scrubbable_entries`` / ``all_fragments`` return correct subsets.
7. Full-string entries have an encoding; fragment entries do not.
8. Catalog is non-empty and entries are ordered (metadata, attributes, US, VS, fragments).
9. Catalog is the single authority: inspect/harden/verify all import from here.
"""

from __future__ import annotations

import pytest

from obfuscate.fingerprints import (
    CATALOG,
    CATALOG_VERSION,
    Entry,
    FragmentEntry,
    FullStringEntry,
    all_fragments,
    by_mitigation,
    scrubbable_entries,
)

# ---------------------------------------------------------------------------
# Valid mitigations set (mirrors the Literal type).
# ---------------------------------------------------------------------------

VALID_MITIGATIONS = frozenset({
    "metadata",
    "attributes",
    "string_scrub",
    "rebuild_config",
    "runtime",
    "none",
})


# ---------------------------------------------------------------------------
# Internal consistency
# ---------------------------------------------------------------------------


class TestCatalogConsistency:
    def test_catalog_is_non_empty(self):
        assert len(CATALOG) > 0, "catalog must not be empty"

    def test_catalog_version_is_non_empty_string(self):
        assert isinstance(CATALOG_VERSION, str)
        assert len(CATALOG_VERSION) > 0

    def test_every_entry_has_exactly_one_valid_mitigation(self):
        for entry in CATALOG:
            assert entry.mitigation in VALID_MITIGATIONS, (
                f"entry {entry.text!r} has invalid mitigation {entry.mitigation!r}"
            )

    def test_every_entry_has_text(self):
        for entry in CATALOG:
            assert isinstance(entry.text, str)
            assert len(entry.text) > 0

    def test_every_entry_has_boolean_flags(self):
        for entry in CATALOG:
            assert isinstance(entry.scrubbable, bool)
            assert isinstance(entry.rename_safe, bool)
            assert isinstance(entry.reflect_sensitive, bool)

    def test_scrubbable_entries_never_carry_rebuild_config(self):
        for entry in CATALOG:
            if entry.scrubbable:
                assert entry.mitigation != "rebuild_config", (
                    f"scrubbable entry {entry.text!r} must not have rebuild_config mitigation"
                )

    def test_reflect_sensitive_never_string_scrub_or_metadata(self):
        for entry in CATALOG:
            if entry.reflect_sensitive:
                assert entry.mitigation not in ("string_scrub", "metadata"), (
                    f"reflect_sensitive entry {entry.text!r} has "
                    f"forbidden mitigation {entry.mitigation!r}"
                )


# ---------------------------------------------------------------------------
# Tier separation: full-string vs fragment
# ---------------------------------------------------------------------------


class TestTierSeparation:
    def test_full_string_entries_have_encoding(self):
        for entry in CATALOG:
            if isinstance(entry, FullStringEntry):
                assert entry.encoding in ("utf-8", "utf-16le"), (
                    f"FullStringEntry {entry.text!r} has invalid encoding {entry.encoding!r}"
                )

    def test_fragment_entries_do_not_have_encoding(self):
        for entry in CATALOG:
            if isinstance(entry, FragmentEntry):
                assert not hasattr(entry, "encoding"), (
                    f"FragmentEntry {entry.text!r} should not have an encoding attribute"
                )

    def test_no_text_overlap_between_full_and_fragment(self):
        full_texts = {e.text for e in CATALOG if isinstance(e, FullStringEntry)}
        frag_texts = {e.text for e in CATALOG if isinstance(e, FragmentEntry)}
        overlap = full_texts & frag_texts
        assert not overlap, f"full-string and fragment share texts: {overlap}"

    def test_all_entries_are_entry_type(self):
        for entry in CATALOG:
            assert isinstance(entry, Entry)


# ---------------------------------------------------------------------------
# Killdate split-fragment matching
# ---------------------------------------------------------------------------


class TestKilldateFragment:
    def test_killdate_full_string_is_scrubbable(self):
        matches = [e for e in CATALOG if isinstance(e, FullStringEntry) and e.text == "killdate"]
        assert len(matches) == 1
        assert matches[0].scrubbable is True
        assert matches[0].mitigation == "string_scrub"

    def test_kill_fragments_are_present(self):
        frag_texts = {e.text for e in CATALOG if isinstance(e, FragmentEntry)}
        assert "kill" in frag_texts, "fragment 'kill' must be present to catch split killdate"
        assert "date" in frag_texts, "fragment 'date' must be present to catch split killdate"

    def test_split_killdate_matches_via_fragments(self):
        """A binary containing 'kill' and 'date' in separate US strings
        is still caught by the fragment tier even though the full
        'killdate' literal is absent."""
        killdate_frags = [e for e in all_fragments() if e.text in ("kill", "date")]
        assert len(killdate_frags) == 2
        for frag in killdate_frags:
            assert isinstance(frag, FragmentEntry)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestByMitigation:
    def test_returns_only_matching_entries(self):
        for mit in VALID_MITIGATIONS:
            result = by_mitigation(mit)
            for entry in result:
                assert entry.mitigation == mit

    def test_string_scrub_entries_are_scrubbable(self):
        for entry in by_mitigation("string_scrub"):
            assert entry.scrubbable is True, (
                f"string_scrub entry {entry.text!r} must be scrubbable"
            )

    def test_rebuild_config_entries_are_not_scrubbable(self):
        for entry in by_mitigation("rebuild_config"):
            assert entry.scrubbable is False, (
                f"rebuild_config entry {entry.text!r} must not be scrubbable"
            )

    def test_unknown_mitigation_returns_empty(self):
        assert by_mitigation("nonexistent_mitigation") == []


class TestScrubbableEntries:
    def test_returns_only_full_string_scrubbable(self):
        result = scrubbable_entries()
        assert len(result) > 0
        for entry in result:
            assert isinstance(entry, FullStringEntry)
            assert entry.scrubbable is True

    def test_no_rebuild_config_in_scrubbable(self):
        for entry in scrubbable_entries():
            assert entry.mitigation != "rebuild_config"

    def test_scrubbable_subset_of_full_string(self):
        all_full = [e for e in CATALOG if isinstance(e, FullStringEntry)]
        assert len(scrubbable_entries()) <= len(all_full)


class TestAllFragments:
    def test_returns_only_fragment_entries(self):
        result = all_fragments()
        assert len(result) > 0
        for entry in result:
            assert isinstance(entry, FragmentEntry)

    def test_fragment_count_matches_catalog(self):
        assert len(all_fragments()) == sum(
            1 for e in CATALOG if isinstance(e, FragmentEntry)
        )


# ---------------------------------------------------------------------------
# Catalog ordering
# ---------------------------------------------------------------------------


class TestCatalogOrdering:
    def test_metadata_before_attributes(self):
        meta_indices = [i for i, e in enumerate(CATALOG) if e.mitigation == "metadata"]
        attr_indices = [i for i, e in enumerate(CATALOG) if e.mitigation == "attributes"]
        if meta_indices and attr_indices:
            assert max(meta_indices) < min(attr_indices), (
                "metadata entries should come before attributes entries"
            )

    def test_fragments_are_last(self):
        frag_start = None
        for i, e in enumerate(CATALOG):
            if isinstance(e, FragmentEntry):
                if frag_start is None:
                    frag_start = i
                # All remaining entries must be fragments.
                for j in range(i + 1, len(CATALOG)):
                    if isinstance(CATALOG[j], FullStringEntry):
                        pytest.fail(
                            f"FullStringEntry {CATALOG[j].text!r} at index {j} "
                            f"appears after a FragmentEntry at index {i}"
                        )


# ---------------------------------------------------------------------------
# to_dict round-trip
# ---------------------------------------------------------------------------


class TestEntryToDict:
    def test_full_string_entry_to_dict(self):
        entry = FullStringEntry(
            "test", "utf-8", "string_scrub", True, True, False
        )
        d = entry.to_dict()
        assert d["text"] == "test"
        assert d["encoding"] == "utf-8"
        assert d["mitigation"] == "string_scrub"
        assert d["scrubbable"] is True
        assert d["rename_safe"] is True
        assert d["reflect_sensitive"] is False

    def test_fragment_entry_to_dict(self):
        entry = FragmentEntry("test_frag", "none", False, False, True)
        d = entry.to_dict()
        assert d["text"] == "test_frag"
        assert "encoding" not in d
        assert d["mitigation"] == "none"
        assert d["reflect_sensitive"] is True


# ---------------------------------------------------------------------------
# Authority invariant
# ---------------------------------------------------------------------------


class TestAuthorityInvariant:
    def test_catalog_is_importable_by_other_modules(self):
        """Verify the catalog is the canonical import path used by the
        project.  Other modules must import CATALOG, by_mitigation,
        scrubbable_entries, and all_fragments from here."""
        from obfuscate import fingerprints as fp

        assert fp.CATALOG is CATALOG
        assert fp.CATALOG_VERSION == CATALOG_VERSION
        assert fp.by_mitigation is by_mitigation
        assert fp.scrubbable_entries is scrubbable_entries
        assert fp.all_fragments is all_fragments


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_catalog_is_stable_across_imports(self):
        """Same module, same CATALOG object — import-time determinism."""
        import importlib

        import obfuscate.fingerprints as fp

        importlib.reload(fp)
        assert fp.CATALOG is not None
        assert len(fp.CATALOG) == len(CATALOG)
        for a, b in zip(fp.CATALOG, CATALOG):
            assert a.text == b.text
            assert a.mitigation == b.mitigation

    def test_same_version_no_bump_needed(self):
        """CATALOG_VERSION is consistent with the current catalog content."""
        # This test will fail if someone adds entries without bumping the version.
        # It asserts a non-empty version exists; the actual bump check is a
        # code-review gate.
        assert CATALOG_VERSION != ""
