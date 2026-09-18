"""Package-side synthetic fixtures (pure stdlib, no compiler, no dnfile).

This module is the permanent home of the synthetic-tree builders that used to
live in ``tests/fixtures/``.  The CLI handlers need them for R7 synthetic-tree
mode: when no ``agent_code`` checkout is present, ``inject-patch`` and
``build-host`` synthesize one (an Apollo-shaped ``agent_code`` tree and a
compiled Apollo-shaped WinExe image respectively) instead of failing.

Three builders live here, merged from the old fixture modules with their
public names unchanged so the thin re-exports in ``tests/fixtures/`` keep every
existing ``from tests.fixtures...`` import site working:

1. :class:`AgentCodeTree` / :func:`build_agent_code_tree` -- an on-disk
   synthetic ``agent_code`` directory tree (Program.cs, AssemblyInfo.cs,
   Config.cs, ApolloInterop/ and Mythic/ namespace markers; ``RuntimePatch.cs``
   absent by default so inject-patch overlay tests can write it).
2. :class:`PeBuilder` -- a pure-Python PE32+ .NET CLI image builder emitting
   all five ECMA-335 streams (``#~`` ``#Strings`` ``#US`` ``#GUID`` ``#Blob``)
   with curated Apollo-shaped ``#US`` literals at deterministic file offsets,
   recorded by :class:`Layout`.
3. The canonical Apollo-shaped sample (``SAMPLE_MVID`` etc.) plus every named
   offset constant and :func:`write_sample_to`, exported through the
   ``samples`` compatibility namespace.

Design rules inherited from the fixture era and still enforced here:

* stdlib-only and deterministic (no clock, no environment, no dnfile import);
  dnfile is used only by tests to validate the produced bytes.
* All edits the tool applies to these images remain in-place and
  constant-length (R3); this module only *produces* them.
"""

from __future__ import annotations

import random
import struct
import textwrap
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. AgentCodeTree -- synthetic agent_code directory layout
# ---------------------------------------------------------------------------


class AgentCodeTree:
    """Builds a synthetic `agent_code` directory tree in a temp directory."""

    def __init__(self, root: Path):
        self.root = root

    def build(self) -> Path:
        """Create the directory tree on disk and return the root path."""
        self.root.mkdir(parents=True, exist_ok=True)
        self._write_program_cs()
        self._write_assembly_info()
        self._write_config_cs()
        self._write_namespace_markers()
        return self.root

    def _write_program_cs(self):
        content = textwrap.dedent("""
            using System;

            namespace Apollo
            {
                public class Program
                {
                    public static void Main(string[] args)
                    {
                        // Entry point for the Apollo WinExe agent.
                        Console.WriteLine("Apollo agent started.");
                    }
                }
            }
        """).strip() + "\n"
        (self.root / "Program.cs").write_text(content, encoding="utf-8")

    def _write_assembly_info(self):
        props_dir = self.root / "Properties"
        props_dir.mkdir(parents=True, exist_ok=True)
        content = textwrap.dedent("""
            using System.Reflection;
            using System.Runtime.CompilerServices;
            using System.Runtime.Versioning;

            [assembly: AssemblyCompany("Mythic Apollo Operations Team")]
            [assembly: AssemblyProduct("Apollo Agent")]
            [assembly: AssemblyCopyright("Copyright (c) 2026 MythicDev. Authorized red-team exercise use only.")]
            [assembly: TargetFramework(".NETFramework,Version=v4.0", FrameworkDisplayName=".NET Framework 4")]
            [assembly: CompilationRelaxations(8)]
            [assembly: System.Diagnostics.Debuggable(System.Diagnostics.DebuggableAttribute.DebuggingModes.Default)]
        """).strip() + "\n"
        (props_dir / "AssemblyInfo.cs").write_text(content, encoding="utf-8")

    def _write_config_cs(self):
        content = textwrap.dedent("""
            namespace Apollo
            {
                internal static class Config
                {
                    // These values are read from the embedded #US heap by the agent.
                    public const string UserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
                    public const string CallbackUrl = "https://192.168.10.20:8443";
                    public const string ApiBase = "/api/v1.4/agent/";
                    public const string KillDate = "killdate";
                    public const string EncryptedExchangeCheck = "encrypted_exchange_check";
                    public const string AespskEncKey = "AESPSK";
                    public const string AespskDecKey = "AESPSK";
                    public const string PayloadUuid = "payload_uuid";
                    public const string PipeName = @"\\\\.\\pipe\\Mythic_Agent";
                    public const string CookieName = "MythicSession";
                    public const string QueryParam = "q";
                }
            }
        """).strip() + "\n"
        (self.root / "Config.cs").write_text(content, encoding="utf-8")

    def _write_namespace_markers(self):
        (self.root / "ApolloInterop").mkdir(exist_ok=True)
        (self.root / "Mythic").mkdir(exist_ok=True)
        (self.root / "ApolloInterop" / "ICommand.cs").write_text(
            textwrap.dedent("""
                namespace ApolloInterop
                {
                    public interface ICommand { }
                }
            """).strip() + "\n",
            encoding="utf-8",
        )
        (self.root / "Mythic" / "Rest.cs").write_text(
            textwrap.dedent("""
                namespace Mythic.Rest
                {
                    public class HttpRestClient { }
                }
            """).strip() + "\n",
            encoding="utf-8",
        )
        (self.root / "Mythic" / "Structs.cs").write_text(
            textwrap.dedent("""
                namespace Mythic.Structs
                {
                    public class JsonObject { }
                }
            """).strip() + "\n",
            encoding="utf-8",
        )

    # ----------------------------------------------------------------------
    # overlay / inject-patch helpers
    # ----------------------------------------------------------------------

    def runtime_patch_path(self) -> Path:
        return self.root / "RuntimePatch.cs"

    def has_runtime_patch(self) -> bool:
        return self.runtime_patch_path().exists()

    def write_runtime_patch(self, content: str):
        """Write the overlay file (called by inject-patch under test)."""
        self.runtime_patch_path().write_text(content, encoding="utf-8")

    def read_runtime_patch(self) -> Optional[str]:
        p = self.runtime_patch_path()
        if p.exists():
            return p.read_text(encoding="utf-8")
        return None

    def expected_files(self) -> List[str]:
        """Return the list of files inject-patch / host tests expect to see."""
        base = [
            "Program.cs",
            "Properties/AssemblyInfo.cs",
            "Config.cs",
            "ApolloInterop/ICommand.cs",
            "Mythic/Rest.cs",
            "Mythic/Structs.cs",
        ]
        if self.has_runtime_patch():
            base.append("RuntimePatch.cs")
        return sorted(base)


def build_agent_code_tree(root: Path) -> Path:
    """Convenience function: build a fresh tree under `root` and return it."""
    return AgentCodeTree(root).build()


# ---------------------------------------------------------------------------
# 2. PeBuilder -- synthetic PE32+ .NET CLI image builder
# ---------------------------------------------------------------------------
#
# Emits a minimal but dnfile-parseable PE32+ image with a .NET CLI header and a
# metadata root carrying the five ECMA-335 streams ``#~``/``#Strings``/``#US``/
# ``#GUID``/``#Blob``.  Everything is written with struct packing at
# deterministic file offsets, so later fixture consumers (heap scanning,
# attribute scrubbing, verify) can depend on the exact offsets documented by the
# returned :class:`Layout`.
#
# The builder models a compiled Mythic Apollo ``WinExe`` agent (output_type =
# WinExe, .NET Framework 4) closely enough for the project's scan/scrub/verify
# passes: the assembly is named ``Apollo``, carries a ``Program`` type with a
# ``Main`` MethodDef, Apollo/ApolloInterop/Mythic namespace markers, an mscorlib
# assembly reference, reflection-encoded custom attributes (Debuggable,
# Company/Product/Copyright, TargetFramework, CompilationRelaxations), and a
# curated set of ``#US`` literals (user-agent, callback URL fragments, API-path
# segments, config key names, pipe names, banner/help strings).
#
# Design notes / invariants:
#
# * No compiler is involved; every byte is produced by this module.
# * The layout is a pure function of the constructor arguments.  Defaults give a
#   fixed, deterministic image; a ``seed`` only shapes the strong-name signature
#   block and never the offsets.
# * The ``#~`` stream and all heaps are smaller than 64 KiB, so every heap index
#   is stored as a 2-byte word and ``HeapOffsetSizes`` is 0 (matching the widths
#   dnfile computes when it parses the rows back).
# * This section never imports dnfile; fixtures must stay hermetic and
#   stdlib-only.

# PE constants
_DOS_MAGIC = 0x5A4D  # "MZ"
_PE_MAGIC = 0x00004550  # "PE\0\0"
_MACHINE_AMD64 = 0x8664
_PE32PLUS_MAGIC = 0x20B

_CHAR_EXECUTABLE_IMAGE = 0x0002
_CHAR_LARGE_ADDRESS_AWARE = 0x0020
_CHARACTERISTICS = _CHAR_EXECUTABLE_IMAGE | _CHAR_LARGE_ADDRESS_AWARE

_SECTION_ALIGNMENT = 0x1000
_FILE_ALIGNMENT = 0x200
_IMAGE_BASE = 0x140000000  # x64 default
_SUBSYSTEM_WINDOWS_GUI = 2
_DLL_CHARACTERISTICS = 0x8160

_COM_DESCRIPTOR_DIRECTORY = 14
_NUM_DATA_DIRECTORIES = 16
_DATA_DIRECTORY_SIZE = 8

# Fixed file-layout offsets for the 1-section image this builder emits.
_DOS_HEADER_SIZE = 0x40
_DOS_STUB_SIZE = 0x80
_PE_SIG_OFFSET = _DOS_HEADER_SIZE + _DOS_STUB_SIZE  # 0xC0
_COFF_OFFSET = _PE_SIG_OFFSET + 4  # 0xC4
_OPTIONAL_OFFSET = _COFF_OFFSET + 20  # 0xD8 (PE32+ optional header is 240 bytes)
_SECTION_OFFSET = _OPTIONAL_OFFSET + 240  # 0x1C8
_SIZE_OF_HEADERS = 0x200

_TEXT_RAW_OFFSET = _SIZE_OF_HEADERS  # 0x200
_TEXT_RVA = 0x1000
_CLI_RAW_OFFSET = _TEXT_RAW_OFFSET
_CLI_RVA = _TEXT_RVA
_CLI_TO_METADATA_GAP = 0x50  # zeros between the CLI header and the metadata root
_METADATA_RAW_OFFSET = _CLI_RAW_OFFSET + _CLI_TO_METADATA_GAP  # 0x250
_METADATA_RVA = _CLI_RVA + _CLI_TO_METADATA_GAP  # 0x1050

_CLI_HEADER_SIZE = 72  # IMAGE_COR20_HEADER (0x48)
_COMFLAG_ILONLY = 0x00000001

_CHECKSUM_OPTIONAL_OFFSET = 64  # within the PE32+ optional header
_TIMESTAMP_COFF_OFFSET = 4  # within the COFF header
_ENTRYPOINT_DEFAULT = 0x06000001  # MethodDef token of the synthetic "Main"

_GUID_SIZE = 16

_ASSEMBLY_HASH_SHA1 = 0x8004
_ASSEMBLY_FLAG_PUBLIC_KEY = 0x0008

_TYPEDEF_FLAG_CLASS = 0x00100001  # Public | BeforeFieldInit
_FIELD_FLAG_PUBLIC_STATIC = 0x0016
_METHOD_FLAG_PUBLIC_STATIC_HIDEBYSIG = 0x0096

_METADATA_VERSION = b"v4.0.30319\x00\x00"

_STR_DEBUGGABLE = "DebuggableAttribute"
_STR_COMPANY = "AssemblyCompanyAttribute"
_STR_PRODUCT = "AssemblyProductAttribute"
_STR_COPYRIGHT = "AssemblyCopyrightAttribute"
_STR_TARGET_FRAMEWORK = "TargetFrameworkAttribute"
_STR_RELAXATIONS = "CompilationRelaxationsAttribute"
_MSCORLIB = "mscorlib"


def _align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def _compress_int(value: int) -> bytes:
    """ECMA-335 II.23.2 compressed integer."""
    if value < 0:
        raise ValueError("cannot compress a negative integer")
    if value <= 0x7F:
        return struct.pack("<B", value)
    if value <= 0x3FFF:
        return struct.pack(">H", 0x8000 | value)
    if value <= 0x1FFFFFFF:
        return struct.pack(">I", 0xC0000000 | value)
    raise ValueError("compressed integer too large")


def _ser_string(value: str) -> bytes:
    """Serialized string (compressed length + UTF-8), ECMA-335 II.23.2.16."""
    return _compress_int(len(value.encode("utf-8"))) + value.encode("utf-8")


def _coded_index(tag_bits: int, tag: int, row_index: int) -> int:
    return (row_index << tag_bits) | tag


# Default curated Apollo #US literals (exported for the catalog / samples).
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
DEFAULT_CALLBACK_URL = "https://192.168.10.20:8443"
DEFAULT_API_BASE = "/api/v1.4/agent/"
DEFAULT_PIPE_NAME = r"\\.\pipe\Mythic_Agent"
DEFAULT_BANNER = "Apollo -- Malleable C2 Profile Agent"
DEFAULT_HELP_TEXT = "Invalid command. Use 'help' to list available commands."
DEFAULT_ERROR_TEXT = "An error occurred while processing the command."

# Curated #US literal set, in deterministic insertion order.  Each entry is a
# (name, text) pair; the names are the Apollo config key names the catalog and
# inspect use to identify the payload's fingerprint family.  Several entries
# model the R4 fragment tier: callback URL and API-path segments that Apollo
# assembles at runtime, plus a deliberately split ``killdate`` so verify's
# fragment scan cannot be gamed by splitting the literal.
DEFAULT_USER_STRINGS: List[Tuple[str, str]] = [
    ("user_agent", DEFAULT_USER_AGENT),
    ("callback_url", DEFAULT_CALLBACK_URL),
    ("api_base", DEFAULT_API_BASE),
    ("api_login", "login"),
    ("api_checkin", "checkin"),
    ("killdate", "killdate"),
    ("encrypted_exchange_check", "encrypted_exchange_check"),
    ("aespsk_enc_key", "AESPSK"),
    ("aespsk_dec_key", "AESPSK"),
    ("payload_uuid", "payload_uuid"),
    ("pipe_name", DEFAULT_PIPE_NAME),
    ("cookie_name", "MythicSession"),
    ("query_param", "q"),
    ("fragment_url_prefix", "https://"),
    ("fragment_host", "192.168.10.20"),
    ("fragment_port", ":8443"),
    ("banner", DEFAULT_BANNER),
    ("help_text", DEFAULT_HELP_TEXT),
    ("error_text", DEFAULT_ERROR_TEXT),
    ("split_kill_left", "kill"),
    ("split_kill_right", "date"),
    ("manufacturer", "Mythic"),
]

DEFAULT_COMPANY = "Mythic Apollo Operations Team"
DEFAULT_PRODUCT = "Apollo Agent"
DEFAULT_COPYRIGHT = "Copyright (c) 2026 MythicDev. Authorized red-team exercise use only."
DEFAULT_TARGET_FRAMEWORK = ".NETFramework,Version=v4.0"
DEFAULT_MODULE_NAME = "Apollo.exe"
DEFAULT_ASSEMBLY_NAME = "Apollo"
DEFAULT_TIME_STAMP = 0x60000000

# Deterministic fake public-key blob in the "0x00 0x24 + 170 bytes" shape of a
# real RSA public key so the strong-name block looks structurally real.
DEFAULT_PUBLIC_KEY = b"\x00\x24" + bytes((i * 7 + 11) % 256 for i in range(170))

SIGNATURE_BLOCK_SIZE = 0x80


def _make_signature_block(seed: int) -> bytes:
    """Deterministic non-zero strong-name signature block (0x80 bytes).

    Non-zero so a fixture models a signed image whose signature bytes the
    metadata pass must zero in place (R3 soft-strip), not an already-zero block.
    """
    rng = random.Random(seed)
    return bytes(rng.randrange(1, 256) for _ in range(SIGNATURE_BLOCK_SIZE))


# ---------------------------------------------------------------------------
# Heap builders (all deduplicate; index 0 is reserved by the format)
# ---------------------------------------------------------------------------


class _StringsHeap:
    """#Strings: deduplicated, null-terminated UTF-8 entries."""

    def __init__(self):
        self._data = bytearray(b"\x00")
        self._offsets: Dict[str, int] = {}
        self.entry_offsets: Dict[str, int] = {}

    def add(self, text: str) -> int:
        existing = self._offsets.get(text)
        if existing is not None:
            return existing
        if "\x00" in text:
            raise ValueError("#Strings entries cannot contain NUL")
        offset = len(self._data)
        self._data += text.encode("utf-8") + b"\x00"
        self._offsets[text] = offset
        self.entry_offsets[text] = offset
        return offset

    def data(self) -> bytes:
        return bytes(self._data)


class _BlobHeap:
    """#Blob: deduplicated, length-prefixed entries."""

    def __init__(self):
        self._data = bytearray(b"\x00")
        self._offsets: Dict[bytes, int] = {}
        self.entry_offsets: Dict[bytes, int] = {}

    def add(self, blob: bytes) -> int:
        existing = self._offsets.get(blob)
        if existing is not None:
            return existing
        offset = len(self._data)
        self._data += _compress_int(len(blob)) + blob
        self._offsets[blob] = offset
        self.entry_offsets[blob] = offset
        return offset

    def data(self) -> bytes:
        return bytes(self._data)


class _UserStringHeap:
    """#US: deduplicated UTF-16LE user strings with a trailing flag byte.

    Each entry is ``[compressed_len][utf-16le][flag]`` where the length is
    ``2 * len(text) + 1`` and ``flag`` is 0x00 for plain 8-bit characters
    (ECMA-335 II.24.2.4).
    """

    def __init__(self):
        self._data = bytearray(b"\x00")
        self._offsets: Dict[str, int] = {}
        self.entry_offsets: Dict[str, int] = {}

    def add(self, text: str) -> int:
        existing = self._offsets.get(text)
        if existing is not None:
            return existing
        raw = text.encode("utf-16le")
        offset = len(self._data)
        self._data += _compress_int(len(raw) + 1) + raw + b"\x00"
        self._offsets[text] = offset
        self.entry_offsets[text] = offset
        return offset

    def data(self) -> bytes:
        return bytes(self._data)


class _GuidHeap:
    """#GUID: a plain sequence of 16-byte GUIDs, 1-based addressing."""

    def __init__(self):
        self._data = bytearray()
        self._indexes: Dict[bytes, int] = {}
        self.entry_data_offsets: Dict[bytes, int] = {}

    def add(self, raw: bytes) -> int:
        if len(raw) != _GUID_SIZE:
            raise ValueError("GUID entries must be exactly 16 bytes")
        existing = self._indexes.get(raw)
        if existing is not None:
            return existing
        self._indexes[raw] = len(self._data) // _GUID_SIZE + 1
        self.entry_data_offsets[raw] = len(self._data)
        self._data += raw
        return self._indexes[raw]

    def data(self) -> bytes:
        return bytes(self._data)


# ---------------------------------------------------------------------------
# Layout record
# ---------------------------------------------------------------------------


class StreamInfo:
    """File offset / RVA / size for one metadata stream."""

    __slots__ = ("name", "offset", "rva", "size")

    def __init__(self, name, offset, rva, size):
        self.name = name
        self.offset = offset  # file offset of the stream data
        self.rva = rva
        self.size = size

    def to_dict(self):
        return {"name": self.name, "offset": self.offset, "rva": self.rva, "size": self.size}


class TableInfo:
    """Per-table layout: row count, row size, and per-row field file offsets."""

    __slots__ = ("name", "num_rows", "row_size", "rows")

    def __init__(self, name, num_rows, row_size, rows):
        self.name = name
        self.num_rows = num_rows
        self.row_size = row_size
        self.rows = rows  # list of {field -> file offset}

    def field(self, field, row=0):
        """File offset of a named field in `row`."""
        return self.rows[row][field]

    def to_dict(self):
        return {
            "name": self.name,
            "num_rows": self.num_rows,
            "row_size": self.row_size,
            "rows": self.rows,
        }


class Layout:
    """Deterministic record of every notable file offset in a built image."""

    def __init__(self):
        self.size = 0
        self.time_stamp_offset = 0
        self.checksum_offset = 0
        self.cli = {}  # CLI-header field name -> file offset or literal value
        self.metadata_offset = 0
        self.metadata_rva = 0
        self.metadata_size = 0
        self.streams: Dict[str, StreamInfo] = {}
        self.tables: Dict[str, TableInfo] = {}
        self.strings: Dict[str, Dict[str, int]] = {}  # text -> {index, offset}
        self.user_strings: Dict[str, Dict[str, int]] = {}  # text -> {index, entry_offset, offset}
        self.blobs: Dict[str, Dict[str, int]] = {}  # name -> {index, entry_offset, data_offset}
        self.blob_text: Dict[str, int] = {}  # embedded text -> file offset
        self.guids: Dict[str, int] = {}  # 'mvid' / 'module_guid' -> file offset

    def to_dict(self) -> dict:
        return {
            "size": self.size,
            "time_stamp_offset": self.time_stamp_offset,
            "checksum_offset": self.checksum_offset,
            "cli": dict(self.cli),
            "metadata_offset": self.metadata_offset,
            "metadata_rva": self.metadata_rva,
            "metadata_size": self.metadata_size,
            "streams": {name: s.to_dict() for name, s in sorted(self.streams.items())},
            "tables": {name: t.to_dict() for name, t in sorted(self.tables.items())},
            "strings": dict(self.strings),
            "user_strings": dict(self.user_strings),
            "blobs": dict(self.blobs),
            "blob_text": dict(self.blob_text),
            "guids": dict(self.guids),
        }


class BuildResult:
    """Built image: raw bytes plus the deterministic layout record."""

    __slots__ = ("bytes", "layout")

    def __init__(self, data: bytes, layout: Layout):
        self.bytes = data
        self.layout = layout

    def write(self, path):
        with open(path, "wb") as fh:
            fh.write(self.bytes)
        return path


# ---------------------------------------------------------------------------
# Table serialization
# ---------------------------------------------------------------------------

# Table numbers per ECMA-335 (matches dnfile's MetadataTables enum).
TABLE_NUMBERS = {
    "Module": 0,
    "TypeRef": 1,
    "TypeDef": 2,
    "Field": 4,
    "MethodDef": 6,
    "Param": 8,
    "MemberRef": 10,
    "CustomAttribute": 12,
    "Assembly": 32,
    "AssemblyRef": 35,
}

# Field layouts.  ``kind`` is one of:
#   "u2"/"u4"/"u8"         raw integer
#   "str"/"blob"/"guid"    heap into the named heap (0-based, 2-byte widths
#                          because HeapOffsetSizes=0)
#   "idx:<Table>"          1-based index into the named table (row lists)
#   "coded:<Family>"       precomputed coded index (the row value is already
#                          encoded via _coded_index)
# The widths of "idx" and "coded" fields are computed from the row counts
# using the exact rule dnfile applies when it parses the rows back.
#
# NOTE: this schema dict is renamed from the old fixtures' ``TABLE_FIELDS`` so
# it does not clobber the sample-offset ``TABLE_FIELDS`` dict exported by the
# samples section below (which has always shadowed this name in test scope).
TABLE_FIELDS_SCHEMA = {
    "Module": [("Generation", "u2"), ("Name", "str"), ("Mvid", "guid"),
               ("EncId", "guid"), ("EncBaseId", "guid")],
    "TypeRef": [("ResolutionScope", "coded:ResolutionScope"), ("TypeName", "str"),
                ("TypeNamespace", "str")],
    "TypeDef": [("Flags", "u4"), ("TypeName", "str"), ("TypeNamespace", "str"),
                ("Extends", "coded:TypeDefOrRef"), ("FieldList", "idx:Field"),
                ("MethodList", "idx:MethodDef")],
    "Field": [("Flags", "u2"), ("Name", "str"), ("Signature", "blob")],
    "MethodDef": [("RVA", "u4"), ("ImplFlags", "u2"), ("Flags", "u2"),
                  ("Name", "str"), ("Signature", "blob"), ("ParamList", "idx:Param")],
    "Param": [("Flags", "u2"), ("Sequence", "u2"), ("Name", "str")],
    "MemberRef": [("Class", "coded:MemberRefParent"), ("Name", "str"),
                  ("Signature", "blob")],
    "CustomAttribute": [("Parent", "coded:HasCustomAttribute"),
                        ("Type", "coded:CustomAttributeType"), ("Value", "blob")],
    "Assembly": [("HashAlgId", "u4"), ("MajorVersion", "u2"), ("MinorVersion", "u2"),
                 ("BuildNumber", "u2"), ("RevisionNumber", "u2"), ("Flags", "u4"),
                 ("PublicKey", "blob"), ("Name", "str"), ("Culture", "str")],
    "AssemblyRef": [("MajorVersion", "u2"), ("MinorVersion", "u2"),
                    ("BuildNumber", "u2"), ("RevisionNumber", "u2"), ("Flags", "u4"),
                    ("PublicKey", "blob"), ("Name", "str"), ("Culture", "str"),
                    ("HashValue", "blob")],
}

# Coded-index tag sets (position in the tuple == tag value), per ECMA-335 and
# dnfile.codedindex.
CODED_TABLES = {
    "ResolutionScope": ("Module", "ModuleRef", "AssemblyRef", "TypeRef"),
    "TypeDefOrRef": ("TypeDef", "TypeRef", "TypeSpec"),
    "MemberRefParent": ("TypeDef", "TypeRef", "ModuleRef", "MethodDef", "TypeSpec"),
    "HasCustomAttribute": (
        "MethodDef", "Field", "TypeRef", "TypeDef", "Param", "InterfaceImpl",
        "MemberRef", "Module", "DeclSecurity", "Property", "Event",
        "StandAloneSig", "ModuleRef", "TypeSpec", "Assembly", "AssemblyRef",
        "File", "ExportedType", "ManifestResource", "GenericParam",
        "GenericParamConstraint",
    ),
    "CustomAttributeType": ("Unused", "Unused", "MethodDef", "MemberRef", "Unused"),
}

CODED_TAG_BITS = {
    "ResolutionScope": 2,
    "TypeDefOrRef": 2,
    "MemberRefParent": 3,
    "HasCustomAttribute": 5,
    "CustomAttributeType": 3,
}


def _coded_width(rowcounts: Dict[str, int], family: str) -> int:
    tag_bits = CODED_TAG_BITS[family]
    max_rows = max(rowcounts.get(t, 0) for t in CODED_TABLES[family] if t != "Unused")
    return 2 if max_rows <= 2 ** (16 - tag_bits) else 4


def _index_width(rowcounts: Dict[str, int], table: str) -> int:
    return 2 if rowcounts.get(table, 0) <= 0xFFFF else 4


def _table_width(name: str, rowcounts: Dict[str, int]) -> int:
    width = 0
    for field, kind in TABLE_FIELDS_SCHEMA[name]:
        if kind == "u2":
            width += 2
        elif kind == "u4":
            width += 4
        elif kind == "u8":
            width += 8
        elif kind in ("str", "blob", "guid"):
            width += 2
        elif kind.startswith("idx:"):
            width += _index_width(rowcounts, kind[4:])
        elif kind.startswith("coded:"):
            width += _coded_width(rowcounts, kind[6:])
        else:
            raise ValueError(f"unknown field kind {kind!r} in table {name}")
    return width


class _Serializer:
    """Build the #~ stream and per-row field offsets from a row model."""

    def __init__(self, rowcounts: Dict[str, int], heaps: Dict[str, object]):
        self.rowcounts = rowcounts
        self.heaps = heaps
        self.mask_valid = 0
        for name in rowcounts:
            self.mask_valid |= 1 << TABLE_NUMBERS[name]

    def _encode(self, name: str, kind: str, value) -> bytes:
        if kind == "u2":
            return struct.pack("<H", value)
        if kind == "u4":
            return struct.pack("<I", value)
        if kind == "u8":
            return struct.pack("<Q", value)
        if kind == "str":
            return struct.pack("<H", self.heaps["strings"].add(value) if value is not None else 0)
        if kind == "blob":
            return struct.pack("<H", self.heaps["blobs"].add(value) if value is not None else 0)
        if kind == "guid":
            if isinstance(value, bytes):
                return struct.pack("<H", self.heaps["guids"].add(value))
            return struct.pack("<H", value if value is not None else 0)
        if kind.startswith("idx:"):
            return struct.pack("<H", value or 0)
        if kind.startswith("coded:"):
            fmt = "H" if _coded_width(self.rowcounts, kind[6:]) == 2 else "I"
            return struct.pack(f"<{fmt}", value)
        raise ValueError(f"cannot encode kind {kind!r}")

    def serialize(self, rows: Dict[str, List[dict]]) -> Tuple[bytes, Dict[str, List[Dict[str, int]]]]:
        """Pack rows into a #~ stream.

        Returns (stream bytes, {table: [{field -> stream-relative offset}]}).
        Offsets are relative to the start of the #~ stream data.
        """
        header = struct.pack("<IBBBBQQ", 0, 1, 1, 0x00, 0, self.mask_valid, 0)
        assert len(header) == 24
        stream = bytearray(header)
        ordered = sorted(self.rowcounts, key=TABLE_NUMBERS.__getitem__)
        for name in ordered:
            stream += struct.pack("<I", self.rowcounts[name])

        field_offsets: Dict[str, List[Dict[str, int]]] = {}
        for name in ordered:
            row_offsets = []
            for row in rows[name]:
                positions = {}
                for field, kind in TABLE_FIELDS_SCHEMA[name]:
                    positions[field] = len(stream)
                    stream += self._encode(name, kind, row[field])
                row_offsets.append(positions)
            field_offsets[name] = row_offsets
        return bytes(stream), field_offsets


# ---------------------------------------------------------------------------
# The builder
# ---------------------------------------------------------------------------


class PeBuilder:
    """Build a synthetic Apollo-shaped WinExe image.

    All content is a deterministic function of the constructor arguments;
    nothing reads the clock or the environment.
    """

    def __init__(
        self,
        *,
        mvid: bytes,
        module_guid: bytes,
        assembly_version: Tuple[int, int, int, int] = (4, 0, 0, 0),
        company: str = DEFAULT_COMPANY,
        product: str = DEFAULT_PRODUCT,
        copyright: str = DEFAULT_COPYRIGHT,
        target_framework: str = DEFAULT_TARGET_FRAMEWORK,
        module_name: str = DEFAULT_MODULE_NAME,
        assembly_name: str = DEFAULT_ASSEMBLY_NAME,
        strong_name: bool = True,
        public_key: Optional[bytes] = None,
        signature_data: Optional[bytes] = None,
        user_strings: Optional[List[Tuple[str, str]]] = None,
        extra_strings: Optional[List[str]] = None,
        debuggable: bool = True,
        compilation_relaxations: bool = True,
        target_framework_attr: bool = True,
        time_stamp: int = DEFAULT_TIME_STAMP,
        checksum: int = 0,
        entry_point_token: int = _ENTRYPOINT_DEFAULT,
        seed: int = 0,
    ):
        if len(mvid) != _GUID_SIZE:
            raise ValueError(f"MVID must be {_GUID_SIZE} bytes, got {len(mvid)}")
        if len(module_guid) != _GUID_SIZE:
            raise ValueError(f"module GUID must be {_GUID_SIZE} bytes, got {len(module_guid)}")
        if len(assembly_version) != 4:
            raise ValueError("assembly_version must be (major, minor, build, revision)")
        for part in assembly_version:
            if not 0 <= part <= 0xFFFF:
                raise ValueError("assembly version parts must fit in 16 bits")
        self._mvid = bytes(mvid)
        self._module_guid = bytes(module_guid)
        self._version = tuple(assembly_version)
        self._company = company
        self._product = product
        self._copyright = copyright
        self._target_framework = target_framework
        self._module_name = module_name
        self._assembly_name = assembly_name
        self._strong_name = strong_name
        self._public_key = public_key if public_key is not None else DEFAULT_PUBLIC_KEY
        sig = signature_data if signature_data is not None else _make_signature_block(seed)
        if len(sig) != SIGNATURE_BLOCK_SIZE:
            raise ValueError(f"signature_data must be exactly {SIGNATURE_BLOCK_SIZE} bytes")
        self._signature_data = sig
        self._user_strings = list(user_strings) if user_strings is not None else list(DEFAULT_USER_STRINGS)
        self._extra_strings = list(extra_strings) if extra_strings else []
        self._debuggable = debuggable
        self._compilation_relaxations = compilation_relaxations
        self._target_framework_attr = target_framework_attr
        self._time_stamp = time_stamp
        self._checksum = checksum
        self._entry_point_token = entry_point_token

    # ------------------------------------------------------------------
    # identity accessors (used by tests and later passes)
    # ------------------------------------------------------------------

    @property
    def mvid(self) -> bytes:
        return self._mvid

    @property
    def module_guid(self) -> bytes:
        return self._module_guid

    @property
    def assembly_version(self) -> Tuple[int, int, int, int]:
        return self._version

    @property
    def strong_name(self) -> bool:
        return self._strong_name

    # ------------------------------------------------------------------
    # model helpers
    # ------------------------------------------------------------------

    def _type_refs(self) -> List[Tuple[str, str]]:
        refs = [("System", "Object")]
        if self._debuggable:
            refs.append(("System.Diagnostics", _STR_DEBUGGABLE))
        refs += [
            ("System.Reflection", _STR_COMPANY),
            ("System.Reflection", _STR_PRODUCT),
            ("System.Reflection", _STR_COPYRIGHT),
        ]
        if self._target_framework_attr:
            refs.append(("System.Runtime.Versioning", _STR_TARGET_FRAMEWORK))
        if self._compilation_relaxations:
            refs.append(("System.Runtime.CompilerServices", _STR_RELAXATIONS))
        refs += [
            ("ApolloInterop", "ICommand"),
            ("Mythic.Rest", "HttpRestClient"),
            ("Mythic.Structs", "JsonObject"),
        ]
        return refs

    def _strings_texts(self) -> List[str]:
        """All #Strings entries in deterministic insertion order."""
        texts: List[str] = []
        seen = set()

        def push(text):
            if text and text not in seen:
                seen.add(text)
                texts.append(text)

        push(self._module_name)
        push("Program")
        push("Apollo")
        for namespace, name in self._type_refs():
            push(namespace)
            push(name)
        push("UserAgent")
        push("Main")
        push("args")
        push(".ctor")
        push(_MSCORLIB)
        push(self._assembly_name)
        for text in self._extra_strings:
            push(text)
        return texts

    @staticmethod
    def _ca_string_blob(value: str) -> bytes:
        # ECma-335 II.23.3: prolog, fixed serString arg, NumNamed=0.
        return b"\x01\x00" + _ser_string(value) + b"\x00\x00"

    @staticmethod
    def _ca_debuggable() -> bytes:
        # [assembly: Debuggable(DebuggingModes.Default)]: prolog, enum value u2,
        # NumNamed=0, classic trailing zero word.
        return b"\x01\x00\x02\x00\x00\x00\x00\x00"

    @staticmethod
    def _ca_relaxations() -> bytes:
        # [assembly: CompilationRelaxations(8)]
        return b"\x01\x00\x08\x00\x00\x00\x00\x00"

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------

    def build(self) -> BuildResult:
        layout = Layout()
        layout.time_stamp_offset = _COFF_OFFSET + _TIMESTAMP_COFF_OFFSET
        layout.checksum_offset = _OPTIONAL_OFFSET + _CHECKSUM_OPTIONAL_OFFSET

        # -- heaps ----------------------------------------------------------
        strings = _StringsHeap()
        for text in self._strings_texts():
            strings.add(text)

        guids = _GuidHeap()
        guids.add(self._mvid)  # heap index 1 = MVID
        guids.add(self._module_guid)  # heap index 2 = module GUID

        blobs = _BlobHeap()
        self._register_blobs(blobs)

        us = _UserStringHeap()
        for _, text in self._user_strings:
            us.add(text)

        # -- tables -----------------------------------------------------------
        rows = self._make_rows()
        rowcounts = {name: len(rows[name]) for name in rows}
        serializer = _Serializer(rowcounts, {"strings": strings, "guids": guids, "blobs": blobs})
        tables_bytes, table_field_offsets = serializer.serialize(rows)

        # -- metadata root ------------------------------------------------------
        contents = {
            "#~": tables_bytes,
            "#Strings": strings.data(),
            "#US": us.data(),
            "#GUID": guids.data(),
            "#Blob": blobs.data(),
        }
        metadata, stream_offsets = self._build_metadata_root(contents)
        metadata_size = _align(len(metadata), 4)

        # -- strong-name signature block placement -------------------------------
        strong_rva = strong_size = 0
        strong_offset_in_text = _CLI_TO_METADATA_GAP + metadata_size
        if self._strong_name:
            strong_size = SIGNATURE_BLOCK_SIZE
            strong_raw = _align(_METADATA_RAW_OFFSET + metadata_size, 8)
            strong_offset_in_text = strong_raw - _TEXT_RAW_OFFSET
            strong_rva = _TEXT_RVA + strong_offset_in_text

        # -- text section ----------------------------------------------------------
        text_section = bytearray(strong_offset_in_text + (strong_size or 0))
        cli_header = struct.pack(
            "<IHHIIIIIIIIIIIIIIII",
            _CLI_HEADER_SIZE,
            2, 5,
            _METADATA_RVA,
            metadata_size,
            _COMFLAG_ILONLY,
            self._entry_point_token,
            0, 0,
            strong_rva, strong_size,
            0, 0, 0, 0, 0, 0, 0, 0,
        )
        assert len(cli_header) == _CLI_HEADER_SIZE
        text_section[0:len(cli_header)] = cli_header
        text_section[_CLI_TO_METADATA_GAP:_CLI_TO_METADATA_GAP + len(metadata)] = metadata
        if self._strong_name:
            text_section[strong_offset_in_text:strong_offset_in_text + strong_size] = self._signature_data
        content_end = len(text_section)

        # -- headers -------------------------------------------------------------------
        image = self._build_headers(bytes(text_section), content_end)

        # -- layout population ------------------------------------------------------------
        layout.metadata_offset = _METADATA_RAW_OFFSET
        layout.metadata_rva = _METADATA_RVA
        layout.metadata_size = metadata_size
        layout.size = len(image)
        layout.cli.update(
            {
                "offset": _CLI_RAW_OFFSET,
                "rva": _CLI_RVA,
                "metadata_rva_field": _CLI_RAW_OFFSET + 8,
                "metadata_size_field": _CLI_RAW_OFFSET + 12,
                "flags_field": _CLI_RAW_OFFSET + 16,
                "entry_point_field": _CLI_RAW_OFFSET + 20,
                "strong_name_rva_field": _CLI_RAW_OFFSET + 32,
                "strong_name_size_field": _CLI_RAW_OFFSET + 36,
                "strong_name_rva": strong_rva,
                "strong_name_size": strong_size,
                "entry_point_token": self._entry_point_token,
                "strong_name": self._strong_name,
            }
        )

        for name in ("#~", "#Strings", "#US", "#GUID", "#Blob"):
            s_off = stream_offsets[name]
            layout.streams[name] = StreamInfo(
                name,
                _METADATA_RAW_OFFSET + s_off,
                _METADATA_RVA + s_off,
                len(contents[name]),
            )

        stream_base = layout.streams["#~"].offset
        for name, rows_offsets in table_field_offsets.items():
            positional = []
            for row in rows_offsets:
                positional.append({field: stream_base + pos for field, pos in row.items()})
            layout.tables[name] = TableInfo(name, rowcounts[name], _table_width(name, rowcounts), positional)

        # #Strings file offsets (UTF-8, null-terminated)
        strings_base = layout.streams["#Strings"].offset
        for text, heap_off in sorted(strings.entry_offsets.items()):
            layout.strings[text] = {"index": heap_off, "offset": strings_base + heap_off}

        # #US file offsets (UTF-16LE; entry start vs. string-data start)
        us_base = layout.streams["#US"].offset
        for text in self._user_strings:
            heap_off = us.entry_offsets[text[1]]
            entry_len = len(_compress_int(len(text[1].encode("utf-16le")) + 1))
            layout.user_strings[text[0]] = {
                "index": heap_off,
                "entry_offset": us_base + heap_off,
                "offset": us_base + heap_off + entry_len,
            }

        # #Blob named entries (index / entry start / data start)
        blob_base = layout.streams["#Blob"].offset
        for name, blob in self._blob_entries.items():
            heap_off = blobs.entry_offsets[blob]
            entry_len = len(_compress_int(len(blob)))
            layout.blobs[name] = {
                "index": heap_off,
                "entry_offset": blob_base + heap_off,
                "data_offset": blob_base + heap_off + entry_len,
            }
        # text embedded inside serialized attribute blobs (UTF-8)
        for name, text in (("CompanyAttribute", self._company),
                           ("ProductAttribute", self._product),
                           ("CopyrightAttribute", self._copyright),
                           ("TargetFrameworkAttribute", self._target_framework)):
            blob = self._blob_entries[name]
            heap_off = blobs.entry_offsets[blob]
            entry_len = len(_compress_int(len(blob)))
            # prolog (2 bytes) + serString length prefix before the text
            text_offset = blob_base + heap_off + entry_len + 2 + len(_compress_int(len(text.encode("utf-8"))))
            layout.blob_text[text] = text_offset

        # GUID heap file offsets
        guid_base = layout.streams["#GUID"].offset
        layout.guids["mvid"] = guid_base + guids.entry_data_offsets[self._mvid]
        layout.guids["module_guid"] = guid_base + guids.entry_data_offsets[self._module_guid]

        return BuildResult(bytes(image), layout)

    def _register_blobs(self, blobs: _BlobHeap):
        """Register every #Blob entry used by the model (deterministic order)."""
        self._blob_entries: Dict[str, bytes] = {}
        # Method/field signatures (all content-deduped).
        self._blob_sig_main = b"\x20\x01\x01\x0e"  # static void Main(string[])
        self._blob_sig_ctor_void = b"\x20\x00\x01"
        self._blob_sig_ctor_int = b"\x20\x01\x01\x08"
        self._blob_sig_field = b"\x06\x0e"  # FIELD sig: string
        # The string-parameter ctor signature is byte-identical to Main's sig.
        self._blob_sig_ctor_str = self._blob_sig_main

        # strong-name public key blob (referenced only when strong_name=True)
        self._blob_public_key = self._public_key

        def named(name, blob_bytes):
            self._blob_entries[name] = blob_bytes
            blobs.add(blob_bytes)

        if self._debuggable:
            named("Debuggable", self._ca_debuggable())
        named("CompanyAttribute", self._ca_string_blob(self._company))
        named("ProductAttribute", self._ca_string_blob(self._product))
        named("CopyrightAttribute", self._ca_string_blob(self._copyright))
        if self._target_framework_attr:
            named("TargetFrameworkAttribute", self._ca_string_blob(self._target_framework))
        if self._compilation_relaxations:
            named("RelaxationsAttribute", self._ca_relaxations())

        # Now register the signature blobs and public key in the heap
        blobs.add(self._blob_sig_main)
        blobs.add(self._blob_sig_ctor_void)
        blobs.add(self._blob_sig_ctor_int)
        blobs.add(self._blob_sig_field)
        blobs.add(self._public_key)

    def _make_rows(self) -> Dict[str, List[dict]]:
        rows = {name: [] for name in TABLE_FIELDS_SCHEMA}

        # Module ---------------------------------------------------------------
        rows["Module"].append(
            {
                "Generation": 0,
                "Name": self._module_name,
                "Mvid": self._mvid,  # GUID heap (raw 16 bytes; index resolved lazily)
                "EncId": None,
                "EncBaseId": None,
            }
        )
        # TypeRef (resolution scope for every row = mscorlib AssemblyRef #1,
        # coded tag 2 = AssemblyRef).
        for namespace, name in self._type_refs():
            rows["TypeRef"].append(
                {
                    "ResolutionScope": _coded_index(2, 2, 1),
                    "TypeName": name,
                    "TypeNamespace": namespace,
                }
            )
        # TypeDef ----------------------------------------------------------------
        rows["TypeDef"].append(
            {
                "Flags": _TYPEDEF_FLAG_CLASS,
                "TypeName": "Program",
                "TypeNamespace": "Apollo",
                "Extends": _coded_index(2, 1, 1),  # System.Object (TypeRef #1)
                "FieldList": 1,
                "MethodList": 1,
            }
        )
        # Field -------------------------------------------------------------------
        rows["Field"].append(
            {"Flags": _FIELD_FLAG_PUBLIC_STATIC, "Name": "UserAgent", "Signature": self._blob_sig_field}
        )
        # MethodDef ----------------------------------------------------------------
        rows["MethodDef"].append(
            {
                "RVA": 0,
                "ImplFlags": 0,
                "Flags": _METHOD_FLAG_PUBLIC_STATIC_HIDEBYSIG,
                "Name": "Main",
                "Signature": self._blob_sig_main,
                "ParamList": 1,
            }
        )
        # Param ----------------------------------------------------------------------
        rows["Param"].append({"Flags": 0, "Sequence": 1, "Name": "args"})

        # MemberRef / CustomAttribute ----------------------------------------------------
        # Order here must match _type_refs: attr type names map to their TypeRef rows.
        attr_order = []
        if self._debuggable:
            attr_order.append(_STR_DEBUGGABLE)
        attr_order += [_STR_COMPANY, _STR_PRODUCT, _STR_COPYRIGHT]
        if self._target_framework_attr:
            attr_order.append(_STR_TARGET_FRAMEWORK)
        if self._compilation_relaxations:
            attr_order.append(_STR_RELAXATIONS)
        typeref_row = {
            name: i + 1 for i, (_, name) in enumerate(self._type_refs())
        }
        sig_of = {
            _STR_DEBUGGABLE: self._blob_sig_ctor_void,
            _STR_COMPANY: self._blob_sig_ctor_str,
            _STR_PRODUCT: self._blob_sig_ctor_str,
            _STR_COPYRIGHT: self._blob_sig_ctor_str,
            _STR_TARGET_FRAMEWORK: self._blob_sig_ctor_str,
            _STR_RELAXATIONS: self._blob_sig_ctor_int,
        }
        blob_of = {
            _STR_DEBUGGABLE: "Debuggable",
            _STR_COMPANY: "CompanyAttribute",
            _STR_PRODUCT: "ProductAttribute",
            _STR_COPYRIGHT: "CopyrightAttribute",
            _STR_TARGET_FRAMEWORK: "TargetFrameworkAttribute",
            _STR_RELAXATIONS: "RelaxationsAttribute",
        }
        for i, name in enumerate(attr_order, start=1):
            rows["MemberRef"].append(
                {
                    "Class": _coded_index(3, 1, typeref_row[name]),  # MemberRefParent tag 1 = TypeRef
                    "Name": ".ctor",
                    "Signature": sig_of[name],
                }
            )
            rows["CustomAttribute"].append(
                {
                    "Parent": _coded_index(5, 14, 1),  # HasCustomAttribute tag 14 = Assembly
                    "Type": _coded_index(3, 3, i),  # CustomAttributeType tag 3 = MemberRef
                    "Value": self._blob_entries[blob_of[name]],
                }
            )

        # Assembly -------------------------------------------------------------------------
        flags = _ASSEMBLY_FLAG_PUBLIC_KEY if self._strong_name else 0
        rows["Assembly"].append(
            {
                "HashAlgId": _ASSEMBLY_HASH_SHA1,
                "MajorVersion": self._version[0],
                "MinorVersion": self._version[1],
                "BuildNumber": self._version[2],
                "RevisionNumber": self._version[3],
                "Flags": flags,
                "PublicKey": self._blob_public_key if self._strong_name else None,
                "Name": self._assembly_name,
                "Culture": None,
            }
        )
        # AssemblyRef (mscorlib) ---------------------------------------------------------------
        rows["AssemblyRef"].append(
            {
                "MajorVersion": 4,
                "MinorVersion": 0,
                "BuildNumber": 0,
                "RevisionNumber": 0,
                "Flags": 0,
                "PublicKey": None,
                "Name": _MSCORLIB,
                "Culture": None,
                "HashValue": None,
            }
        )
        return rows

    def _build_metadata_root(self, contents: Dict[str, bytes]) -> Tuple[bytes, Dict[str, int]]:
        """Assemble a metadata root; returns (bytes, {stream -> root-relative offset})."""
        stream_order = ["#~", "#Strings", "#US", "#GUID", "#Blob"]
        header = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(_METADATA_VERSION))
        header += _METADATA_VERSION
        header += struct.pack("<HH", 0, len(stream_order))
        assert len(header) == 32

        entry_sizes = [self._stream_entry_size(name) for name in stream_order]
        cursor = len(header) + sum(entry_sizes)
        offsets: Dict[str, int] = {}
        stream_table = bytearray()
        for name, entry_size in zip(stream_order, entry_sizes):
            content = contents[name]
            offsets[name] = cursor
            stream_table += struct.pack("<II", cursor, len(content))
            name_bytes = name.encode("ascii") + b"\x00"
            stream_table += name_bytes + b"\x00" * (entry_size - 8 - len(name_bytes))
            cursor = _align(cursor + len(content), 4)

        root = bytearray(header)
        root += stream_table
        for name in stream_order:
            root += b"\x00" * (offsets[name] - len(root))
            root += contents[name]
        return bytes(root), offsets

    @classmethod
    def _stream_entry_size(cls, name: str) -> int:
        # dnfile reads len(name)+(4 - len(name)%4) bytes for the padded name
        # (len excludes the NUL); the entry is Offset(4)+Size(4)+Name.
        return 8 + len(name) + (4 - (len(name) % 4))

    def _build_headers(self, text_section: bytes, content_end: int) -> bytes:
        raw_size = _align(content_end, _FILE_ALIGNMENT)
        virtual_size = _align(content_end, _SECTION_ALIGNMENT)

        dos = bytearray(b"\x00" * _DOS_HEADER_SIZE)
        dos[0:2] = struct.pack("<H", _DOS_MAGIC)
        dos[0x3C:0x40] = struct.pack("<I", _PE_SIG_OFFSET)
        stub = b"\x00" * _DOS_STUB_SIZE

        coff = struct.pack(
            "<HHIIIHH",
            _MACHINE_AMD64,
            1,  # NumberOfSections
            self._time_stamp,
            0,  # PointerToSymbolTable
            0,  # NumberOfSymbols
            240,  # SizeOfOptionalHeader
            _CHARACTERISTICS,
        )

        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            _PE32PLUS_MAGIC,
            0x30,  # linker major
            0x00,  # linker minor
            raw_size,  # SizeOfCode
            0,  # SizeOfInitializedData
            0,  # SizeOfUninitializedData
            0,  # AddressOfEntryPoint (CLR image; the CLI header drives loading)
            _TEXT_RVA,  # BaseOfCode
            _IMAGE_BASE,
            _SECTION_ALIGNMENT,
            _FILE_ALIGNMENT,
            6,  # MajorOperatingSystemVersion
            0,
            0,  # MajorImageVersion
            0,
            6,  # MajorSubsystemVersion
            0,
            0,  # Win32VersionValue
            _align(_TEXT_RVA + virtual_size, _SECTION_ALIGNMENT),  # SizeOfImage
            _SIZE_OF_HEADERS,
            self._checksum,
            _SUBSYSTEM_WINDOWS_GUI,
            _DLL_CHARACTERISTICS,
            0x400000,  # SizeOfStackReserve
            0x1000,  # SizeOfStackCommit
            0x100000,  # SizeOfHeapReserve
            0x1000,  # SizeOfHeapCommit
            0,  # LoaderFlags
            _NUM_DATA_DIRECTORIES,
        )
        assert len(opt) == 112

        directories = bytearray(_NUM_DATA_DIRECTORIES * _DATA_DIRECTORY_SIZE)
        com_off = _COM_DESCRIPTOR_DIRECTORY * _DATA_DIRECTORY_SIZE
        directories[com_off:com_off + 8] = struct.pack("<II", _CLI_RVA, _CLI_HEADER_SIZE)

        section = struct.pack(
            "<8sIIIIIIHHI",
            b".text\x00\x00\x00",
            virtual_size,
            _TEXT_RVA,
            raw_size,
            _TEXT_RAW_OFFSET,
            0,  # PointerToRelocations
            0,  # PointerToLineNumbers
            0,  # NumberOfRelocations
            0,  # NumberOfLineNumbers
            0x60000020,  # CODE | EXECUTE | READ
        )

        headers = bytes(dos) + stub + struct.pack("<I", _PE_MAGIC) + coff
        headers += opt + bytes(directories) + section
        headers += b"\x00" * (_SIZE_OF_HEADERS - len(headers))
        assert len(headers) == _SIZE_OF_HEADERS

        image = headers + bytes(text_section)
        image += b"\x00" * (raw_size - content_end)
        return image


def build_apollo_sample(**kwargs) -> BuildResult:
    """Build a default Apollo-shaped sample with overridable PeBuilder kwargs."""
    return PeBuilder(**kwargs).build()


# ---------------------------------------------------------------------------
# 3. Apollo-shaped sample fixture and exported constants
# ---------------------------------------------------------------------------
#
# This section is the single source of truth for the default Apollo-shaped
# `BuildResult` used by the fixture tests (via the `samples` re-export) and by
# the package's synthetic-tree CLI modes.  It exports the exact `Layout` and
# the byte positions of every curated #US literal so that tests and later
# scan/scrub/verify passes can assert deterministic offsets.
#
# All values are derived from the `PeBuilder` above so they remain consistent
# across Python versions and do not depend on a real compiler.

# Deterministic defaults used by the "apollo sample" fixture.
SAMPLE_MVID = bytes.fromhex("112233445566778899aabbccddeeff00")
SAMPLE_MODULE_GUID = bytes.fromhex("ffeeddccbbaa99887766554433221100")
SAMPLE_ASSEMBLY_VERSION = (4, 0, 0, 0)

# A deterministic seed for the strong-name signature block so it's always
# non-zero (and thus scrubbable by the metadata pass) but byte-identical
# across runs.
SAMPLE_SIGNATURE_SEED = 0xC0FFEE

# Build the canonical sample once; exported for test consumption.
_SAMPLE_RESULT: BuildResult = PeBuilder(
    mvid=SAMPLE_MVID,
    module_guid=SAMPLE_MODULE_GUID,
    assembly_version=SAMPLE_ASSEMBLY_VERSION,
    company=DEFAULT_COMPANY,
    product=DEFAULT_PRODUCT,
    copyright=DEFAULT_COPYRIGHT,
    target_framework=DEFAULT_TARGET_FRAMEWORK,
    module_name=DEFAULT_MODULE_NAME,
    assembly_name=DEFAULT_ASSEMBLY_NAME,
    strong_name=True,
    public_key=DEFAULT_PUBLIC_KEY,
    signature_data=None,  # deterministic seed chosen below
    user_strings=DEFAULT_USER_STRINGS,
    debuggable=True,
    compilation_relaxations=True,
    target_framework_attr=True,
    time_stamp=DEFAULT_TIME_STAMP,
    checksum=0,
    seed=SAMPLE_SIGNATURE_SEED,
).build()


def sample_result() -> BuildResult:
    """Return the canonical Apollo-shaped `BuildResult`."""
    return _SAMPLE_RESULT


def sample_bytes() -> bytes:
    """Return the raw image bytes of the canonical sample."""
    return _SAMPLE_RESULT.bytes


def sample_layout() -> Layout:
    """Return the `Layout` record for the canonical sample."""
    return _SAMPLE_RESULT.layout


# ---------------------------------------------------------------------------
# Exported constants: exact file offsets of every curated #US literal.
# ---------------------------------------------------------------------------

# These are populated from the sample's layout at module import time.  Any
# test that needs to assert a specific offset uses these named constants
# rather than hard-coded numbers.
LAYOUT = _SAMPLE_RESULT.layout

US_BASE = LAYOUT.streams["#US"].offset
US_OFFSETS: Dict[str, int] = {}

for name, info in LAYOUT.user_strings.items():
    US_OFFSETS[name] = info["offset"]

# Convenience named exports for the most important #US literals.
USER_AGENT_OFFSET = US_OFFSETS.get("user_agent")
CALLBACK_URL_OFFSET = US_OFFSETS.get("callback_url")
API_BASE_OFFSET = US_OFFSETS.get("api_base")
API_LOGIN_OFFSET = US_OFFSETS.get("api_login")
API_CHECKIN_OFFSET = US_OFFSETS.get("api_checkin")
KILLDATE_OFFSET = US_OFFSETS.get("killdate")
ENCRYPTED_EXCHANGE_CHECK_OFFSET = US_OFFSETS.get("encrypted_exchange_check")
AESPSK_ENC_KEY_OFFSET = US_OFFSETS.get("aespsk_enc_key")
AESPSK_DEC_KEY_OFFSET = US_OFFSETS.get("aespsk_dec_key")
PAYLOAD_UUID_OFFSET = US_OFFSETS.get("payload_uuid")
PIPE_NAME_OFFSET = US_OFFSETS.get("pipe_name")
COOKIE_NAME_OFFSET = US_OFFSETS.get("cookie_name")
QUERY_PARAM_OFFSET = US_OFFSETS.get("query_param")
FRAGMENT_URL_PREFIX_OFFSET = US_OFFSETS.get("fragment_url_prefix")
FRAGMENT_HOST_OFFSET = US_OFFSETS.get("fragment_host")
FRAGMENT_PORT_OFFSET = US_OFFSETS.get("fragment_port")
BANNER_OFFSET = US_OFFSETS.get("banner")
HELP_TEXT_OFFSET = US_OFFSETS.get("help_text")
ERROR_TEXT_OFFSET = US_OFFSETS.get("error_text")
SPLIT_KILL_LEFT_OFFSET = US_OFFSETS.get("split_kill_left")
SPLIT_KILL_RIGHT_OFFSET = US_OFFSETS.get("split_kill_right")
MANUFACTURER_OFFSET = US_OFFSETS.get("manufacturer")

# #Strings offsets for identity/attribute strings.
STRINGS_OFFSETS: Dict[str, int] = {text: info["offset"] for text, info in LAYOUT.strings.items()}

MODULE_NAME_OFFSET = STRINGS_OFFSETS.get(DEFAULT_MODULE_NAME)
TYPE_NAME_PROGRAM_OFFSET = STRINGS_OFFSETS.get("Program")
NAMESPACE_APOLLO_OFFSET = STRINGS_OFFSETS.get("Apollo")
USER_AGENT_FIELD_OFFSET = STRINGS_OFFSETS.get("UserAgent")
MSCORLIB_OFFSET = STRINGS_OFFSETS.get("mscorlib")
ASSEMBLY_NAME_OFFSET = STRINGS_OFFSETS.get(DEFAULT_ASSEMBLY_NAME)

# #Blob data offsets for attribute text content.
BLOB_TEXT_OFFSETS: Dict[str, int] = LAYOUT.blob_text

COMPANY_TEXT_OFFSET = BLOB_TEXT_OFFSETS.get(DEFAULT_COMPANY)
PRODUCT_TEXT_OFFSET = BLOB_TEXT_OFFSETS.get(DEFAULT_PRODUCT)
COPYRIGHT_TEXT_OFFSET = BLOB_TEXT_OFFSETS.get(DEFAULT_COPYRIGHT)
TARGET_FRAMEWORK_TEXT_OFFSET = BLOB_TEXT_OFFSETS.get(DEFAULT_TARGET_FRAMEWORK)

# GUID data offsets.
MVID_DATA_OFFSET = LAYOUT.guids.get("mvid")
MODULE_GUID_DATA_OFFSET = LAYOUT.guids.get("module_guid")

# CLI header field offsets.
CLI_OFFSET = LAYOUT.cli.get("offset")
CLI_RVA = LAYOUT.cli.get("rva")
CLI_METADATA_RVA_FIELD = LAYOUT.cli.get("metadata_rva_field")
CLI_METADATA_SIZE_FIELD = LAYOUT.cli.get("metadata_size_field")
CLI_FLAGS_FIELD = LAYOUT.cli.get("flags_field")
CLI_ENTRY_POINT_FIELD = LAYOUT.cli.get("entry_point_field")
CLI_STRONG_NAME_RVA_FIELD = LAYOUT.cli.get("strong_name_rva_field")
CLI_STRONG_NAME_SIZE_FIELD = LAYOUT.cli.get("strong_name_size_field")

# Metadata root offsets.
METADATA_ROOT_OFFSET = LAYOUT.metadata_offset
METADATA_ROOT_RVA = LAYOUT.metadata_rva
METADATA_ROOT_SIZE = LAYOUT.metadata_size

# Stream offsets within the metadata root.
STREAM_OFFSETS: Dict[str, int] = {name: info.offset for name, info in LAYOUT.streams.items()}
STREAM_RVAS: Dict[str, int] = {name: info.rva for name, info in LAYOUT.streams.items()}
STREAM_SIZES: Dict[str, int] = {name: info.size for name, info in LAYOUT.streams.items()}

# Table field offsets (for the first row of each table).
TABLE_FIELDS: Dict[str, Dict[str, int]] = {}
for name, table in LAYOUT.tables.items():
    if table.num_rows > 0:
        TABLE_FIELDS[name] = dict(table.rows[0])

# PE header fields.
TIMESTAMP_OFFSET = LAYOUT.time_stamp_offset
CHECKSUM_OFFSET = LAYOUT.checksum_offset

# Strong-name signature block offsets.
STRONG_NAME_RVA = LAYOUT.cli.get("strong_name_rva")
STRONG_NAME_SIZE = LAYOUT.cli.get("strong_name_size")
STRONG_NAME_FILE_OFFSET = None
if STRONG_NAME_RVA:
    STRONG_NAME_FILE_OFFSET = _SAMPLE_RESULT.layout.streams["#~"].offset + (
        STRONG_NAME_RVA - _SAMPLE_RESULT.layout.metadata_rva
    )


# ---------------------------------------------------------------------------
# Helper: write the sample to a temp path for integration tests.
# ---------------------------------------------------------------------------


def write_sample_to(path: Path) -> Path:
    """Write the canonical sample to `path` and return the path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_SAMPLE_RESULT.bytes)
    return path


# ---------------------------------------------------------------------------
# Public surface: the union of the three legacy fixture modules, so
# `from obfuscate.synth import *` (and the tests/fixtures re-exports) expose
# every name consumers historically imported.
# ---------------------------------------------------------------------------

__all__ = [
    # agent_code_tree
    "AgentCodeTree",
    "build_agent_code_tree",
    # pe_builder
    "PeBuilder",
    "BuildResult",
    "Layout",
    "StreamInfo",
    "TableInfo",
    "build_apollo_sample",
    "TABLE_NUMBERS",
    "TABLE_FIELDS_SCHEMA",
    "CODED_TABLES",
    "CODED_TAG_BITS",
    "DEFAULT_USER_AGENT",
    "DEFAULT_CALLBACK_URL",
    "DEFAULT_API_BASE",
    "DEFAULT_PIPE_NAME",
    "DEFAULT_BANNER",
    "DEFAULT_HELP_TEXT",
    "DEFAULT_ERROR_TEXT",
    "DEFAULT_USER_STRINGS",
    "DEFAULT_COMPANY",
    "DEFAULT_PRODUCT",
    "DEFAULT_COPYRIGHT",
    "DEFAULT_TARGET_FRAMEWORK",
    "DEFAULT_MODULE_NAME",
    "DEFAULT_ASSEMBLY_NAME",
    "DEFAULT_TIME_STAMP",
    "DEFAULT_PUBLIC_KEY",
    "SIGNATURE_BLOCK_SIZE",
    # samples
    "sample_result",
    "sample_bytes",
    "sample_layout",
    "LAYOUT",
    "US_OFFSETS",
    "USER_AGENT_OFFSET",
    "CALLBACK_URL_OFFSET",
    "API_BASE_OFFSET",
    "API_LOGIN_OFFSET",
    "API_CHECKIN_OFFSET",
    "KILLDATE_OFFSET",
    "ENCRYPTED_EXCHANGE_CHECK_OFFSET",
    "AESPSK_ENC_KEY_OFFSET",
    "AESPSK_DEC_KEY_OFFSET",
    "PAYLOAD_UUID_OFFSET",
    "PIPE_NAME_OFFSET",
    "COOKIE_NAME_OFFSET",
    "QUERY_PARAM_OFFSET",
    "FRAGMENT_URL_PREFIX_OFFSET",
    "FRAGMENT_HOST_OFFSET",
    "FRAGMENT_PORT_OFFSET",
    "BANNER_OFFSET",
    "HELP_TEXT_OFFSET",
    "ERROR_TEXT_OFFSET",
    "SPLIT_KILL_LEFT_OFFSET",
    "SPLIT_KILL_RIGHT_OFFSET",
    "MANUFACTURER_OFFSET",
    "STRINGS_OFFSETS",
    "MODULE_NAME_OFFSET",
    "TYPE_NAME_PROGRAM_OFFSET",
    "NAMESPACE_APOLLO_OFFSET",
    "USER_AGENT_FIELD_OFFSET",
    "MSCORLIB_OFFSET",
    "ASSEMBLY_NAME_OFFSET",
    "BLOB_TEXT_OFFSETS",
    "COMPANY_TEXT_OFFSET",
    "PRODUCT_TEXT_OFFSET",
    "COPYRIGHT_TEXT_OFFSET",
    "TARGET_FRAMEWORK_TEXT_OFFSET",
    "MVID_DATA_OFFSET",
    "MODULE_GUID_DATA_OFFSET",
    "CLI_OFFSET",
    "CLI_RVA",
    "CLI_METADATA_RVA_FIELD",
    "CLI_METADATA_SIZE_FIELD",
    "CLI_FLAGS_FIELD",
    "CLI_ENTRY_POINT_FIELD",
    "CLI_STRONG_NAME_RVA_FIELD",
    "CLI_STRONG_NAME_SIZE_FIELD",
    "METADATA_ROOT_OFFSET",
    "METADATA_ROOT_RVA",
    "METADATA_ROOT_SIZE",
    "STREAM_OFFSETS",
    "STREAM_RVAS",
    "STREAM_SIZES",
    "TABLE_FIELDS",
    "TIMESTAMP_OFFSET",
    "CHECKSUM_OFFSET",
    "STRONG_NAME_RVA",
    "STRONG_NAME_SIZE",
    "STRONG_NAME_FILE_OFFSET",
    "write_sample_to",
    "SAMPLE_MVID",
    "SAMPLE_MODULE_GUID",
    "SAMPLE_ASSEMBLY_VERSION",
    "SAMPLE_SIGNATURE_SEED",
]