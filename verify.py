#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted.
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""Offline, standard-library verifier for the KYOTO-RB00009915 public text package.

Usage:
  python3 package-tools/verify.py PUBLIC_PACKAGE
  python3 package-tools/verify.py --self-test
  python3 package-tools/verify.py PUBLIC_PACKAGE --self-test
  python3 package-tools/verify.py PUBLIC_PACKAGE --tei-schema tei_all.rng \
      --cff-schema cff.schema.json

Defaults: book.json, book.txt, book.tei.xml, SHA256SUMS.
Override these with --json, --txt, --tei, and --checksums (package-relative).
--allow PATH adds an intentional public file to the built-in allowlist.
--whitelist FILE supplies an exact UTF-8 JSON array or newline-delimited list
of public files; SHA256SUMS itself is automatically allowed but never hashed.
All package files, except Git's own .git metadata, must be allowlisted and
listed in SHA256SUMS. No image, PDF, archive, symlink, or binary is accepted.

Each unknown-extent object in gap, then gaps, adds one final TXT/TEI marker
"⟦gap:unknown⟧". Do not duplicate one gap in both fields. Positions count
Unicode code points from 1; no Unicode normalization is performed. TXT text
cannot contain CR/LF. XML permits only text and gap inside each ab.
An unlocated column is null (rendered as None in the TEI n locator). An
explicitly unresolved anchor has no verified reference or character position.

Optional schemas are local files. xmllint validates TEI Relax NG with --nonet;
PyYAML and jsonschema validate CFF if installed. Missing tools are reported as
not-run, never as a successful schema validation. No dependencies are installed.
JSON output goes to stdout; exit 0 means core checks passed (and any schemas
actually run passed), not that transcription accuracy was established.
"""

import argparse
import hashlib
import importlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

BOOK_ID = "KYOTO-RB00009915"
SOURCE_HASH = "bb02261b2701b001854bb052b260862c79168f1e145021645adf57addcb49bfc"
MANIFEST_URL = "https://rmda.kulib.kyoto-u.ac.jp/iiif/metadata_manifest/RB00009915/manifest.json"
PAGE_URL = "https://rmda.kulib.kyoto-u.ac.jp/iiif/RB00009915/canvas/p{}"
SCAN_COUNT = 49
FIXED_IMAGES = [{'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00001_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '388b65b58697db12aa3b865e3ca86ba7e16717f1e9ed22d11501d9bd7999eafb',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00002_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '284a268540e8d80699c58d8cd9d114cf66dfbb2d1be584b990259758aa92503c',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00003_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'dba42a20764a8036310fea1e67ec7a34dba56c9bcc2a1ed08912b2fcff16a040',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00004_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '6ba9c3ab85de43c1a58d544304609cf65112baa9a3d6227d33d1715f031a45ca',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00005_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '531114285c12c90192ee106f1616c5f3a206071077024d12699eb25cc1d7d983',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00006_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '8942477cc4511926991c6ae34df90b5d1b9036a4b9099fc728ff328bd24c52e8',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00007_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '1da796fc37f7dc8667e048e075773bf99e01e72f32389da5b5f31e7249a6b1c5',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00008_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '6e24ebd6b0ba26009760f5ff52ccffec251cec10edf326fe9c3c84d91d85ddcd',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00009_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '8746b6db8fc54b8da0f52083105d0e2f741f980d8c527362c03fcf598e4f4c31',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00010_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '7b64c936e00dc05f21842c62308414e5dbfa6db33ad9cf0e5df62c1bcaf0f2f3',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00011_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '50428f14e8ba1173477766e1a4b0d6fdf6ec657af9eda1cead869fa13b008d13',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00012_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '25f162cbc07bc9211f869211b4bac3d0147c8b0a4289d6615e000d1406059c5f',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00013_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'ae1f65360efd97cefd2f5b3c50718d2154acde81cdc7ab99b9e2491b4b44fe61',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00014_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '98d1a5b317d395ccd01c970d3d7b5d51f9b5714ce6f803996576f86bc35b77c1',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00015_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '1490348ca3afaccde03888084d7a9ab6a3f3cd0c93d54dfe4d42ba6a8f32b8e9',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00016_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '64ca7c36947d1271cb60552ae209e479f3ab9ce316731b52a6b5eaa03924b1f3',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00017_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '21ef5336f881ac8ad51a632623cbadeca00c248e3855a3a83234b1cb9f61bb3f',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00018_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '3f3072b40ee76be2a199a5a03deb4c8443145ff82bb97a18b9b62df034bd0e6b',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00019_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'cc77feec7d8296f2b7a36734c64e9632b7001c0389be951ed572b5a351eb8930',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00020_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '12b2ba6673e5f49eb6b9a505f96a08f68202dcc6ff2a9f95a221bdb88401e77c',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00021_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '5232e990ea4bc7484cd783301a168bd4abb601bbb1f0428e91161f49232391bf',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00022_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'b8cf26592c0f21315b832c6c923f573ddde4ed7a828840b7dd740942335a674d',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00023_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '474c51b677e6b8d10bffea2be01405754f03b39d4f9c20fec69ecf1a4c118d8f',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00024_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'f7ba9a62987faa465ec235c43881f0b4c2e2376c3f0db70efd9d6a5d2f2defb4',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00025_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '325208183f00e64299be101ea7284f9dc659ed3cf5e35b191fcc003a844cc166',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00026_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'abace2d9eb5c0f846b299ac26ac1a67fc0bd4228f846ca5025e4f4659515a3d6',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00027_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'a3c58fd8439fdbd6ea65417d9dd2d3cf1d04425ecbdf8a5095e97c800b8cb2f9',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00028_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '049f19c240b3c7cfe50636ebd1a0de95948760f1c452f5123a21f4be3133a6b9',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00029_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'a669d890f3a157c013245d4936fb044be08dc0c675f0eb3ce10e1e3a1039bdc3',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00030_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '96fd34d9480e26dcd564d983dc6e6b41e1089a33bccb21a57c29ea9c83917c59',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00031_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'ba9b20554975a1a41c0a65a1507ee7ec760c0a756dc3dc61f376df048cb86ad8',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00032_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '44a33a7c40db9f5a319a8b96d24f05ce9960662dc55d0a8df0761491d184876b',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00033_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '8bc847a2c40c95e74eb545b1360ce5bdbe1a9d3a3f02e8e3999b33775d308c99',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00034_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '95f994bc770fe318da86225e5014620f8d724a9d67ef8d83a00194ef1724ce00',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00035_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'c7df17e1ba2a65ad615737d9d37845b89024763e845a2a2f9a62a33f1c21277a',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00036_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '4be7cb2c6c53b0ee1ca9aa6d503d3b3ef6452a2286b39b0ec5d51572a112aa98',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00037_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'b29c2b114a522b763e9e1fba6304b9f45cced2e34d9d3c9ddd1948feb5f0a90b',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00038_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'cf930c2a2d89b9cabc9fb11e7be872e462cad27c32dc719faa81b05d59119489',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00039_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'd9fc6780765a1e7aa862ec1d77e0f122bb8498bab2ce0ffb5e0c3db1731ea271',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00040_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '619d0e236e5da4138141150c4c5758d0181d00929cf42d0ee549e697520926f3',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00041_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'afa45686ff69a0f2710b604f3b176d0ae6fda95fa47313f4ec060026b8e6ddb3',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00042_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'a2f9c406b6f2cd5180ede18be6f69f4b683f5eb3a01f00011b990d6633372f9e',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00043_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'd3e54aefee26f5562a2fecde896cc79603edbf668fdd2b264b0fcb463ef097fd',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00044_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'd117218fef61bd716f0862f8a9332657e5f3e90c5282a39e63a6a1fbe03d05f3',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00045_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'd270eaae11c876e253d8b8df42a2b2ec929bc1c44fa1b0832fc8994a580bc58a',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00046_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'db8395d3b5cab55eed57d4e6ff12e773a1b7f30464f9b435e2b02585c0b17143',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00047_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'bc7e7399b6b425aad7f4713593396a700c7ed3ebf7faab49ce331eef9714f74e',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00048_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': 'f3aaf5fe5de7222f8fe4221791ac4f01df8220815adaca15eaf906607fc5984e',
  'width': 2000,
  'height': 1335},
 {'image_uri': 'https://rmda.kulib.kyoto-u.ac.jp/iiif/3/RB00009915%2FRB00009915_00049_0.ptif/full/2000,/0/default.jpg',
  'image_sha256': '5e19cdcb5601fcdcaf57a5c72e9e527900add4bbec9ca44f404f75ac23699d87',
  'width': 2000,
  'height': 1335}]
GAP_MARKER = "⟦gap:unknown⟧"
TEI = "http://www.tei-c.org/ns/1.0"
XML_ID = "{http://www.w3.org/XML/1998/namespace}id"
DEFAULT_FILES = {
    "README.md", "CITATION.cff", "LICENSE", "LICENSE.txt", "LICENSE.md",
    "LICENSE-DATA", "LICENSE-DATA.txt", "LICENSE-CODE", "LICENSE-CODE.txt",
    "LICENSE-DOCS", "LICENSE-DOCS.txt", "NOTICE", "NOTICE.md", "AUTHORS.md",
    "CHANGELOG.md", ".gitignore", "metadata.json", "manifest.json",
    "public-files.json", "PUBLIC-FILES.txt", "rights.json",
    "LICENSES/0BSD.txt", "LICENSES/CC-BY-4.0.txt", "LICENSES/PDM-1.0.txt",
    "schema/book.schema.json", "metadata/provenance.json",
    "package-tools/verify.py", "verify.py",
}
TEXT_SUFFIXES = {".json", ".txt", ".xml", ".md", ".cff", ".py", ".rng"}
BAD_NAMES = re.compile(r"(?:^|[/_-])(?:screenshots?|prompts?|transcripts?|credentials?|secrets?)(?:[._/-]|$)", re.I)
PRIVATE_CONTENT = re.compile(
    r"/Users/[^\s/]+/|/home/[^\s/]+/|[A-Za-z]:\\Users\\|file://|"
    r"(?:^|[\s\"'])private/|<codex_delegation|<transcript_evidence|"
    r"\"(?:system_prompt|user_prompt|prompt_text)\"\s*:", re.I
)


class Invalid(Exception):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def need(condition, code, message):
    if not condition:
        raise Invalid(code, message)


def string(value, label, nonempty=True):
    need(isinstance(value, str) and (bool(value) or not nonempty), "FIELD", label + " must be a string")
    return value


def integer(value, label, minimum=1, maximum=None):
    need(type(value) is int and value >= minimum and (maximum is None or value <= maximum),
         "FIELD", label + " is outside its integer range")
    return value


def relative(value):
    string(value, "file path")
    p = PurePosixPath(value)
    need(not p.is_absolute() and value == p.as_posix() and "\\" not in value
         and all(x not in {"", ".", ".."} for x in value.split("/")),
         "PATH", "Noncanonical or unsafe package-relative path: " + value)
    return value


def utf8(path):
    try:
        return path.read_bytes().decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        detail = getattr(exc, "strerror", None) or getattr(exc, "reason", None) or type(exc).__name__
        raise Invalid("UTF8", "Cannot read UTF-8 file " + path.name + ": " + detail) from exc


def load_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "JSON", "Duplicate JSON object key: " + key)
            result[key] = value
        return result

    def constant(value):
        raise Invalid("JSON", "Nonstandard JSON numeric constant: " + value)

    try:
        return json.loads(utf8(path), object_pairs_hook=pairs, parse_constant=constant)
    except json.JSONDecodeError as exc:
        raise Invalid("JSON", str(exc)) from exc


def unknown_gaps(unit):
    primary = unit.get("gap")
    extra = unit.get("gaps", [])
    need(primary is None or isinstance(primary, dict), "GAP", "gap must be null or an object")
    need(isinstance(extra, list), "GAP", "gaps must be an array")
    result = ([] if primary is None else [primary]) + extra
    for gap in result:
        need(isinstance(gap, dict) and gap.get("extent") == "unknown", "GAP", "Only explicit unknown-extent gap objects are supported")
        string(gap.get("reason"), "gap reason")
    return result


def display_text(unit):
    return unit["text"] + GAP_MARKER * len(unknown_gaps(unit))


def validate_json(book):
    need(isinstance(book, dict), "JSON", "Book must be an object")
    need(book.get("schema_version") == "1.0" and book.get("id") == BOOK_ID, "IDENTITY", "Unexpected schema_version or book id")
    need(book.get("title") == "論語郷黨圖解", "IDENTITY", "Unexpected historical work title")
    release_date = string(book.get("date_released"), "date_released")
    need(re.fullmatch(r"\d{4}-\d{2}-\d{2}", release_date) is not None, "FIELD", "date_released must be an ISO date")
    version = string(book.get("version"), "version")
    need(not any(c in version for c in "\r\n\t"), "FIELD", "version must fit one TXT header")
    source = book.get("source")
    need(isinstance(source, dict), "SOURCE", "source must be an object")
    need(source.get("manifest_sha256") == SOURCE_HASH, "SOURCE_HASH", "Source manifest SHA-256 differs from the fixed source")
    need(source.get("scan_count") == SCAN_COUNT and type(source.get("scan_count")) is int, "SOURCE", "Expected 49 source scans")
    manifest = string(source.get("manifest_url"), "manifest_url")
    need(manifest == MANIFEST_URL, "SOURCE_MANIFEST_URL", "manifest_url differs from the fixed official source URL")
    need(source.get("catalogue_url") == "https://rmda.kulib.kyoto-u.ac.jp/item/rb00009915", "SOURCE_CATALOGUE_URL", "catalogue_url differs from the fixed holding record")
    need(source.get("doi") is None or isinstance(source.get("doi"), str), "SOURCE", "doi must be null or a string")
    pages = book.get("pages")
    need(isinstance(pages, list) and len(pages) == SCAN_COUNT, "PAGE_COVERAGE", "pages must cover all 49 scans")
    page_urls = {}
    for expected, page in enumerate(pages, 1):
        need(isinstance(page, dict) and type(page.get("scan_index")) is int and page.get("scan_index") == expected,
             "PAGE_COVERAGE", "pages must be ordered scans 1 through 49 without omissions")
        url = string(page.get("source_url"), "source_url")
        need(url == PAGE_URL.format(expected), "SOURCE_PAGE_URL", "source_url differs from the fixed official URL for scan " + str(expected))
        need(page.get("coverage_state") in ("initial-attempted", "independently-reviewed"),
             "PAGE_COVERAGE", "Unrecognized coverage_state")
        fixed = FIXED_IMAGES[expected - 1]
        need(page.get("image_url") == fixed["image_uri"], "SOURCE_IMAGE_URL", "Image URL differs from the fixed public 2000px source")
        need(page.get("image_sha256") == fixed["image_sha256"], "SOURCE_IMAGE_HASH", "Source image SHA-256 differs from the fixed source")
        need(type(page.get("width")) is int and type(page.get("height")) is int
             and page["width"] == fixed["width"] and page["height"] == fixed["height"],
             "SOURCE_IMAGE_SIZE", "Decoded source-image dimensions differ")
        for field in ("figures", "excluded_nonoriginal_regions", "custodial_metadata"):
            if field in page:
                need(isinstance(page[field], list) and all(isinstance(item, dict) for item in page[field]),
                     "PAGE_METADATA", field + " must be an array of objects")
        if "new_unique_book_surfaces" in page:
            need(type(page["new_unique_book_surfaces"]) is int and 0 <= page["new_unique_book_surfaces"] <= 2,
                 "PAGE_METADATA", "Invalid new unique surface count")
        for field in ("duplicate_of", "duplicate_of_scan_index"):
            if field in page:
                need(expected == 48 and page[field] == 47, "PAGE_METADATA", "Unexpected duplicate capture mapping")
        page_urls[expected] = url
    units = book.get("units")
    need(isinstance(units, list) and bool(units), "UNITS", "units must be a nonempty array")
    ids = {}
    last_scan = 0
    for unit in units:
        need(isinstance(unit, dict), "UNIT", "Each unit must be an object")
        uid = string(unit.get("id"), "unit id")
        need(not any(c.isspace() or c in "[]" for c in uid), "ID", "Unit id cannot contain whitespace or TXT brackets")
        need(uid not in ids, "DUPLICATE_ID", "Duplicate unit id: " + uid)
        ids[uid] = unit
        scan = integer(unit.get("scan_index"), "scan_index", maximum=SCAN_COUNT)
        need(scan >= last_scan, "UNIT_ORDER", "Units must follow source scan order")
        last_scan = scan
        side = string(unit.get("side"), "side")
        need(not any(c.isspace() or c == ":" for c in side), "FIELD", "side cannot contain whitespace or colon")
        column = unit.get("column_index")
        need("column_index" in unit and (column is None or (type(column) is int and column >= 1)),
             "COLUMN_INDEX", "column_index must be null or a positive integer")
        string(unit.get("role"), "role")
        string(unit.get("layer"), "layer")
        text = string(unit.get("text"), "text", nonempty=False)
        need("\r" not in text and "\n" not in text, "TXT_TEXT", "Unit text must fit one TXT line")
        need(GAP_MARKER not in text, "GAP", "The reserved gap marker cannot occur literally in source text")
        uncertainties = unit.get("uncertainties")
        need(isinstance(uncertainties, list), "UNCERTAINTY", "uncertainties must be an array")
        covered = set()
        for uncertainty in uncertainties:
            need(isinstance(uncertainty, dict), "UNCERTAINTY", "Uncertainty must be an object")
            pos = uncertainty.get("character_index")
            need(type(pos) is int and 1 <= pos <= len(text), "UNCERTAINTY_INDEX", "Uncertainty index outside text in " + uid)
            covered.add(pos)
            candidates = uncertainty.get("candidates")
            need(isinstance(candidates, list) and all(isinstance(c, str) for c in candidates), "UNCERTAINTY", "Candidates must be an array of strings")
            string(uncertainty.get("reason"), "uncertainty reason")
        need(all(i in covered for i, c in enumerate(text, 1) if c == "□"), "UNCERTAINTY_COVERAGE", "Unrecorded □ in " + uid)
        unknown_gaps(unit)
        need(isinstance(unit.get("events", []), list), "EVENTS", "events must be an array")
        bbox = unit.get("bbox")
        need(bbox is None or (isinstance(bbox, list) and len(bbox) == 4
             and all(type(v) in (int, float) for v in bbox)
             and 0 <= bbox[0] < bbox[2] <= FIXED_IMAGES[scan - 1]["width"]
             and 0 <= bbox[1] < bbox[3] <= FIXED_IMAGES[scan - 1]["height"]),
             "BBOX", "bbox must be null or valid xyxy in the actual fixed image")
    for unit in units:
        anchor = unit.get("anchor")
        need(anchor is None or isinstance(anchor, dict), "ANCHOR", "anchor must be null or an object")
        if anchor is not None:
            if anchor.get("unit_id") is None:
                original = anchor.get("unresolved_original_unit_id")
                need(anchor.get("status") == "unresolved source-column mapping"
                     and isinstance(original, str) and bool(original)
                     and anchor.get("character_index") is None,
                     "ANCHOR_UNRESOLVED", "Unresolved anchor requires the explicit status, original id, and no character position")
                continue
            target = ids.get(string(anchor.get("unit_id"), "anchor unit_id"))
            need(target is not None and target is not unit, "ANCHOR_REF", "Missing or self-referential anchor in " + unit["id"])
            pos = anchor.get("character_index")
            need(pos is None or (type(pos) is int and 1 <= pos <= len(target["text"])),
                 "ANCHOR_INDEX", "Anchor character index outside target text")
            string(anchor.get("status"), "anchor status")
    return page_urls, ids


def validate_txt(book, content):
    lines = content.split("\n")
    if lines[-1] == "":
        lines.pop()
    need(lines and lines[0] == "# " + BOOK_ID + " " + book["version"], "TXT_HEADER", "TXT header differs from JSON")
    need(len(lines) - 1 == len(book["units"]), "TXT_UNIT_COUNT", "TXT and JSON unit counts differ")
    for line, unit in zip(lines[1:], book["units"]):
        uid, separator, text = line.partition("\t")
        need(separator and uid == "[" + unit["id"] + "]", "TXT_ORDER", "TXT unit id/order differs from JSON")
        need(text == display_text(unit), "TXT_TEXT_MISMATCH", "TXT text/gap marker differs in " + unit["id"])


def safe_xml(content):
    need(not re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, re.I), "XML_UNSAFE", "DOCTYPE and entity declarations are forbidden")
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise Invalid("XML", str(exc)) from exc
    need(root.tag == "{" + TEI + "}TEI", "TEI_NAMESPACE", "Expected a TEI P5 namespaced root")
    return root


def ab_text(ab):
    text = ab.text or ""
    need("□" not in text and GAP_MARKER not in text, "TEI_GAP", "Missing text must use gap elements, not literal placeholders")
    for child in ab:
        need(child.tag == "{" + TEI + "}gap", "TEI_CONTENT", "Only gap elements may occur inside ab")
        need(child.get("reason") == "illegible" and not len(child) and not child.text,
             "TEI_GAP", "Unexpected gap content or reason")
        if child.get("extent") == "unknown":
            need(child.get("quantity") is None and child.get("unit") is None, "TEI_GAP", "Unknown gap cannot also declare quantity/unit")
            text += GAP_MARKER
        else:
            need(child.get("extent") is None and child.get("quantity") == "1" and child.get("unit") == "character",
                 "TEI_GAP", "Known □ must be a one-character gap")
            text += "□"
        tail = child.tail or ""
        need("□" not in tail and GAP_MARKER not in tail, "TEI_GAP", "Missing text must use gap elements, not literal placeholders")
        text += tail
    return text


def validate_tei(book, content, page_urls):
    root = safe_xml(content)
    ns = {"t": TEI}
    def node(path):
        item = root.find(path, ns)
        need(item is not None, "TEI_METADATA", "Missing TEI header/source element: " + path)
        return item
    need(node("t:teiHeader/t:fileDesc/t:titleStmt/t:title").text == book.get("title") + "：分層影像轉錄 " + book["version"],
         "TEI_METADATA", "TEI title/version differs from fixed JSON")
    need(node("t:teiHeader/t:fileDesc/t:titleStmt/t:author").text == "宮田華龍（五渓）", "TEI_METADATA", "Historical author differs")
    need(node("t:teiHeader/t:fileDesc/t:editionStmt/t:edition").text == book["version"], "TEI_METADATA", "TEI edition differs from JSON")
    date = node("t:teiHeader/t:fileDesc/t:publicationStmt/t:date")
    need(date.text == book.get("date_released") and date.get("when") == book.get("date_released"), "TEI_METADATA", "TEI release date differs from JSON")
    need(node("t:teiHeader/t:fileDesc/t:sourceDesc/t:bibl/t:ref").get("target") == "https://rmda.kulib.kyoto-u.ac.jp/item/rb00009915",
         "TEI_METADATA", "TEI source reference differs from fixed catalogue")
    need(node("t:teiHeader/t:fileDesc/t:sourceDesc/t:bibl/t:idno").text == SOURCE_HASH, "TEI_METADATA", "TEI source manifest fingerprint differs")
    xml_ids = [e.get(XML_ID) for e in root.iter() if e.get(XML_ID) is not None]
    need(len(xml_ids) == len(set(xml_ids)), "TEI_DUPLICATE_ID", "Duplicate XML id")
    bodies = list(root.iter("{" + TEI + "}body"))
    need(len(bodies) == 1, "TEI_BODY", "Expected exactly one TEI body")
    seen_pages, seen_units = [], []
    current_scan = None

    def walk(container):
        nonlocal current_scan
        need(not (container.text or "").strip(), "TEI_CONTENT", "Unmapped text outside ab")
        for child in container:
            if child.tag == "{" + TEI + "}div":
                walk(child)
            elif child.tag == "{" + TEI + "}pb":
                number = str(len(seen_pages) + 1)
                need(child.get("n") == number and len(seen_pages) < SCAN_COUNT,
                     "TEI_PAGE_ORDER", "TEI pb sequence must cover scans 1 through 49")
                current_scan = int(number)
                need(child.get("facs") == page_urls[current_scan], "TEI_SOURCE", "TEI pb source_url differs from JSON")
                need(not len(child) and not (child.text or "").strip(), "TEI_CONTENT", "pb must be empty")
                seen_pages.append(current_scan)
            elif child.tag == "{" + TEI + "}ab":
                index = len(seen_units)
                need(index < len(book["units"]), "TEI_UNIT_COUNT", "TEI has an extra ab")
                unit = book["units"][index]
                need(current_scan == unit["scan_index"], "TEI_PAGE_ORDER", "ab must follow the pb for its source scan")
                need(child.get(XML_ID) == unit["id"], "TEI_UNIT_ORDER", "TEI unit id/order differs from JSON")
                need(child.get("type") == unit["layer"], "TEI_LAYER", "TEI ab type differs from JSON layer")
                need(child.get("n") == "{}:{}:{}".format(unit["scan_index"], unit["side"], unit["column_index"]),
                     "TEI_LOCATOR", "TEI ab source locator differs from JSON")
                need(ab_text(child) == display_text(unit), "TEI_TEXT_MISMATCH", "TEI text/gaps differ in " + unit["id"])
                seen_units.append(unit["id"])
            else:
                raise Invalid("TEI_CONTENT", "Unsupported body element: " + child.tag)
            need(not (child.tail or "").strip(), "TEI_CONTENT", "Unmapped text between source units")

    walk(bodies[0])
    need(seen_pages == list(range(1, SCAN_COUNT + 1)), "TEI_PAGE_COVERAGE", "TEI lacks a source page pb")
    need(len(seen_units) == len(book["units"]), "TEI_UNIT_COUNT", "TEI and JSON unit counts differ")
    need(len(list(root.iter("{" + TEI + "}ab"))) == len(seen_units), "TEI_CONTENT", "ab outside the source body")


def declared_whitelist(path):
    content = utf8(path)
    if path.suffix.lower() == ".json":
        try:
            values = json.loads(content)
        except json.JSONDecodeError as exc:
            raise Invalid("WHITELIST", str(exc)) from exc
        need(isinstance(values, list), "WHITELIST", "Whitelist JSON must be an array")
    else:
        values = [s for s in content.split("\n") if s and not s.startswith("#")]
    result = [relative(s) for s in values]
    need(len(result) == len(set(result)), "WHITELIST", "Duplicate whitelist entry")
    return set(result)


def package_files(root):
    result = set()
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        if rel == ".git" or rel.startswith(".git/"):
            continue
        need(not path.is_symlink(), "SYMLINK", "Symlink in public package: " + rel)
        if path.is_file():
            result.add(relative(rel))
    return result


def verify_files(root, names, allow, whitelist=None):
    manifest_name = names["checksums"]
    actual = package_files(root)
    required = {names[k] for k in ("json", "txt", "tei", "checksums")}
    need(required <= actual, "MISSING_FILE", "Missing required package files: " + ", ".join(sorted(required - actual)))
    if whitelist is not None:
        allowed = declared_whitelist(whitelist) | {manifest_name}
        need(actual == allowed, "WHITELIST", "Actual files and explicit whitelist differ: " + ", ".join(sorted(actual ^ allowed)))
    else:
        allowed = DEFAULT_FILES | required | set(allow)
        need(actual <= allowed, "WHITELIST", "File is not allowlisted: " + ", ".join(sorted(actual - allowed)))
    for rel in sorted(actual):
        path = root / rel
        need(not BAD_NAMES.search(rel) and not any(s.startswith(".") for s in PurePosixPath(rel).parts if s != ".gitignore"),
             "PUBLIC_CONTENT", "Disallowed artifact name: " + rel)
        need(not set(PurePosixPath(rel).parts) & {"private", "work", "blind"},
             "PUBLIC_CONTENT", "Private workspace path is forbidden: " + rel)
        need(path.suffix.lower() in TEXT_SUFFIXES or path.name in {"LICENSE", "LICENSE-CODE", "LICENSE-DATA", "LICENSE-DOCS", "NOTICE", "SHA256SUMS", ".gitignore"}
             or rel == manifest_name, "PUBLIC_CONTENT", "Non-text artifact type is forbidden: " + rel)
        content = utf8(path)
        # This script necessarily contains the rejection patterns themselves.
        if path.name != "verify.py":
            need(not PRIVATE_CONTENT.search(content), "PUBLIC_CONTENT", "Possible private path or prompt payload in " + rel)
    checksums = {}
    for line in utf8(root / manifest_name).split("\n"):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        need(match is not None, "CHECKSUM_FORMAT", "Invalid SHA256SUMS line")
        digest, rel = match.groups()
        rel = relative(rel)
        need(rel != manifest_name, "CHECKSUM_SELF", "SHA256SUMS must not hash itself")
        need(rel not in checksums, "CHECKSUM_DUPLICATE", "Duplicate checksum entry: " + rel)
        checksums[rel] = digest.lower()
    need(set(checksums) == actual - {manifest_name}, "CHECKSUM_COVERAGE", "SHA256SUMS must cover every public file except itself")
    for rel, expected in checksums.items():
        need(hashlib.sha256((root / rel).read_bytes()).hexdigest() == expected, "CHECKSUM_HASH", "SHA-256 mismatch: " + rel)
    return len(actual), len(checksums)


def verify_core(root, names, allow=(), whitelist=None):
    files, hashes = verify_files(root, names, allow, whitelist)
    book = load_json(root / names["json"])
    page_urls, _ = validate_json(book)
    validate_txt(book, utf8(root / names["txt"]))
    validate_tei(book, utf8(root / names["tei"]), page_urls)
    anchors = [u["anchor"] for u in book["units"] if u.get("anchor") is not None]
    return {"status": "passed", "scans": len(book["pages"]), "units": len(book["units"]),
            "public_files": files, "verified_hashes": hashes,
            "anchor_checks": {"existing_target_references": sum(a.get("unit_id") is not None for a in anchors),
                              "explicitly_unresolved_unverified": sum(a.get("unit_id") is None for a in anchors)},
            "checks": ["JSON identity, fixed source hash and 49-frame coverage", "unique unit ids and scan order",
                       "Unicode code-point uncertainty indexes; resolved anchor reference/index integrity",
                       "explicitly unresolved anchors retained without reference/index claims", "all □ have uncertainty records",
                       "exact JSON/TXT/TEI text, gaps, unit order and page references",
                       "DOCTYPE/entity rejection before XML parsing", "public allowlist and SHA256SUMS closure"],
            "limitations": ["No character accuracy or independent-review claim is verified.",
                            "Page figures and excluded_nonoriginal_regions are JSON metadata; only their array/object shape is checked, not diagram completeness, label references, coordinates or exclusion accuracy. They are not serialized into TXT/TEI.",
                            "The artifact/privacy screen detects specified file types, names and literal patterns; it is not a human content review."]}


def optional_schemas(root, names, tei_schema=None, cff_schema=None, cff_name="CITATION.cff"):
    results = []
    if tei_schema is None:
        results.append({"schema": "TEI Relax NG", "status": "not-run", "reason": "No fixed local TEI schema supplied"})
    if cff_schema is None:
        results.append({"schema": "CFF", "status": "not-run", "reason": "No fixed local CFF schema supplied"})
    if tei_schema is not None:
        exe = shutil.which("xmllint")
        if not exe or not tei_schema.is_file():
            results.append({"schema": "TEI Relax NG", "status": "not-run", "reason": "xmllint or the local schema file is unavailable"})
        else:
            run = subprocess.run([exe, "--nonet", "--noout", "--relaxng", str(tei_schema.resolve()), str(root / names["tei"])],
                                 capture_output=True, text=True, timeout=60)
            results.append({"schema": "TEI Relax NG", "status": "passed" if run.returncode == 0 else "failed",
                            "schema_sha256": hashlib.sha256(tei_schema.read_bytes()).hexdigest(),
                            "diagnostic": (run.stderr or run.stdout).strip().replace(str(tei_schema.resolve()), "SCHEMA").replace(str(root), "PACKAGE")})
    if cff_schema is not None:
        try:
            yaml = importlib.import_module("yaml")
            jsonschema = importlib.import_module("jsonschema")
        except ImportError:
            results.append({"schema": "CFF", "status": "not-run", "reason": "PyYAML and/or jsonschema is unavailable"})
        else:
            if not cff_schema.is_file():
                results.append({"schema": "CFF", "status": "not-run", "reason": "The local CFF schema file is unavailable"})
            else:
                try:
                    schema = load_json(cff_schema)

                    def local_refs(value):
                        if isinstance(value, dict):
                            for k, v in value.items():
                                if k in {"$ref", "$dynamicRef", "$recursiveRef"}:
                                    need(isinstance(v, str) and v.startswith("#"), "SCHEMA_OFFLINE", "External CFF schema references are unavailable offline")
                                local_refs(v)
                        elif isinstance(value, list):
                            for v in value:
                                local_refs(v)

                    local_refs(schema)
                    validator = jsonschema.validators.validator_for(schema)
                    validator.check_schema(schema)
                    class NoDatesSafeLoader(yaml.SafeLoader):
                        pass
                    NoDatesSafeLoader.yaml_implicit_resolvers = {
                        key: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:timestamp"]
                        for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
                    }
                    validator(schema).validate(yaml.load(utf8(root / cff_name), Loader=NoDatesSafeLoader))
                    results.append({"schema": "CFF", "status": "passed", "schema_sha256": hashlib.sha256(cff_schema.read_bytes()).hexdigest()})
                except Invalid as exc:
                    results.append({"schema": "CFF", "status": "not-run" if exc.code == "SCHEMA_OFFLINE" else "failed", "reason": str(exc)})
                except Exception as exc:
                    results.append({"schema": "CFF", "status": "failed", "reason": str(exc)})
    return results


def self_test():
    names = {"json": "data/book.json", "txt": "data/book.txt", "tei": "data/book.tei.xml", "checksums": "SHA256SUMS"}
    sample = {"schema_version": "1.0", "id": BOOK_ID, "title": "論語郷黨圖解", "version": "test-1", "date_released": "2026-10-24", "source": {
        "manifest_sha256": SOURCE_HASH, "scan_count": SCAN_COUNT,
        "manifest_url": MANIFEST_URL, "catalogue_url": "https://rmda.kulib.kyoto-u.ac.jp/item/rb00009915", "doi": None},
        "pages": [{"scan_index": n, "source_url": PAGE_URL.format(n), "coverage_state": "initial-attempted", "image_url": FIXED_IMAGES[n - 1]["image_uri"], "image_sha256": FIXED_IMAGES[n - 1]["image_sha256"], "width": FIXED_IMAGES[n - 1]["width"], "height": FIXED_IMAGES[n - 1]["height"]} for n in range(1, SCAN_COUNT + 1)],
        "units": [{"id": "test-a", "scan_index": 1, "side": "right", "column_index": 1, "role": "poem", "layer": "main",
                   "text": "𠮷□e\u0301<&>", "uncertainties": [{"character_index": 2, "candidates": [], "reason": "Test uncertainty"}],
                   "gap": None, "gaps": [], "anchor": None, "events": [], "bbox": None},
                  {"id": "test-b", "scan_index": 1, "side": "right", "column_index": 1, "role": "annotation", "layer": "annotation",
                   "text": "", "uncertainties": [], "gap": {"extent": "unknown", "reason": "Test unknown extent"}, "gaps": [],
                   "anchor": {"unit_id": "test-a", "character_index": 1, "status": "located"}, "events": [], "bbox": None},
                  {"id": "test-c", "scan_index": 1, "side": "left", "column_index": None, "role": "seal", "layer": "seal",
                   "text": "", "uncertainties": [], "gap": None, "gaps": [],
                   "anchor": {"unit_id": None, "character_index": None, "status": "unresolved source-column mapping",
                              "unresolved_original_unit_id": "source-column-unlocated"}, "events": [], "bbox": None}]}
    sample["pages"][0].update(
        figures=[{"id": "synthetic-figure", "description": "Synthetic figure metadata only", "label_unit_ids": ["test-a"]}],
        excluded_nonoriginal_regions=[{"bbox": [1, 2, 3, 4], "reason": "Synthetic exclusion metadata only"}])

    def write_fixture(root):
        (root / "data").mkdir()
        (root / names["json"]).write_text(json.dumps(sample, ensure_ascii=False), encoding="utf-8")
        (root / names["txt"]).write_text("# " + BOOK_ID + " test-1\n" + "\n".join("[" + u["id"] + "]\t" + display_text(u) for u in sample["units"]) + "\n", encoding="utf-8")
        ET.register_namespace("", TEI)
        tei = ET.Element("{" + TEI + "}TEI")
        fd = ET.SubElement(ET.SubElement(tei, "{" + TEI + "}teiHeader"), "{" + TEI + "}fileDesc")
        titles = ET.SubElement(fd, "{" + TEI + "}titleStmt")
        ET.SubElement(titles, "{" + TEI + "}title").text = sample["title"] + "：分層影像轉錄 " + sample["version"]
        ET.SubElement(titles, "{" + TEI + "}author").text = "宮田華龍（五渓）"
        ET.SubElement(ET.SubElement(fd, "{" + TEI + "}editionStmt"), "{" + TEI + "}edition").text = sample["version"]
        publication = ET.SubElement(fd, "{" + TEI + "}publicationStmt")
        ET.SubElement(publication, "{" + TEI + "}date", {"when": sample["date_released"]}).text = sample["date_released"]
        bibl = ET.SubElement(ET.SubElement(fd, "{" + TEI + "}sourceDesc"), "{" + TEI + "}bibl")
        ET.SubElement(bibl, "{" + TEI + "}ref", {"target": "https://rmda.kulib.kyoto-u.ac.jp/item/rb00009915"})
        ET.SubElement(bibl, "{" + TEI + "}idno").text = SOURCE_HASH
        body = ET.SubElement(ET.SubElement(tei, "{" + TEI + "}text"), "{" + TEI + "}body")
        for page in sample["pages"]:
            ET.SubElement(body, "{" + TEI + "}pb", {"n": str(page["scan_index"]), "facs": page["source_url"]})
            for unit in sample["units"]:
                if unit["scan_index"] != page["scan_index"]:
                    continue
                ab = ET.SubElement(body, "{" + TEI + "}ab", {XML_ID: unit["id"], "type": unit["layer"],
                                   "n": "{}:{}:{}".format(unit["scan_index"], unit["side"], unit["column_index"])})
                before, *after = unit["text"].split("□")
                ab.text = before
                for tail in after:
                    ET.SubElement(ab, "{" + TEI + "}gap", {"reason": "illegible", "quantity": "1", "unit": "character"}).tail = tail
                for _ in unknown_gaps(unit):
                    ET.SubElement(ab, "{" + TEI + "}gap", {"reason": "illegible", "extent": "unknown"})
        (root / names["tei"]).write_bytes(ET.tostring(tei, encoding="utf-8", xml_declaration=True))
        (root / "README.md").write_text("Synthetic verification fixture.\n", encoding="utf-8")

    def sums(root):
        (root / "SHA256SUMS").write_text("".join(hashlib.sha256((root / p).read_bytes()).hexdigest() + "  " + p + "\n"
                                               for p in sorted(package_files(root) - {"SHA256SUMS"})), encoding="utf-8")

    def edit_json(root, mutate):
        book = load_json(root / names["json"])
        mutate(book)
        (root / names["json"]).write_text(json.dumps(book, ensure_ascii=False), encoding="utf-8")

    def xxe(root):
        xml_path = root / names["tei"]
        text = utf8(xml_path)
        start = text.find("?>") + 2
        xml_path.write_text(text[:start] + '\n<!DOCTYPE TEI [<!ENTITY probe SYSTEM "https://example.invalid/no-request">]>' + text[start:], encoding="utf-8")

    def change_edition(root):
        path = root / names["tei"]
        original = utf8(path)
        changed = original.replace("<edition>test-1</edition>", "<edition>wrong-edition</edition>")
        need(changed != original, "SELF_TEST", "Could not locate synthetic TEI edition")
        path.write_text(changed, encoding="utf-8")

    tests = [
        ("change-character", "TXT_TEXT_MISMATCH", lambda r: edit_json(r, lambda b: b["units"][0].update(text="字" + b["units"][0]["text"][1:]))),
        ("drop-unit", "TXT_UNIT_COUNT", lambda r: edit_json(r, lambda b: b["units"].pop())),
        ("swap-unit", "TXT_ORDER", lambda r: edit_json(r, lambda b: b["units"].reverse())),
        ("source-hash", "SOURCE_HASH", lambda r: edit_json(r, lambda b: b["source"].update(manifest_sha256="0" * 64))),
        ("manifest-url", "SOURCE_MANIFEST_URL", lambda r: edit_json(r, lambda b: b["source"].update(manifest_url="https://example.invalid/2538957"))),
        ("catalogue-url", "SOURCE_CATALOGUE_URL", lambda r: edit_json(r, lambda b: b["source"].update(catalogue_url="https://example.invalid/incorrect-source"))),
        ("source-page-url", "SOURCE_PAGE_URL", lambda r: edit_json(r, lambda b: b["pages"][0].update(source_url=PAGE_URL.format(2)))),
        ("source-image-hash", "SOURCE_IMAGE_HASH", lambda r: edit_json(r, lambda b: b["pages"][0].update(image_sha256="0" * 64))),
        ("source-image-size", "SOURCE_IMAGE_SIZE", lambda r: edit_json(r, lambda b: b["pages"][0].update(width=6016))),
        ("figures-not-array", "PAGE_METADATA", lambda r: edit_json(r, lambda b: b["pages"][0].update(figures={}))),
        ("figure-not-object", "PAGE_METADATA", lambda r: edit_json(r, lambda b: b["pages"][0].update(figures=["invalid"]))),
        ("exclusions-not-array", "PAGE_METADATA", lambda r: edit_json(r, lambda b: b["pages"][0].update(excluded_nonoriginal_regions={}))),
        ("exclusion-not-object", "PAGE_METADATA", lambda r: edit_json(r, lambda b: b["pages"][0].update(excluded_nonoriginal_regions=["invalid"]))),
        ("invented-zero-column", "COLUMN_INDEX", lambda r: edit_json(r, lambda b: b["units"][2].update(column_index=0))),
        ("unresolved-anchor-position", "ANCHOR_UNRESOLVED", lambda r: edit_json(r, lambda b: b["units"][2]["anchor"].update(character_index=1))),
        ("unresolved-anchor-status", "ANCHOR_UNRESOLVED", lambda r: edit_json(r, lambda b: b["units"][2]["anchor"].update(status="located"))),
        ("unresolved-anchor-origin", "ANCHOR_UNRESOLVED", lambda r: edit_json(r, lambda b: b["units"][2]["anchor"].pop("unresolved_original_unit_id"))),
        ("missing-normal-anchor", "ANCHOR_REF", lambda r: edit_json(r, lambda b: b["units"][1]["anchor"].update(unit_id="missing"))),
        ("normal-anchor-position", "ANCHOR_INDEX", lambda r: edit_json(r, lambda b: b["units"][1]["anchor"].update(character_index=999))),
        ("uncertainty-index", "UNCERTAINTY_INDEX", lambda r: edit_json(r, lambda b: b["units"][0]["uncertainties"][0].update(character_index=0))),
        ("duplicate-id", "DUPLICATE_ID", lambda r: edit_json(r, lambda b: b["units"][1].update(id=b["units"][0]["id"]))),
        ("tei-header-edition", "TEI_METADATA", change_edition),
        ("XXE", "XML_UNSAFE", xxe),
    ]
    outcomes = []
    with tempfile.TemporaryDirectory(prefix="kyoto-rb00009915-verify-") as temporary:
        base = Path(temporary) / "valid"
        base.mkdir()
        write_fixture(base)
        sums(base)
        positive = verify_core(base, names)
        need(positive["anchor_checks"] == {"existing_target_references": 1, "explicitly_unresolved_unverified": 1},
             "SELF_TEST", "Unresolved anchor must remain explicitly unverified in the report")
        for name, expected, mutate in tests:
            trial = Path(temporary) / name
            shutil.copytree(base, trial)
            mutate(trial)
            sums(trial)  # Each mutation must fail its semantic check, not stale hashes.
            try:
                verify_core(trial, names)
            except Invalid as exc:
                need(exc.code == expected, "SELF_TEST", name + " failed the wrong check: " + exc.code)
                outcomes.append({"case": name, "status": "rejected", "check": exc.code})
            else:
                raise Invalid("SELF_TEST", "Negative test was accepted: " + name)
    return {"status": "passed", "positive": "non-BMP, decomposed Unicode, XML reserved characters, □, empty text, unknown gap, null column, explicitly unresolved anchor", "negative_tests": outcomes}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", nargs="?", type=Path, help="Public package directory (defaults to current directory unless only --self-test)")
    parser.add_argument("--json", default="book.json")
    parser.add_argument("--txt", default="book.txt")
    parser.add_argument("--tei", default="book.tei.xml")
    parser.add_argument("--checksums", default="SHA256SUMS")
    parser.add_argument("--allow", action="append", default=[], help="Additional intentional public file; repeatable")
    parser.add_argument("--whitelist", type=Path, help="Exact public-file list; JSON array or one path per line")
    parser.add_argument("--tei-schema", type=Path, help="Local official TEI Relax NG schema")
    parser.add_argument("--cff-schema", type=Path, help="Local official CFF JSON schema")
    parser.add_argument("--cff", default="CITATION.cff")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    report = {"verifier": BOOK_ID, "status": "passed"}
    try:
        if args.self_test:
            report["self_test"] = self_test()
        if args.root is not None or not args.self_test:
            root = (args.root or Path.cwd()).resolve()
            need(root.is_dir(), "ROOT", "Public package directory does not exist")
            names = {k: relative(getattr(args, k)) for k in ("json", "txt", "tei", "checksums")}
            allow = [relative(p) for p in args.allow]
            report["core"] = verify_core(root, names, allow, args.whitelist)
            report["optional_schemas"] = optional_schemas(root, names, args.tei_schema, args.cff_schema, relative(args.cff))
            if any(r["status"] == "failed" for r in report["optional_schemas"]):
                report["status"] = "failed"
    except Invalid as exc:
        report.update(status="failed", error={"check": exc.code, "message": str(exc)})
    except subprocess.TimeoutExpired:
        report.update(status="failed", error={"check": "EXECUTION", "message": "Optional schema validation timed out"})
    except (OSError, ValueError) as exc:
        report.update(status="failed", error={"check": "EXECUTION", "message": getattr(exc, "strerror", None) or type(exc).__name__})
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
