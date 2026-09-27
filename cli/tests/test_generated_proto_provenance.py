# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The committed protobuf stubs must be reproducible by one `make proto` run."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"

# Every stub `make proto` writes and `make proto-check` diffs.
STUBS = (
    ROOT / "proto/defenseclaw/secureclient/v1/secureclient.pb.go",
    ROOT / "proto/defenseclaw/secureclient/v1/secureclient_grpc.pb.go",
    ROOT / "internal/guardrail/semanticpb/facts.pb.go",
)

# protoc-gen-go writes "// \tprotoc        vX.Y.Z" and protoc-gen-go-grpc
# writes "// - protoc             vX.Y.Z"; both take the version from the
# same CodeGeneratorRequest.
HEADER = re.compile(r"^//\s+(?:-\s+)?protoc\s+(v\S+)\s*$", re.MULTILINE)


def _makefile_variable(name: str) -> str:
    match = re.search(
        rf"^{name}\s*:=\s*(\S+)\s*$",
        MAKEFILE.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert match, f"Makefile does not define {name}"
    return match.group(1)


def test_committed_stubs_share_the_pinned_protoc_version() -> None:
    pinned = _makefile_variable("PROTOC_VERSION")
    versions = {}
    for stub in STUBS:
        headers = HEADER.findall(stub.read_text(encoding="utf-8"))
        assert len(headers) == 1, f"{stub.relative_to(ROOT)}: {headers}"
        versions[str(stub.relative_to(ROOT))] = headers[0]
    assert len(set(versions.values())) == 1, versions
    # protoc 29.3 reports itself to plugins as 5.29.3, so compare the
    # minor.patch suffix with the Makefile pin.
    (recorded,) = set(versions.values())
    assert recorded.endswith("." + pinned), (recorded, pinned)


def test_proto_target_refuses_an_unpinned_protoc() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    recipe = re.search(r"^proto: proto-tools\n((?:\t.*\n)+)", text, re.MULTILINE)
    assert recipe, "Makefile has no proto recipe"
    assert '"libprotoc $(PROTOC_VERSION)"' in recipe.group(1)
