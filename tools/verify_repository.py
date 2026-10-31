#!/usr/bin/env python3
from __future__ import annotations
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = json.loads((ROOT / "VERSION_INDEX.json").read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

errors: list[str] = []
for entry in INDEX["versions"]:
    version = entry["version"]
    base = ROOT / entry["path"]
    if not base.is_dir():
        errors.append(f"{version}: missing directory {base}")
        continue
    version_file = base / "VERSION"
    if not version_file.is_file():
        errors.append(f"{version}: missing VERSION file")
    else:
        actual = version_file.read_text(encoding="utf-8").strip()
        if actual not in {version, version.removeprefix("v")}:
            errors.append(f"{version}: VERSION contains {actual!r}")

    checks = [
        (entry["source_archive"]["path"], entry["source_archive"]["sha256"]),
        (entry["wheel"]["path"], entry["wheel"]["sha256"]),
        (f"{entry['path']}/release/XAVI_DUO_Encryption_{version}_2026-10-30.RELEASE.json", entry["release_manifest_sha256"]),
        (f"{entry['path']}/release/XAVI_DUO_Encryption_{version}_2026-10-30.RELEASE-PROOF.json", entry["release_proof_sha256"]),
        (f"{entry['path']}/release/XAVI_DUO_Encryption_{version}_2026-10-30.ARTIFACTS.sha256", entry["artifact_list_sha256"]),
        (f"{entry['path']}/release/XAVI_DUO_Encryption_{version}_2026-10-30.SIGNING-REQUEST.json", entry["signing_request_sha256"]),
        (f"{entry['path']}/release/XAVI_DUO_Encryption_{version}_2026-10-30.CUSTODY-DISCOVERY.json", entry["custody_discovery_sha256"]),
    ]
    for rel, expected in checks:
        path = ROOT / rel
        if not path.is_file():
            errors.append(f"{version}: missing {rel}")
            continue
        actual = sha256(path)
        if actual != expected:
            errors.append(f"{version}: hash mismatch {rel}: {actual} != {expected}")

if errors:
    print("xavi-encrypt repository verification: FAIL")
    for error in errors:
        print(f" - {error}")
    raise SystemExit(1)

print(f"xavi-encrypt repository verification: PASS ({len(INDEX['versions'])} version(s))")
