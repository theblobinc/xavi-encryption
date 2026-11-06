#!/usr/bin/env python3
"""Verify a frozen release only when an independently installed owner policy permits it.

The detached signature's authority:false flag is NEVER upgraded to runtime authority.
The Git copy of the policy is a proposal, not a trusted policy source.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

SCHEMA = "XAVI-ENCRYPT/RELEASE-TRUST-POLICY/v1"
PURPOSE = "release-manifest-verification-only"
TRUST_PATH = Path("/etc/xavi-encrypt/release-trust/v1.json")
MANIFEST_SCHEMA = "XAVI-DUO/RELEASE-ARTIFACT-MANIFEST/v1"


class TrustError(ValueError):
    pass


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read_regular(path: Path, limit: int) -> bytes:
    if path.is_symlink():
        raise TrustError("symlink input forbidden")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as fh:
        before = os.fstat(fh.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise TrustError("nonregular or oversized input")
        data = fh.read(limit + 1)
        after = os.fstat(fh.fileno())
        if len(data) > limit or (before.st_ino, before.st_dev, before.st_size) != (after.st_ino, after.st_dev, after.st_size):
            raise TrustError("input changed while reading")
        return data


def read_owner_policy(path: Path = TRUST_PATH) -> dict:
    if path != TRUST_PATH:
        raise TrustError("trust policy must come from the fixed independent /etc location")
    for parent in (path.parent, path.parent.parent):
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise TrustError("trust policy directory must be root owned, without group/world write")
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise TrustError("trust policy must be root owned and protected")
    try:
        return json.loads(_read_regular(path, 16384))
    except (ValueError, UnicodeError) as exc:
        raise TrustError("malformed trust policy") from exc


def verify_with_policy(policy: dict, *, public_key: Path, manifest: Path, signature: Path) -> dict:
    if not isinstance(policy, dict) or set(policy) != {
        "schema", "policy_id", "organization", "status", "purpose",
        "runtime_authority", "signer", "allowed_manifests", "registration",
    }:
        raise TrustError("trust policy fields mismatch")
    if (policy["schema"] != SCHEMA or policy["status"] != "active"
            or policy["purpose"] != PURPOSE or policy["runtime_authority"] is not False
            or policy["organization"] != "The Blob Inc."):
        raise TrustError("trust policy inactive or outside release-only scope")
    signer = policy["signer"]
    if not isinstance(signer, dict) or set(signer) != {
        "algorithm", "key_id", "custody_reference", "pcr_policy", "native_pq_operation"
    }:
        raise TrustError("trusted signer fields mismatch")
    if (signer["algorithm"] != "ML-DSA-87" or signer["native_pq_operation"] is not False
            or signer["pcr_policy"] != "sha256:7"
            or signer["custody_reference"] != "tpm2://prod3/release-root-mldsa87"):
        raise TrustError("unexpected signer attributes")
    actual_key_id = digest(_read_regular(public_key, 65536))
    if actual_key_id != signer["key_id"]:
        raise TrustError("signer key is not the independently pinned root")
    try:
        m = json.loads(_read_regular(manifest, 131072))
    except ValueError as exc:
        raise TrustError("invalid release manifest JSON") from exc
    if (not isinstance(m, dict) or m.get("schema") != MANIFEST_SCHEMA
            or m.get("project") != "XAVI-DUO Encryption" or m.get("authority") is not False
            or m.get("signature_required") != "ML-DSA-87"):
        raise TrustError("release manifest outside authorized domain")
    allowed = policy["allowed_manifests"]
    if not isinstance(allowed, dict) or not isinstance(m.get("version"), str):
        raise TrustError("release version is not in trust policy")
    canonical_digest = digest(json.dumps(m, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    if allowed.get(m["version"]) != canonical_digest:
        raise TrustError("release version or canonical manifest digest not authorized")
    # Verification uses the installed Python package, never a path injected
    # from a caller-writable Git checkout.
    from xavi_duo_release import verify_manifest
    verified = verify_manifest(public_key, manifest, signature)
    if (verified.get("status") != "PASS" or verified.get("authority") is not False
            or verified.get("signer_key_id") != actual_key_id
            or verified.get("algorithm") != "ML-DSA-87"):
        raise TrustError("ML-DSA release verification rejected")
    return {"status": "TRUSTED_RELEASE_PASS", "policy_id": policy["policy_id"],
            "purpose": PURPOSE, "release_version": m["version"],
            "signer_key_id": actual_key_id, "manifest_sha256": verified["manifest_sha256"],
            "cryptographic_verification": "PASS", "runtime_authority": False}


def _root_owned_regular(path: Path) -> None:
    if path.is_symlink():
        raise TrustError("trusted runtime symlink forbidden")
    path = path.resolve(strict=True)
    if not path.is_file():
        raise TrustError("trusted executable must be regular")
    parents = [path, *path.parents]
    for item in parents:
        st = item.lstat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise TrustError("verifier runtime must be root-owned, without group/world write")


def _check_runtime_integrity() -> None:
    # Prevent a mutable Git checkout, user site-packages, or PYTHONPATH from
    # becoming an implicit second trust root. Install the script and pinned
    # v0.8.2 wheel into root-owned locations, invoke with Python -I.
    import importlib.util
    if not sys.flags.isolated:
        raise TrustError("trusted verifier requires isolated Python (-I)")
    _root_owned_regular(Path(__file__))
    spec = importlib.util.find_spec("xavi_duo_release")
    if spec is None or not spec.origin:
        raise TrustError("pinned crypto library not installed")
    _root_owned_regular(Path(spec.origin))
    # The pinned v0.8.2 package lives *inside* the protected venv;
    # its version string is not an indicator of an untrusted checkout.
    installed_module = Path(spec.origin).resolve(strict=True)
    interpreter_prefix = Path(sys.prefix).resolve(strict=True)
    if not installed_module.is_relative_to(interpreter_prefix):
        raise TrustError("crypto module is outside the protected Python environment")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args()
    try:
        _check_runtime_integrity()
        policy = read_owner_policy()
        result = verify_with_policy(policy, public_key=args.public_key,
                                    manifest=args.manifest, signature=args.signature)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        print(f"TRUSTED_RELEASE_FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
