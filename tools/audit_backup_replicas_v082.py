#!/usr/bin/env python3
"""Bounded, read-only XAVI-DUO v0.8.2 backup integrity audit.

Fixed profiles only; no filesystem mutations or key export. Prints small JSON
evidence suitable for a service journal. Deep mode decrypts a pinned CMS
envelope *in memory* with its own recipient key, validates exactly five
TPM-sealed/AEAD-encrypted custody members, and never saves plaintext files.

This checks one frozen backup version. It does not expand release trust, rotate
keys, change retention, or imply recovery after losing prod3's original TPM.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile

ORIGINAL_SHA = "ccd1438917fba5f108fb3d6f7e8facc9f190b7acb3c2f56f086e6f751fa6b41d"
VM1_SHA = "da336ca348b41e64d3c2afbe809b43102b0e85dff4ee2faed9c956cfa0d0c511"
PROD4_CERT_SHA = "cf8127e10957d554f0b648ea26666c0595992869c09b5d0b8533d29ba1fe7cfc"
VM1_CERT_SHA = "5f98e6ea8c65fef92080783f317b0003e0a0cdddc17759edf40764090caf7b02"
PROD4_RECEIPT_SHA = "c47e95f22c741105d9290e3e848264c27a09e1c021ef4efed7f709461198a1ec"
VM1_RECEIPT_SHA = "b9de1090dcbea31ed38c3141b6f7cac193aae4f22cf0cefd5f51a3e947efb47b"
PROD3_RETURN_RECEIPT_SHA = "bb4ab9f6873d3ccc711f7f0ddd1296130c0fc87f1827ad99ea09c580b2ffd4cf"
PROD3_RETURN_SIG_SHA = "17c012770f604b3f0affde013b5f2608596cbce9944f75aa8c31ee8fc3a20df8"
EXPECTED = {
    "custody/default-kek/metadata.json": "63a21c931c92b59fc5bcfcfcac4743b964f9f41724fc1d493b60a54cd0020e14",
    "custody/default-kek/seal.priv": "670e080a27d94f6ab5e83669c86aa8647c899ade868efef01bb43541a82489fc",
    "custody/default-kek/seal.pub": "0a3ec083c3cc812c82d495bc50951b3b2d55c287123acaa8da299daa33fc3732",
    "custody/default-kek/policy.digest": "487eb988506a69e372f37d565f8b6c23195e57a0372e6740fbbe1afb30a88291",
    "custody/objects/release-root-mldsa87.json": "770279b0c3e3dfd720c30817e3d6c0e1d415e42ff3a61840a536e2cb647bebda",
}
ROOT = Path("/var/backups/xavi-encrypt/v0.8.2")
RECIP = Path("/var/lib/xavi-encrypt-backup/v082-recipient")
PROD3_BACKUP = Path("/var/backups/xavi-duo/release-root-v082-20261106")
PROD3_RETURN = Path("/var/lib/xavi-duo/release-signer/recovery-tests/v082-vm1-return")
PROD3_SIG = Path("/var/lib/xavi-duo/release-signer/recovery-tests/v082-vm1-return.VERIFIED-DRILL-20261106.json")
SEAWEED_URL = "http://127.0.0.1:8888/xavi-backups/encrypt/v0.8.2/custody.cms.der"
PROFILE_IDS = ("prod3-root", "prod3-seaweed", "prod4-root", "prod4-user", "vm1-root")

class AuditFailure(Exception):
    pass

def require(condition, detail):
    if not condition:
        raise AuditFailure(detail)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def file_hash(path, expected, uid, modes=(0o600,), max_bytes=131072):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode), f"not a regular file: {path}")
    require(st.st_uid == uid and st.st_gid == uid, f"unexpected file owner: {path}")
    require(stat.S_IMODE(st.st_mode) in modes, f"unexpected file permissions: {path}")
    require(st.st_size <= max_bytes, f"oversized file: {path}")
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    require(actual == expected, f"SHA-256 mismatch: {path}")
    return st.st_size

def directory_mode(path, uid, modes=(0o700,)):
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode), f"not a directory: {path}")
    require(st.st_uid == uid and st.st_gid == uid, f"directory ownership mismatch: {path}")
    require(stat.S_IMODE(st.st_mode) in modes, f"directory permissions mismatch: {path}")

def require_root():
    require(os.geteuid() == 0, "root execution required")

def require_user():
    require(os.geteuid() != 0, "unprivileged account execution required")
    return os.geteuid()

def validate_custody_tar(contents):
    require(len(contents) <= 131072, "decrypted archive over size limit")
    with tarfile.open(fileobj=io.BytesIO(contents), mode="r:") as tf:
        members = tf.getmembers()
        require(len(members) == 5 and {m.name for m in members} == set(EXPECTED),
                "restored archive membership mismatch")
        for member in members:
            require(member.isfile() and member.mode == 0o600
                    and member.uid == 0 and member.gid == 0,
                    "restored member metadata mismatch")
            require(member.size <= 65536, "oversized archive member")
            stream = tf.extractfile(member)
            require(stream is not None and digest(stream.read()) == EXPECTED[member.name],
                    "restored custody digest mismatch")
    return 5

def deep_cms_check(cipher, cert, key):
    args = ["/usr/bin/openssl", "cms", "-decrypt", "-binary", "-inform", "DER",
            "-in", str(cipher), "-recip", str(cert), "-inkey", str(key)]
    result = subprocess.run(args, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=45, check=False)
    require(result.returncode == 0, "authenticated CMS decryption failed")
    return validate_custody_tar(result.stdout)

def check_recipient_certificate_window(cert):
    # Certificate expiry is an *operational rotation alarm*; an expired
    # certificate does not automatically erase a decryption private key.
    # Fail the scheduled check if expiry occurs within the next 60 days.
    result = subprocess.run(
        ["/usr/bin/openssl", "x509", "-in", str(cert),
         "-checkend", str(60 * 24 * 60 * 60), "-noout"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=15, check=False)
    require(result.returncode == 0, "backup recipient certificate expires within 60 days or is invalid")


def check_recipient(cert_hash, checks, deep_cipher=None):
    directory_mode(RECIP, 0)
    file_hash(RECIP / "recipient.cert.pem", cert_hash, 0, modes=(0o644, 0o600,))
    check_recipient_certificate_window(RECIP / "recipient.cert.pem")
    checks.append("recipient_certificate_valid_more_than_60_days")
    # Public certificate is within a root-only directory; private key is never read by Python.
    key = RECIP / "recipient.key.pem"
    st = key.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == 0
            and stat.S_IMODE(st.st_mode) == 0o600, "recipient private key exposure")
    checks.append("recipient_permissions_certificate")
    if deep_cipher is not None:
        count = deep_cms_check(deep_cipher, RECIP / "recipient.cert.pem", key)
        checks.append(f"authenticated_cms_and_{count}_member_hashes")

def check_prod4_root(deep, checks):
    require_root()
    directory_mode(ROOT, 0)
    file_hash(ROOT / "custody.cms.der", ORIGINAL_SHA, 0)
    file_hash(ROOT / "custody-vm1-recipient.cms.der", VM1_SHA, 0)
    file_hash(ROOT / "OFFNODE-STORAGE-RECEIPT.json", PROD4_RECEIPT_SHA, 0)
    checks.extend(("prod4_original_cms", "prod4_vm1_cms", "prod4_storage_receipt"))
    check_recipient(PROD4_CERT_SHA, checks, ROOT / "custody.cms.der" if deep else None)

def check_vm1_root(deep, checks):
    require_root()
    directory_mode(ROOT, 0)
    file_hash(ROOT / "custody.cms.der", ORIGINAL_SHA, 0)
    file_hash(ROOT / "custody-vm1-recipient.cms.der", VM1_SHA, 0)
    file_hash(ROOT / "VM1-INDEPENDENT-RECIPIENT-RECEIPT.json", VM1_RECEIPT_SHA, 0)
    checks.extend(("vm1_original_cms", "vm1_independent_cms", "vm1_recipient_receipt"))
    check_recipient(VM1_CERT_SHA, checks, ROOT / "custody-vm1-recipient.cms.der" if deep else None)

def check_prod4_user(deep, checks):
    require(not deep, "unprivileged profile cannot perform private-key decryption")
    uid = require_user()
    ds = Path("/datastore2/xavi-encrypt-backups/v0.8.2")
    nfs = Path("/srv/xavi-backups/xavi-encrypt/v0.8.2")
    directory_mode(ds, uid)
    directory_mode(nfs, uid, modes=(0o2700, 0o700))
    file_hash(ds / "custody.cms.der", ORIGINAL_SHA, uid)
    file_hash(nfs / "custody.cms.der", ORIGINAL_SHA, uid)
    # Prevent silently confusing a local directory with the expected prod3 NFS export.
    result = subprocess.run(
        ["/usr/bin/findmnt", "-n", "-T", str(nfs / "custody.cms.der"),
         "-o", "SOURCE"], capture_output=True, text=True, timeout=12, check=False)
    require(result.returncode == 0 and
            result.stdout.strip().startswith("10.77.0.2:/xavi-storage/.nfs-exports/backups"),
            "backup NFS mount source mismatch")
    checks.extend(("prod4_datastore2_cms", "prod3_nfs_backup_cms", "nfs_source"))

def check_prod3_seaweed(deep, checks):
    require(not deep, "SeaweedFS user profile is ciphertext-only")
    require_user()
    args = ["/usr/bin/podman", "exec", "xavi-seaweedfs", "/usr/bin/curl",
            "-fsS", "--max-filesize", "131072", "--max-time", "20", SEAWEED_URL]
    result = subprocess.run(args, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=35, check=False)
    require(result.returncode == 0 and len(result.stdout) == 21077,
            "SeaweedFS filer readback failed")
    require(digest(result.stdout) == ORIGINAL_SHA, "SeaweedFS ciphertext digest mismatch")
    checks.append("seaweedfs_filer_readback")

def check_prod3_root(deep, checks):
    require_root()
    directory_mode(PROD3_BACKUP, 0)
    file_hash(PROD3_BACKUP / "VM1-RETURN-DRILL-RECEIPT.json", PROD3_RETURN_RECEIPT_SHA, 0)
    # Detached signature is not a key and is stored with 0644 permissions in private tree.
    file_hash(PROD3_SIG, PROD3_RETURN_SIG_SHA, 0, modes=(0o644, 0o600), max_bytes=20000)
    directory_mode(PROD3_RETURN, 0)
    for name, expected_hash in EXPECTED.items():
        rel = name.removeprefix("custody/")
        directory_mode(PROD3_RETURN / Path(rel).parent, 0)
        file_hash(PROD3_RETURN / rel, expected_hash, 0)
    checks.extend(("prod3_return_receipt", "prod3_frozen_signature", "prod3_5_member_inventory"))
    # A one-time test key still awaits *separately approved* retirement.
    pending_key = Path("/var/lib/xavi-duo/release-signer/recovery-tests/v082-vm1-return-recipient/return.key.pem")
    if pending_key.exists():
        st = pending_key.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == 0
                and stat.S_IMODE(st.st_mode) == 0o600,
                "one-time test recipient key has unsafe permissions")
        checks.append("one_time_key_retirement_pending")
    if deep:
        base = Path("/var/lib/xavi-duo/release-signer/v0.8.2")
        cmd = [str(base / "venv/bin/python"), "-I",
               "/var/lib/xavi-duo/release-signer/bootstrap/verify_trusted_release.py",
               "--public-key", str(base / "release-root-mldsa87.pub.pem"),
               "--manifest", str(base / "stage/RELEASE.json"),
               "--signature", str(PROD3_SIG)]
        result = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=60, check=False)
        require(result.returncode == 0, "protected release-only signature verifier failed")
        data = json.loads(result.stdout)
        require(data.get("status") == "TRUSTED_RELEASE_PASS"
                and data.get("runtime_authority") is False
                and data.get("release_version") == "0.8.2",
                "signed recovery receipt failed organizational trust verification")
        checks.append("protected_release_only_verification")

PROFILES = {
    "prod3-root": check_prod3_root,
    "prod3-seaweed": check_prod3_seaweed,
    "prod4-root": check_prod4_root,
    "prod4-user": check_prod4_user,
    "vm1-root": check_vm1_root,
}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=PROFILE_IDS)
    parser.add_argument("--deep", action="store_true")
    args = parser.parse_args(argv)
    checks = []
    try:
        PROFILES[args.profile](args.deep, checks)
    except (AuditFailure, OSError, subprocess.TimeoutExpired, tarfile.TarError,
            json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"schema": "XAVI-ENCRYPT/BACKUP-AUDIT/v1",
                          "profile": args.profile, "deep": args.deep,
                          "status": "FAIL", "verified_checks": checks,
                          "reason": str(exc)[:280]}, sort_keys=True))
        return 1
    print(json.dumps({"schema": "XAVI-ENCRYPT/BACKUP-AUDIT/v1",
                      "profile": args.profile, "deep": args.deep,
                      "status": "PASS", "verified_checks": checks,
                      "release_version": "0.8.2",
                      "original_physical_tpm_required": True,
                      "site_disaster_recovery_proven": False}, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
