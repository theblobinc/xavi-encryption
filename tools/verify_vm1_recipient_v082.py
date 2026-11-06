#!/usr/bin/env python3
"""Independently verify XAVI-DUO v0.8.2's vm1 backup recipient envelope.

Runs under a root-authorized isolated Python interpreter on vm1. No decrypted
tarball or custody member is written to disk; the receipt contains only digests
and flags, never private-key bytes or decrypted custody objects.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
from datetime import datetime, timezone

BASE = Path("/var/backups/xavi-encrypt/v0.8.2")
CIPHERTEXT = BASE / "custody-vm1-recipient.cms.der"
OTHER_RECIPIENT_CIPHERTEXT = BASE / "custody.cms.der"
RECIPIENT = Path("/var/lib/xavi-encrypt-backup/v082-recipient")
CERT = RECIPIENT / "recipient.cert.pem"
KEY = RECIPIENT / "recipient.key.pem"
RECEIPT = BASE / "VM1-INDEPENDENT-RECIPIENT-RECEIPT.json"
CIPHER_SHA = "da336ca348b41e64d3c2afbe809b43102b0e85dff4ee2faed9c956cfa0d0c511"
OLD_CIPHER_SHA = "ccd1438917fba5f108fb3d6f7e8facc9f190b7acb3c2f56f086e6f751fa6b41d"
CERT_SHA = "5f98e6ea8c65fef92080783f317b0003e0a0cdddc17759edf40764090caf7b02"
MEMBERS = {
    "custody/default-kek/metadata.json": "63a21c931c92b59fc5bcfcfcac4743b964f9f41724fc1d493b60a54cd0020e14",
    "custody/default-kek/seal.priv": "670e080a27d94f6ab5e83669c86aa8647c899ade868efef01bb43541a82489fc",
    "custody/default-kek/seal.pub": "0a3ec083c3cc812c82d495bc50951b3b2d55c287123acaa8da299daa33fc3732",
    "custody/default-kek/policy.digest": "487eb988506a69e372f37d565f8b6c23195e57a0372e6740fbbe1afb30a88291",
    "custody/objects/release-root-mldsa87.json": "770279b0c3e3dfd720c30817e3d6c0e1d415e42ff3a61840a536e2cb647bebda",
}

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def require(condition, reason):
    if not condition:
        raise ValueError(reason)

def root_regular(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == 0
            and stat.S_IMODE(st.st_mode) == 0o600, "incorrect root-only file mode")
    return st

def decrypt(contents):
    # Use stdin: even the negative tampering check cannot create a plaintext file.
    return subprocess.run(
        ["/usr/bin/openssl", "cms", "-decrypt", "-binary", "-inform", "DER",
         "-in", "/dev/stdin", "-recip", str(CERT), "-inkey", str(KEY)],
        input=contents, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=75, check=False,
    )

def main():
    require(os.geteuid() == 0, "approved root execution required")
    require(not RECEIPT.exists(), "do not overwrite prior drill receipt")
    for directory in (BASE, RECIPIENT):
        st = directory.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_gid == 0
                and stat.S_IMODE(st.st_mode) == 0o700, "directory must be root-owned 0700")
    for p in (CIPHERTEXT, OTHER_RECIPIENT_CIPHERTEXT, KEY):
        root_regular(p)
    require(sha256(CERT.read_bytes()) == CERT_SHA, "vm1 recipient cert hash mismatch")
    encrypted = CIPHERTEXT.read_bytes()
    require(sha256(encrypted) == CIPHER_SHA, "new CMS ciphertext hash mismatch")
    old = OTHER_RECIPIENT_CIPHERTEXT.read_bytes()
    require(sha256(old) == OLD_CIPHER_SHA, "prod4-recipient CMS hash mismatch")
    result = decrypt(encrypted)
    require(result.returncode == 0, "vm1 private-key CMS authenticated decrypt failed")
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        entries = archive.getmembers()
        require(len(entries) == 5 and {m.name for m in entries} == set(MEMBERS),
                "custody archive member list mismatch")
        for member in entries:
            require(member.isfile() and member.mode == 0o600
                    and member.uid == 0 and member.gid == 0, "invalid member metadata")
            body = archive.extractfile(member)
            require(body is not None and sha256(body.read()) == MEMBERS[member.name],
                    "custody member digest mismatch")
    # This key must NOT be able to decrypt the old archive, which targets prod4.
    wrong_recipient = decrypt(old)
    require(wrong_recipient.returncode != 0, "old recipient archive wrongly decryptable by vm1")
    altered = bytearray(encrypted)
    altered[-1] ^= 1
    tamper_result = decrypt(bytes(altered))
    require(tamper_result.returncode != 0, "tampered CMS failed to reject")
    record = {
        "schema": "XAVI-ENCRYPT/VM1-INDEPENDENT-RECIPIENT-RECEIPT/v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "host": "vm1",
        "release_version": "0.8.2",
        "status": "PASS",
        "archive_name": "custody-vm1-recipient.cms.der",
        "encrypted_archive_sha256": CIPHER_SHA,
        "encrypted_archive_bytes": len(encrypted),
        "recipient_certificate_sha256": CERT_SHA,
        "envelope": "CMS AES-256-GCM RSA-OAEP",
        "authenticated_decryption": "PASS",
        "member_count": 5,
        "member_hashes_verified": True,
        "wrong_recipient_denied": True,
        "tampered_ciphertext_denied": True,
        "decrypted_custody_archive_saved": False,
        "original_prod3_tpm_still_required": True,
        "independent_site_recovery_proven": False,
        "runtime_authority": False,
    }
    fd = os.open(RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as writer:
        writer.write((json.dumps(record, sort_keys=True, indent=2) + "\n").encode())
        writer.flush()
        os.fsync(writer.fileno())
    print("VM1_INDEPENDENT_RECIPIENT_VERIFIED=PASS files=5 wrong_recipient_denied=true tamper_denied=true receipt_sha256=" + sha256(RECEIPT.read_bytes()))

if __name__ == "__main__":
    main()
