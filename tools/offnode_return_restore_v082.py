#!/usr/bin/env python3
"""One-time, fail-closed prod3 re-import of a prod4-wrapped TPM custody backup.

Requires exact digest, original inventory and pre-existing root-only return recipient.
Never overwrites live custody or exports decrypted keys. Not an alternative trust root.
"""
import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile

BASE = Path("/var/lib/xavi-duo/release-signer/recovery-tests")
INBOUND = Path("/tmp/xavi-v082-offnode-return-transfer.cms.der")
DEST = BASE / "v082-offnode-return"
RECIPIENT = BASE / "offnode-return-recipient"
CIPHER_SHA256 = "54e5471871ce503bf5e8a6345c9a2536fdbcdab7a6bcd6a7018b2c67d2cd02b3"
EXPECTED = {
    "custody/default-kek/metadata.json": "63a21c931c92b59fc5bcfcfcac4743b964f9f41724fc1d493b60a54cd0020e14",
    "custody/default-kek/seal.priv": "670e080a27d94f6ab5e83669c86aa8647c899ade868efef01bb43541a82489fc",
    "custody/default-kek/seal.pub": "0a3ec083c3cc812c82d495bc50951b3b2d55c287123acaa8da299daa33fc3732",
    "custody/default-kek/policy.digest": "487eb988506a69e372f37d565f8b6c23195e57a0372e6740fbbe1afb30a88291",
    "custody/objects/release-root-mldsa87.json": "770279b0c3e3dfd720c30817e3d6c0e1d415e42ff3a61840a536e2cb647bebda",
}


def restore():
    if os.geteuid() != 0:
        raise PermissionError("requires root OIDC approval")
    if DEST.exists():
        raise FileExistsError("refusing to reuse or overwrite existing restore")
    for p in (BASE, RECIPIENT):
        st = p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
            raise PermissionError("restore directories require root:root 0700")
    priv = RECIPIENT / "return.key.pem"
    pstat = priv.lstat()
    if not stat.S_ISREG(pstat.st_mode) or pstat.st_uid != 0 or stat.S_IMODE(pstat.st_mode) != 0o600:
        raise PermissionError("recipient key must be root-owned 0600")
    ciphertext = INBOUND.read_bytes()
    if hashlib.sha256(ciphertext).hexdigest() != CIPHER_SHA256:
        raise ValueError("return ciphertext digest mismatch")
    decrypt = subprocess.run(
        ["/usr/bin/openssl", "cms", "-decrypt", "-binary", "-inform", "DER",
         "-in", str(INBOUND), "-recip", str(RECIPIENT / "return.cert.pem"),
         "-inkey", str(priv)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=90, check=False)
    if decrypt.returncode:
        raise ValueError("CMS authenticated decrypt failed")
    old_umask = os.umask(0o077)
    temp = Path(tempfile.mkdtemp(prefix=".v082-restore-", dir=BASE))
    try:
        with tarfile.open(fileobj=io.BytesIO(decrypt.stdout), mode="r:") as tf:
            entries = tf.getmembers()
            if len(entries) != len(EXPECTED) or {m.name for m in entries} != set(EXPECTED):
                raise ValueError("archive member allowlist mismatch")
            for m in entries:
                if not m.isfile() or m.mode != 0o600 or m.uid != 0 or m.gid != 0:
                    raise ValueError("unsafe archive member")
                rel = m.name.removeprefix("custody/")
                if rel == m.name or rel.startswith("/") or ".." in Path(rel).parts:
                    raise ValueError("unsafe archive path")
                data = tf.extractfile(m).read()
                if hashlib.sha256(data).hexdigest() != EXPECTED[m.name]:
                    raise ValueError("custody digest mismatch")
                target = temp / rel
                target.parent.mkdir(mode=0o700, exist_ok=True)
                fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as fout:
                    fout.write(data)
                    fout.flush()
                    os.fsync(fout.fileno())
        for directory in (temp, temp / "default-kek", temp / "objects"):
            if directory.stat().st_uid != 0 or stat.S_IMODE(directory.stat().st_mode) != 0o700:
                raise PermissionError("restored directory permissions differ")
        if DEST.exists():
            raise FileExistsError("restore destination appeared concurrently")
        os.rename(temp, DEST)
        print("OFFNODE_RETURN_RESTORE=PASS files=5 sealed_only=true root_only=true")
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    restore()
