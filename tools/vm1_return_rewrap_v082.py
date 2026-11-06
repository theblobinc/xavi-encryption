#!/usr/bin/env python3
"""Return vm1's independently recovered 0.8.2 archive to prod3's one-time recipient.

This executes on vm1 under root approval. It performs authenticated CMS
decryption in a subprocess to memory, checks an allowlist of ciphertext-object
hashes, and re-encrypts to prod3's one-time pinned public return certificate.
No secret key material is printed or copied, and no plaintext tar file is saved.
"""
import hashlib
import io
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile

BASE = Path("/var/backups/xavi-encrypt/v0.8.2")
ORIGINAL = BASE / "custody-vm1-recipient.cms.der"
OUT = BASE / "vm1-to-prod3-return.cms.der"
OLD_KEY = Path("/var/lib/xavi-encrypt-backup/v082-recipient/recipient.key.pem")
OLD_CERT = OLD_KEY.with_name("recipient.cert.pem")
NEW_CERT = Path("/tmp/xavi-v082-vm1-return-recipient-prod3.cert.pem")
OLD_CMS_SHA256 = "da336ca348b41e64d3c2afbe809b43102b0e85dff4ee2faed9c956cfa0d0c511"
NEW_CERT_SHA256 = "a4976bca65b5372beeeb909ed1f1e537c69e678329adc9ba05440f415be56276"
EXPECTED = {
    "custody/default-kek/metadata.json": "63a21c931c92b59fc5bcfcfcac4743b964f9f41724fc1d493b60a54cd0020e14",
    "custody/default-kek/seal.priv": "670e080a27d94f6ab5e83669c86aa8647c899ade868efef01bb43541a82489fc",
    "custody/default-kek/seal.pub": "0a3ec083c3cc812c82d495bc50951b3b2d55c287123acaa8da299daa33fc3732",
    "custody/default-kek/policy.digest": "487eb988506a69e372f37d565f8b6c23195e57a0372e6740fbbe1afb30a88291",
    "custody/objects/release-root-mldsa87.json": "770279b0c3e3dfd720c30817e3d6c0e1d415e42ff3a61840a536e2cb647bebda",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run():
    if os.geteuid() != 0:
        raise PermissionError("requires approved root execution")
    if OUT.exists():
        raise FileExistsError("refusing to replace existing independent envelope")
    if sha256(NEW_CERT.read_bytes()) != NEW_CERT_SHA256:
        raise ValueError("prod3 one-time public return certificate mismatch")
    if sha256(ORIGINAL.read_bytes()) != OLD_CMS_SHA256:
        raise ValueError("vm1 independently encrypted archive hash mismatch")
    for path in (ORIGINAL, OLD_KEY):
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
            raise PermissionError("original archive or key not root-owned 0600")
    dec = subprocess.run(
        ["/usr/bin/openssl", "cms", "-decrypt", "-binary", "-inform", "DER",
         "-in", str(ORIGINAL), "-recip", str(OLD_CERT), "-inkey", str(OLD_KEY)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
        timeout=75, check=False)
    if dec.returncode:
        raise ValueError("authenticated CMS decryption failed")
    with tarfile.open(fileobj=io.BytesIO(dec.stdout), mode="r:") as tf:
        members = tf.getmembers()
        if len(members) != 5 or {m.name for m in members} != set(EXPECTED):
            raise ValueError("object membership mismatch")
        for member in members:
            if not member.isfile() or member.mode != 0o600 or member.uid != 0 or member.gid != 0:
                raise ValueError("unexpected archive member permissions")
            if sha256(tf.extractfile(member).read()) != EXPECTED[member.name]:
                raise ValueError("archive member hash mismatch")
    previous_umask = os.umask(0o077)
    fd, temp = tempfile.mkstemp(prefix=".vm1-cms-", suffix=".tmp", dir=BASE)
    os.close(fd)
    try:
        enc = subprocess.run(
            ["/usr/bin/openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm",
             "-in", "/dev/stdin", "-outform", "DER", "-out", temp,
             "-recip", str(NEW_CERT), "-keyopt", "rsa_padding_mode:oaep"],
            input=dec.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=75, check=False)
        if enc.returncode:
            raise ValueError("prod3 return recipient re-encryption failed")
        os.chmod(temp, 0o600)
        os.link(temp, OUT)
        with OUT.open("rb") as fh:
            os.fsync(fh.fileno())
        print("VM1_TO_PROD3_RETURN_CMS_PASS files=5 bytes=%d sha256=%s" %
              (OUT.stat().st_size, sha256(OUT.read_bytes())))
    finally:
        os.unlink(temp)
        os.umask(previous_umask)


if __name__ == "__main__":
    run()
