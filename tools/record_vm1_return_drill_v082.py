#!/usr/bin/env python3
"""Record a verified vm1-independent return drill without exporting any secrets.

Run on prod3 as root with Python -I after the actual TPM sign/verify gate.
The receipt is add-only; prior receipts and live custody cannot be overwritten.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

BACKUP=Path("/var/backups/xavi-duo/release-root-v082-20261106")
ORIGINAL=BACKUP/"custody"
RESTORED=Path("/var/lib/xavi-duo/release-signer/recovery-tests/v082-vm1-return")
SIGNATURE=Path("/var/lib/xavi-duo/release-signer/recovery-tests/v082-vm1-return.VERIFIED-DRILL-20261106.json")
RETURN=Path("/tmp/xavi-v082-vm1-return-transfer.cms.der")
RECEIPT=BACKUP/"VM1-RETURN-DRILL-RECEIPT.json"
BASE=Path("/var/lib/xavi-duo/release-signer/v0.8.2")
EXPECTED_RETURN_SHA="e95d52dfcddc77e64d5562afaa3d851fcba7d91afe09abc9dc63c2cb02f12261"
EXPECTED_SIGNATURE_SHA="17c012770f604b3f0affde013b5f2608596cbce9944f75aa8c31ee8fc3a20df8"
MANIFEST_SHA="sha256:afecddbe0941794be169e9a097ced7640e5432830d97ab2648f9a1d02bc92f26"
SIGNER_ID="sha256:ca74ba83611d2358efa2748f5945892069a55e2d3e1372ed53b5a1da5a851612"
VM1_CMS_SHA="da336ca348b41e64d3c2afbe809b43102b0e85dff4ee2faed9c956cfa0d0c511"
VM1_VERIFY_RECEIPT_SHA="b9de1090dcbea31ed38c3141b6f7cac193aae4f22cf0cefd5f51a3e947efb47b"

def require(ok, message):
    if not ok:
        raise ValueError(message)

def digest(contents):
    return hashlib.sha256(contents).hexdigest()

def main():
    require(os.geteuid()==0, "root approval required")
    require(not RECEIPT.exists(), "existing receipt cannot be replaced")
    for directory in (BACKUP, ORIGINAL, RESTORED, RESTORED/"objects", RESTORED/"default-kek"):
        s=directory.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0
                and stat.S_IMODE(s.st_mode)==0o700,"unprotected directory")
    base=json.loads((BACKUP/"RECOVERY-RECEIPT.json").read_text())
    inventory=base["inventory_sha256"]
    require(len(inventory)==5, "inventory must have exactly five objects")
    for name,sha in inventory.items():
        require(name.startswith(("default-kek/","objects/")) and ".." not in Path(name).parts,
                "invalid custody path")
        for folder in (ORIGINAL,RESTORED):
            file=folder/name
            s=file.lstat()
            require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0
                    and stat.S_IMODE(s.st_mode)==0o600,"unprotected custody file")
            require(digest(file.read_bytes())==sha, "custody digest mismatch")
    require(digest(RETURN.read_bytes())==EXPECTED_RETURN_SHA,"return transfer digest mismatch")
    require(digest(SIGNATURE.read_bytes())==EXPECTED_SIGNATURE_SHA,"signature receipt digest mismatch")
    v=subprocess.run(
        [str(BASE/"venv/bin/python"), "-I",
         "/var/lib/xavi-duo/release-signer/bootstrap/verify_trusted_release.py",
         "--public-key",str(BASE/"release-root-mldsa87.pub.pem"),
         "--manifest",str(BASE/"stage/RELEASE.json"),
         "--signature",str(SIGNATURE)],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        timeout=110,check=False)
    require(v.returncode==0,"protected independent trust verification failed")
    result=json.loads(v.stdout)
    require(result.get("status")=="TRUSTED_RELEASE_PASS"
            and result.get("cryptographic_verification")=="PASS"
            and result.get("manifest_sha256")==MANIFEST_SHA
            and result.get("signer_key_id")==SIGNER_ID
            and result.get("release_version")=="0.8.2"
            and result.get("runtime_authority") is False,
            "unexpected trusted release verification outcome")
    receipt={
        "schema":"XAVI-ENCRYPT/VM1-RETURN-DRILL-RECEIPT/v1",
        "status":"PASS",
        "created_utc":datetime.now(timezone.utc).isoformat(),
        "original_host":"prod3",
        "independent_recipient_host":"vm1",
        "same_physical_tpm":True,
        "pcr_policy":"sha256:7",
        "vm1_recipient_cms_sha256":VM1_CMS_SHA,
        "vm1_approved_decrypt_receipt_sha256":VM1_VERIFY_RECEIPT_SHA,
        "return_cms_sha256":EXPECTED_RETURN_SHA,
        "restored_signature_sha256":EXPECTED_SIGNATURE_SHA,
        "inventory_sha256":inventory,
        "inventory_verified":True,
        "restored_file_count":len(inventory),
        "trusted_release_policy_id":result["policy_id"],
        "trusted_release_status":result["status"],
        "canonical_manifest_digest":MANIFEST_SHA,
        "signer_key_id":SIGNER_ID,
        "runtime_authority":False,
        "original_live_custody_modified":False,
        "plaintext_signing_key_exported":False,
        "offsite_site_disaster_recovery_proven":False,
        "different_tpm_recovery_proven":False,
        "test_sign_approval_challenge":"c23290ff140e828dba1eb428351a232c4b31ed59bc838ce25e05512a069f57c2",
        "trust_verify_approval_challenge":"51b8c460768dc1d9553de4cb4a2dbb6f6ee3e49b72da167e50dae9d442642560",
    }
    fd=os.open(RECEIPT,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o600)
    with os.fdopen(fd,"wb") as output:
        output.write((json.dumps(receipt,sort_keys=True,indent=2)+"\n").encode())
        output.flush()
        os.fsync(output.fileno())
    print("VM1_RETURN_DRILL_RECEIPT=PASS files=5 sha256="+digest(RECEIPT.read_bytes()))

if __name__=="__main__":
    main()
