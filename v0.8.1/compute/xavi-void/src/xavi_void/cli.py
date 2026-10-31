from __future__ import annotations

import argparse
import json

from .crypto.selftest import run_crypto_selftest
from .crypto.shake import content_id
from .math.state import Branch, SignedBijective, to_text


def main() -> int:
    parser = argparse.ArgumentParser(prog="xavi-void")
    sub = parser.add_subparsers(dest="command", required=True)

    encode = sub.add_parser("encode", help="encode a native signed DUO value; unity is 1 and there is no numeric zero")
    encode.add_argument("value", type=int)
    encode.add_argument("--base", type=int, default=10)

    shake = sub.add_parser("shake", help="produce a SHAKE256-512 domain-separated content id")
    shake.add_argument("domain", help="versioned ASCII domain ending in /vN")
    shake.add_argument("text")

    sub.add_parser("selftest", help="run deterministic cryptographic reference self-tests")
    sub.add_parser("encrypted-selftest", help="run NON-SECURE reference encrypted SHAKE conformance test")
    sub.add_parser("evaluator-audit", help="audit evaluator code for decrypt calls or encrypted-field branch tests")

    args = parser.parse_args()
    if args.command == "encode":
        if args.value == 0:
            parser.error("numeric zero is not a DUO semantic value; use unity origin 1")
        if abs(args.value) == 1:
            state = SignedBijective.origin(base=args.base)
        else:
            branch = Branch.POSITIVE if args.value > 1 else Branch.NEGATIVE
            state = SignedBijective.from_magnitude(abs(args.value), branch=branch, base=args.base)
        print(to_text(state))
        return 0
    if args.command == "shake":
        print(content_id(args.domain, args.text.encode("utf-8")))
        return 0
    if args.command == "selftest":
        print(json.dumps(run_crypto_selftest(), sort_keys=True))
        return 0
    if args.command == "evaluator-audit":
        from .runtime.native_validation import audit_evaluator_secrecy
        result=audit_evaluator_secrecy()
        print(json.dumps({"passed":result.passed,"forbidden_decrypt_references":result.forbidden_decrypt_references,"secret_branch_references":result.secret_branch_references,"audited_functions":result.audited_functions},sort_keys=True))
        return 0 if result.passed else 1
    if args.command == "encrypted-selftest":
        from .runtime.encrypted import ReferenceFHEBackend
        from .runtime.shake_encrypted import verify_encrypted_shake256_512
        digest=verify_encrypted_shake256_512(b"abc",ReferenceFHEBackend())
        print(json.dumps({"backend":"reference-NOT-SECURE","message":"abc","shake256_512":digest.hex(),"verified":True},sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
