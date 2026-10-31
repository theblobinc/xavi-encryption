"""Long-lived production evaluator worker process for Rev 1.2-dev4.

The worker launches only an evaluation-key TFHE sidecar.  It has no code path
for loading the TFHE client key.  Transport/networking remains external so the
same worker can be carried over SSH, a message bus, or the PQ channel.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import sys

from .remote_protocol import RemoteMessage
from .remote_service import RemoteEvaluatorProtocol
from .remote_tfhe import ProductionTFHEWorker
from .tfhe_split import TFHEEvaluatorSidecarBackend


def _b64d(value:str)->bytes:return base64.b64decode(value,validate=True)
def _b64e(value:bytes)->str:return base64.b64encode(value).decode("ascii")


def serve(command:list[str])->int:
    backend=TFHEEvaluatorSidecarBackend(command)
    worker=ProductionTFHEWorker(backend)
    protocol=RemoteEvaluatorProtocol()
    try:
        for line in sys.stdin:
            request=None
            try:
                request=json.loads(line);op=str(request.get("op",""))
                if op=="capabilities":
                    result={"role":"remote-worker","provider":"tfhe","cryptographic":True,"has_client_secret":False,"key_id":worker.key_id,"device":backend.capabilities.device,"protocol_snapshot":"v1"}
                elif op=="protocol_accept":
                    message=RemoteMessage.decode(_b64d(request["message"]))
                    result={"commitment":protocol.accept(message)}
                elif op=="protocol_snapshot": result=protocol.snapshot()
                elif op=="protocol_restore":
                    protocol=RemoteEvaluatorProtocol.restore(dict(request["snapshot"]));result={"restored":True}
                elif op=="execute_shake":
                    session_id=str(request["session_id"]);protocol.authorize_execution(session_id)
                    result={"response":_b64e(worker.execute_shake(_b64d(request["request"])))}
                elif op=="metrics": result=backend.metrics()
                elif op=="resident_stats": result=backend.resident_stats()
                elif op=="close": result={"closed":True}
                else: raise ValueError(f"unknown worker operation {op}")
                response={"ok":True,"result":result}
            except Exception as exc:
                response={"ok":False,"error":str(exc)}
            print(json.dumps(response,separators=(",",":")),flush=True)
            if isinstance(request,dict) and request.get("op")=="close":break
    finally:
        backend.close()
    return 0


def main(argv=None)->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--evaluator-command",default=os.environ.get("XAVI_VOID_TFHE_EVALUATOR_SIDECAR"))
    args=ap.parse_args(argv)
    if not args.evaluator_command:ap.error("--evaluator-command or XAVI_VOID_TFHE_EVALUATOR_SIDECAR is required")
    return serve(shlex.split(args.evaluator_command))

if __name__=="__main__":raise SystemExit(main())
