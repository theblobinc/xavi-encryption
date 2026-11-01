"""Provider-neutral word execution backends.

The local reference backend is CPU.  Real GPU execution is attached through the
same opaque sidecar model used by the FHE layer; the sidecar must advertise a
GPU device and the xavi-void Keccak word-program capability.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
import subprocess
from typing import Sequence

from .encrypted import BackendUnavailable
from .word_ir import WordProgram, execute_word_program

@dataclass(frozen=True,slots=True)
class WordBackendCapabilities:
    provider:str
    device:str
    accelerated:bool
    supports_keccak_word_ir:bool

class WordExecutionBackend(ABC):
    backend_id:str
    capabilities:WordBackendCapabilities
    @abstractmethod
    def execute(self,state:Sequence[int],program:WordProgram)->list[int]: ...

class CPUWordBackend(WordExecutionBackend):
    backend_id="xavi-void-cpu-word-reference"
    capabilities=WordBackendCapabilities("python","cpu",False,True)
    def execute(self,state:Sequence[int],program:WordProgram)->list[int]: return execute_word_program(list(state),program)

class SidecarGPUWordBackend(WordExecutionBackend):
    def __init__(self,command:Sequence[str])->None:
        if not command: raise ValueError("GPU sidecar command required")
        try:self._proc=subprocess.Popen(list(command),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        except OSError as e: raise BackendUnavailable(f"unable to launch GPU sidecar: {e}") from e
        result=self._call("capabilities")
        caps=WordBackendCapabilities(str(result.get("provider","")),str(result.get("device","")),bool(result.get("accelerated")),bool(result.get("supports_keccak_word_ir")))
        if not caps.accelerated or caps.device.lower() not in {"cuda","rocm","gpu"} or not caps.supports_keccak_word_ir:
            self.close(); raise BackendUnavailable("sidecar does not provide an accelerated GPU word backend")
        self.capabilities=caps;self.backend_id=f"xavi-void-gpu-sidecar:{caps.provider}:{caps.device}"
    def _call(self,op:str,**kwargs):
        if self._proc.poll() is not None: raise BackendUnavailable("GPU sidecar terminated")
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(json.dumps({"op":op,**kwargs},separators=(",",":"))+"\n");self._proc.stdin.flush()
        line=self._proc.stdout.readline()
        if not line: raise BackendUnavailable("GPU sidecar returned no response")
        response=json.loads(line)
        if not response.get("ok",False): raise RuntimeError(str(response.get("error","GPU sidecar failure")))
        return response.get("result",{})
    def execute(self,state:Sequence[int],program:WordProgram)->list[int]:
        program.validate()
        result=self._call("execute_keccak_word_program",state=[int(v) for v in state],representation_id=program.representation_id())
        words=[int(v) for v in result["state"]]
        if len(words)!=25: raise RuntimeError("GPU sidecar returned invalid state length")
        return words
    def close(self):
        if getattr(self,"_proc",None) is not None and self._proc.poll() is None:
            try:self._call("close")
            except Exception:pass
            self._proc.terminate()
