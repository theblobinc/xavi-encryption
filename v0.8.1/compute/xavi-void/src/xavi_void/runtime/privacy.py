"""Observable-shape hardening policies for encrypted execution."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from xavi_void.math.types import PositiveExtent

class CiphertextReusePolicy(str,Enum):
    FORBID="forbid"
    PROVIDER_REFRESH="provider-refresh"
    SESSION_SCOPED="session-scoped"

@dataclass(frozen=True,slots=True)
class ExecutionClass:
    name:str
    padded_instruction_count:PositiveExtent
    batch_size:PositiveExtent
    register_bank_size:PositiveExtent
    checkpoint_interval_batches:PositiveExtent
    padded_absorb_blocks:PositiveExtent | None = None
    ciphertext_reuse_policy:CiphertextReusePolicy=CiphertextReusePolicy.SESSION_SCOPED

    def __post_init__(self):
        if not self.name: raise ValueError("execution class name required")
        for field in (self.padded_instruction_count,self.batch_size,self.register_bank_size,self.checkpoint_interval_batches):
            if not isinstance(field,PositiveExtent): raise TypeError("execution class extents must be PositiveExtent")
        if self.padded_absorb_blocks is not None and not isinstance(self.padded_absorb_blocks,PositiveExtent):
            raise TypeError("padded_absorb_blocks must be PositiveExtent or None")

    def batch_count(self)->int:
        n=self.padded_instruction_count.value; b=self.batch_size.value
        return (n+b-1)//b

    def validate_program_shape(self,*,instruction_count:int,register_count:int)->None:
        if instruction_count>self.padded_instruction_count.value: raise ValueError("program exceeds execution-class instruction budget")
        if register_count>self.register_bank_size.value: raise ValueError("program exceeds execution-class register budget")

BOOLEAN_MEDIUM=ExecutionClass(
    "boolean-medium",PositiveExtent(256),PositiveExtent(32),PositiveExtent(128),PositiveExtent(2)
)
KECCAK_24R=ExecutionClass(
    "keccak-24r",PositiveExtent(2080),PositiveExtent(32),PositiveExtent(60),PositiveExtent(4),PositiveExtent(4)
)
