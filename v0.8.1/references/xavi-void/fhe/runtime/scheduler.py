"""Simple multi-worker encrypted-session scheduler."""
from __future__ import annotations
from dataclasses import dataclass,field
from .session import SessionManager

@dataclass(slots=True)
class EvaluatorWorker:
    worker_id:str
    sessions:SessionManager=field(default_factory=SessionManager)
    active_sessions:int=0

class EvaluatorPool:
    def __init__(self,workers:list[EvaluatorWorker]):
        if not workers: raise ValueError("at least one evaluator worker is required")
        if len({w.worker_id for w in workers})!=len(workers): raise ValueError("worker ids must be unique")
        self.workers=workers
    def choose(self)->EvaluatorWorker:
        return min(self.workers,key=lambda w:(w.active_sessions,w.worker_id))
    def acquire(self)->EvaluatorWorker:
        worker=self.choose();worker.active_sessions+=1;return worker
    def release(self,worker_id:str)->None:
        for worker in self.workers:
            if worker.worker_id==worker_id:
                if worker.active_sessions<1: raise ValueError("worker has no active sessions")
                worker.active_sessions-=1;return
        raise KeyError(worker_id)
