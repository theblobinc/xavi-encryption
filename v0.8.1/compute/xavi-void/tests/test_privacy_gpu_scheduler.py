from xavi_void.runtime.gpu import CPUWordBackend
from xavi_void.runtime.privacy import BOOLEAN_MEDIUM,KECCAK_24R
from xavi_void.runtime.scheduler import EvaluatorPool,EvaluatorWorker
from xavi_void.runtime.word_ir import KECCAK_WORD_PROGRAM,execute_word_program


def test_execution_classes_have_constant_batch_shapes():
    assert BOOLEAN_MEDIUM.padded_instruction_count.value % BOOLEAN_MEDIUM.batch_size.value==0
    assert KECCAK_24R.padded_instruction_count.value % KECCAK_24R.batch_size.value==0
    KECCAK_24R.validate_program_shape(instruction_count=len(KECCAK_WORD_PROGRAM.instructions),register_count=60)


def test_cpu_word_backend_matches_reference():
    state=list(range(25)); backend=CPUWordBackend()
    assert backend.execute(state,KECCAK_WORD_PROGRAM)==execute_word_program(state,KECCAK_WORD_PROGRAM)


def test_multi_worker_pool_uses_least_loaded_worker():
    a=EvaluatorWorker("a");b=EvaluatorWorker("b");pool=EvaluatorPool([a,b])
    assert pool.acquire().worker_id=="a"
    assert pool.acquire().worker_id=="b"
    pool.release("a")
    assert pool.choose().worker_id=="a"
