import hashlib

from xavi_void.crypto.keccak import keccak_f1600, shake256_512
from xavi_void.runtime.word_ir import (
    KECCAK_WORD_PROGRAM,
    WORD_REGISTER_COUNT,
    execute_word_program,
    shake256_512_word_ir,
)


def test_keccak_word_program_is_fixed_reusable_shape():
    program = KECCAK_WORD_PROGRAM
    program.validate()
    assert program.register_count.value == WORD_REGISTER_COUNT == 60
    assert len(program.instructions) == 2064
    assert program.instructions[0].instruction_id.value == 1
    assert program.instructions[-1].instruction_id.value == 2064
    assert program.representation_id().startswith("xvoid:shake256-512:")


def test_word_program_matches_native_keccak_permutation():
    state = [((i + 1) * 0x9E3779B97F4A7C15) & ((1 << 64) - 1) for i in range(25)]
    expected = list(state)
    keccak_f1600(expected)
    assert execute_word_program(state) == expected


def test_word_ir_shake_matches_standard_and_native_across_rate_boundaries():
    for length in (0, 1, 3, 64, 135, 136, 137, 271, 272, 273, 400):
        message = bytes((index * 17 + 5) % 256 for index in range(length))
        expected = hashlib.shake_256(message).digest(64)
        assert shake256_512_word_ir(message) == expected
        assert shake256_512_word_ir(message) == shake256_512(message)


def test_message_length_does_not_change_permutation_program_identity():
    program_id = KECCAK_WORD_PROGRAM.representation_id()
    for message in (b"a", b"a" * 136, b"a" * 1000):
        shake256_512_word_ir(message)
        assert KECCAK_WORD_PROGRAM.representation_id() == program_id
