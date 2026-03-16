from taintinduce.classifier.classifier import classify_instruction, is_mapped, is_translatable
from taintinduce.classifier.categories import InstructionCategory
from taintinduce.isa.x86_registers import X86_REG_EAX, X86_REG_EBX
from taintinduce.state.state import Observation, State
from taintinduce.types import Architecture, StateValue


def test_classify_monotonic():
    state_fmt = [X86_REG_EAX(), X86_REG_EBX()]
    seed_in = State(64, StateValue(0))
    seed_out = State(64, StateValue(0))

    # OR instruction: Two different inputs map to the SAME output
    mut_in1 = State(64, StateValue(1))  # eax[0] flipped
    mut_out1 = State(64, StateValue(1))  # out[0] flipped

    mut_in2 = State(64, StateValue(1 << 32))  # ebx[0] flipped
    mut_out2 = State(64, StateValue(1))  # out[0] flipped

    obs = Observation(
        (seed_in, seed_out),
        frozenset([(mut_in1, mut_out1), (mut_in2, mut_out2)]),
        '00',
        Architecture.X86,
        state_fmt,
    )

    assert classify_instruction([obs]) == InstructionCategory.MONOTONIC


def test_classify_transportable():
    state_fmt = [X86_REG_EAX(), X86_REG_EBX()]
    seed_in = State(64, StateValue(1))  # EAX=1
    seed_out = State(64, StateValue(1))

    mut_in_0 = State(64, StateValue(0))
    mut_out_0 = State(64, StateValue(0))

    mut_in_32 = State(64, StateValue(1 | (1 << 32)))
    mut_out_32 = State(64, StateValue(2))

    obs = Observation(
        (seed_in, seed_out),
        frozenset([(mut_in_0, mut_out_0), (mut_in_32, mut_out_32)]),
        '00',
        Architecture.X86,
        state_fmt,
    )

    assert classify_instruction([obs]) == InstructionCategory.TRANSPORTABLE


def test_classify_translatable():
    state_fmt = [X86_REG_EAX(), X86_REG_EBX()]

    # SHL EAX, CL (using EBX as CL for simplicity)
    # EAX = 3 (bits 0,1 are 1). EBX = 1. Output = 6 (bits 1,2 are 1).
    # If we flip EBX bit 0 (so EBX = 0), Output = 3 (bits 0,1 are 1).
    # Here, going EBX 0->1 means Output goes 3->6. Bit 0 falls from 1->0! Bit 2 rises 0->1!
    # This means EBX bit 0 is NEITHER non-decreasing NOR non-increasing! So not monotonic.

    seed_in = State(64, StateValue(3 | (1 << 32)))  # EAX=3, EBX=1
    seed_out = State(64, StateValue(6))  # 3 << 1 = 6

    # Flip bit 0 of EAX (3 -> 2) -> Output 2 << 1 = 4
    mut_in_0 = State(64, StateValue(2 | (1 << 32)))
    mut_out_0 = State(64, StateValue(4))

    # Flip bit 1 of EAX (3 -> 1) -> Output 1 << 1 = 2
    mut_in_1 = State(64, StateValue(1 | (1 << 32)))
    mut_out_1 = State(64, StateValue(2))

    # Flip bit 0 of EBX (EBX 1 -> 0) -> Output 3 << 0 = 3
    mut_in_32 = State(64, StateValue(3 | (0 << 32)))
    mut_out_32 = State(64, StateValue(3))

    obs = Observation(
        (seed_in, seed_out),
        frozenset([(mut_in_0, mut_out_0), (mut_in_1, mut_out_1), (mut_in_32, mut_out_32)]),
        'd3e0',
        Architecture.X86,
        state_fmt,
    )

    assert classify_instruction([obs]) == InstructionCategory.TRANSLATABLE


def test_classify_cond_transportable():
    # To avoid being classified as Monotonic, a bit must show it is neither non-decreasing nor non-increasing.
    # We need an input bit that both rises AND falls causing the output to rise in both cases, or something similar.
    # Ex: O = 1 if ((in0 ^ in1) == 0) else 0.

    # seed 1: in0=0, in1=0 -> O=1
    seed_in_1 = State(64, StateValue(0))
    seed_out_1 = State(64, StateValue(1))

    mut1_1 = State(64, StateValue(1))  # in0=1, in1=0
    mut1_out_1 = State(64, StateValue(0))  # O=0.  in0 rose -> O fell. (Non-increasing behavior for in0)

    mut2_1 = State(64, StateValue(2))  # in0=0, in1=1
    mut2_out_1 = State(64, StateValue(0))  # O=0.  in1 rose -> O fell.

    obs2_1 = Observation(
        (seed_in_1, seed_out_1),
        frozenset([(mut1_1, mut1_out_1), (mut2_1, mut2_out_1)]),
        'test_eq',
        Architecture.X86,
        [X86_REG_EAX(), X86_REG_EBX()],
    )

    # seed 2: in0=1, in1=0 -> O=0
    seed_in_2 = State(64, StateValue(1))
    seed_out_2 = State(64, StateValue(0))

    mut1_2 = State(64, StateValue(0))  # in0=0, in1=0
    mut1_out_2 = State(64, StateValue(1))  # O=1. in0 fell -> O rose. (Non-increasing behavior for in0)

    mut2_2 = State(64, StateValue(3))  # in0=1, in1=1
    mut2_out_2 = State(64, StateValue(1))  # O=1. in1 rose -> O rose. (Non-decreasing behavior for in1)

    obs2_2 = Observation(
        (seed_in_2, seed_out_2),
        frozenset([(mut1_2, mut1_out_2), (mut2_2, mut2_out_2)]),
        'test_eq',
        Architecture.X86,
        [X86_REG_EAX(), X86_REG_EBX()],
    )

    # seed 3: in0=0, in1=1 -> O=0
    seed_in_3 = State(64, StateValue(2))
    seed_out_3 = State(64, StateValue(0))

    mut1_3 = State(64, StateValue(3))  # in0=1, in1=1
    mut1_out_3 = State(
        64,
        StateValue(1),
    )  # O=1. in0 rose -> O rose. (Non-decreasing behavior for in0! Breaks monotonic for in0)

    mut2_3 = State(64, StateValue(0))  # in0=0, in1=0
    mut2_out_3 = State(
        64,
        StateValue(1),
    )  # O=1. in1 fell -> O rose. (Non-increasing behavior for in1! Breaks monotonic for in1)

    obs2_3 = Observation(
        (seed_in_3, seed_out_3),
        frozenset([(mut1_3, mut1_out_3), (mut2_3, mut2_out_3)]),
        'test_eq',
        Architecture.X86,
        [X86_REG_EAX(), X86_REG_EBX()],
    )

    assert classify_instruction([obs2_1, obs2_2, obs2_3]) == InstructionCategory.COND_TRANSPORTABLE


def test_classify_mapped():
    # Test for mapped (e.g. NOT eax)
    # X_0 flips Y_0, X_1 flips Y_1, etc.
    seed_in = State(64, StateValue(0))
    seed_out = State(64, StateValue(0xFFFFFFFFFFFFFFFF))

    mutations = []
    for i in range(5):
        mut_in = State(64, StateValue(1 << i))
        # NOT eax implies that the bit i of output will drop to 0
        mut_out = State(64, StateValue(0xFFFFFFFFFFFFFFFF ^ (1 << i)))
        mutations.append((mut_in, mut_out))

    obs = Observation(
        (seed_in, seed_out),
        frozenset(mutations),
        'test_not',
        Architecture.X86,
        [X86_REG_EAX(), X86_REG_EBX()],
    )

    assert is_mapped([obs]) is True
    assert classify_instruction([obs]) == InstructionCategory.MAPPED


def test_classify_mapped_shifted():
    # Test for SHL eax, 2 (Mapped but shifted AND some inputs don't map)
    # X_0 flips Y_2, X_1 flips Y_3... X_62 flips Y_64 (outside, or None), X_63 -> None
    seed_in = State(64, StateValue(0))
    seed_out = State(64, StateValue(0))

    mutations = []
    for i in range(10):
        mut_in = State(64, StateValue(1 << i))
        # SHL 2 means output is input << 2
        mut_out = State(64, StateValue(mut_in.state_value << 2))
        mutations.append((mut_in, mut_out))

    # Add a mutation that falls off the edge
    mutations.append((State(64, StateValue(1 << 63)), State(64, StateValue(0))))

    obs = Observation(
        (seed_in, seed_out),
        frozenset(mutations),
        'test_shl',
        Architecture.X86,
        [X86_REG_EAX(), X86_REG_EBX()],
    )

    assert is_mapped([obs]) is True
    assert classify_instruction([obs]) == InstructionCategory.MAPPED


def test_classify_mapped_add_fail():
    # Test that ADD is NOT mapped (multiple inputs trigger same output carry, or single input triggers multiple outputs)
    seed_in = State(64, StateValue(0))
    seed_out = State(64, StateValue(0))

    # If X_0 flips Y_0 and Z_0 flips Y_0 -> that's 2 inputs mapping to 1 output. Should fail is_mapped!
    mut1_in = State(64, StateValue(1))  # X_0 = 1
    mut1_out = State(64, StateValue(1))  # Y_0 = 1

    mut2_in = State(64, StateValue(1 << 32))  # Z_0 = 1
    mut2_out = State(64, StateValue(1))  # Y_0 = 1

    obs = Observation(
        (seed_in, seed_out),
        frozenset([(mut1_in, mut1_out), (mut2_in, mut2_out)]),
        'test_add',
        Architecture.X86,
        [X86_REG_EAX(), X86_REG_EBX()],
    )

    assert is_mapped([obs]) is False


def test_classify_mapped_carry_fail():
    # If 1 input causes 2 output flips, but a SECOND input ALSO causes a flip in those outputs
    # Examples: Arithmetic ADD triggers carry cascades.
    s_in = State(64, StateValue(0))
    s_out = State(64, StateValue(0))

    # Input 0 flips Output 0, 1 (like AL, BL where AL generates carry to BL)
    m_in1 = State(64, StateValue(1))
    m_out1 = State(64, StateValue(3))  # Y_0 and Y_1 flipped by X_0!

    # Input 1 flips Output 1
    m_in2 = State(64, StateValue(2))
    m_out2 = State(64, StateValue(2))  # Y_1 flipped by X_1!

    obs = Observation(
        (s_in, s_out),
        frozenset([(m_in1, m_out1), (m_in2, m_out2)]),
        'test_carry',
        Architecture.X86,
        [X86_REG_EAX(), X86_REG_EBX()],
    )

    assert is_mapped([obs]) is False


def test_classify_not_avalanche_arithmetic():
    # Simulate an arithmetic carry. A single input bit flip causes a long streak of 1s (contiguous)
    # Output XOR looks like 0x0000FFFF (16 straight bits)
    s_in = State(32, StateValue(0))
    s_out = State(32, StateValue(0))

    m_in = State(32, StateValue(1))  # 1 bit flip
    m_out = State(32, StateValue(0x0000FFFF))  # 16 bits flipped contiguously

    _obs = Observation(
        (s_in, s_out),
        frozenset([(m_in, m_out)]),
        'test_arithmetic_cascade',
        Architecture.X86,
        [X86_REG_EAX()],
    )

    # Needs a few mutations to bypass simple mapped check, mapped requires 1 to very specific mapping
    # Just checking if classify_instruction outputs "Avalanche" or not.
    # Actually, 1 input 16 output bits contiguously will fail Mapped, fail monotonic etc.
    # But let's add enough complexity to make it fall through to Unknown instead of Avalanche.
    m_in2 = State(32, StateValue(2))
    m_out2 = State(32, StateValue(0x0000FFFE))

    obs2 = Observation(
        (s_in, s_out),
        frozenset([(m_in, m_out), (m_in2, m_out2)]),
        'test_arithmetic_cascade_2',
        Architecture.X86,
        [X86_REG_EAX()],
    )

    res = classify_instruction([obs2])
    # Should not be avalanche because bits are contiguous
    assert res != InstructionCategory.AVALANCHE


def test_classify_avalanche():
    # Simulate dense entropy: 8 non-contiguous bits flipped
    s_in = State(32, StateValue(0))
    s_out = State(32, StateValue(0x0001))

    m_in1 = State(32, StateValue(1))  # bit 0
    m_out1 = State(32, StateValue(0x5554))  # out_xor = 0x5555 (overlaps bit 0)
    # bits fell: 0x0001, rose: 0x5554. Breaks monotonic.

    m_in2 = State(32, StateValue(2))  # bit 1
    m_out2 = State(32, StateValue(0xAAAA))  # out_xor = 0xAAAA | 1 = 0xAAAB (overlaps bit 0)
    # Both break Monotonic, out_xors overlap breaking Mapped unconditionally

    obs = Observation(
        (s_in, s_out),
        frozenset([(m_in1, m_out1), (m_in2, m_out2)]),
        'test_avalanche',
        Architecture.X86,
        [X86_REG_EAX()],
    )

    res = classify_instruction([obs])
    assert res == InstructionCategory.AVALANCHE
    assert 'EAX' in res


def test_classify_not_translatable_multiple_flips():
    # Simulates a scenario like 'imul' where a constant offset exists for the lowest bit,
    # but a single input bit flips multiple output bits in the destination register.
    # This must not be classified as Translatable.
    s_in = State(32, StateValue(0))
    s_out = State(32, StateValue(0))

    # Bit 0 flip causes Bit 1 AND Bit 2 to flip (e.g. out_xor = 6)
    m_in1 = State(32, StateValue(1))
    m_out1 = State(32, StateValue(6))  # 0b110 -> 2 bits flipped in EAX

    # Bit 1 flip causes Bit 2 AND Bit 3 to flip (e.g. out_xor = 12)
    m_in2 = State(32, StateValue(2))
    m_out2 = State(32, StateValue(12))  # 0b1100 -> 2 bits flipped in EAX

    obs = Observation(
        (s_in, s_out),
        frozenset([(m_in1, m_out1), (m_in2, m_out2)]),
        'test_imul_sim',
        Architecture.X86,
        [X86_REG_EAX()],
    )

    # It should correctly drop past mapping, monotonic, transportable, translatable.
    # We want to specifically ensure is_translatable rejects it.
    assert is_translatable([obs]) is False
