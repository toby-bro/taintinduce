import random

from taintinduce.classifier.categories import InstructionCategory
from taintinduce.instrumentation.instrument import instrument_instruction
from taintinduce.instrumentation.test_monotonic_simulation import C_and, m_replica
from taintinduce.isa.x86_registers import X86_REG_EAX, X86_REG_EBX
from taintinduce.state.state import Observation, State
from taintinduce.types import Architecture, StateValue


def test_instrument_monotonic_and_correctness():
    state_fmt = [X86_REG_EAX(), X86_REG_EBX()]

    seed_in = State(64, StateValue((0xFFFFFFFF << 32) | 0xFFFFFFFF))
    seed_out = State(64, StateValue((0xFFFFFFFF << 32) | 0xFFFFFFFF))

    mutated_ios = set()
    # flip EAX bit 0
    mut_eax = (0xFFFFFFFF << 32) | 0xFFFFFFFE
    mutated_ios.add(
        (
            State(64, StateValue(mut_eax)),
            State(64, StateValue(mut_eax)),
        ),
    )
    # flip EBX bit 0
    mut_ebx = (0xFFFFFFFE << 32) | 0xFFFFFFFF
    mut_out_ebx = (0xFFFFFFFE << 32) | 0xFFFFFFFE
    mutated_ios.add(
        (
            State(64, StateValue(mut_ebx)),
            State(64, StateValue(mut_out_ebx)),
        ),
    )

    obs = Observation((seed_in, seed_out), frozenset(mutated_ios), 'mock_and', Architecture.X86, state_fmt)
    obs2 = Observation(
        (
            State(64, StateValue((0x12345678 << 32) | 0x87654321)),
            State(64, StateValue((0x12345678 << 32) | (0x12345678 & 0x87654321))),
        ),
        frozenset(),
        'mock_and',
        Architecture.X86,
        state_fmt,
    )

    circuit = instrument_instruction([obs2, obs], InstructionCategory.MONOTONIC)

    for _ in range(50):
        # We test on 32-bit registers matching the circuit
        A_val = random.randint(0, 0xFFFFFFFF)
        B_val = random.randint(0, 0xFFFFFFFF)
        T_A = random.randint(0, 0xFFFFFFFF)
        T_B = random.randint(0, 0xFFFFFFFF)

        expected_taint = m_replica(A_val, B_val, T_A, T_B, C_and, width=32)

        input_values = {'EAX': A_val, 'EBX': B_val}
        input_taint = {'EAX': T_A, 'EBX': T_B}

        output_taint = circuit.evaluate(input_taint=input_taint, input_values=input_values)

        assert output_taint['EAX'] == expected_taint
