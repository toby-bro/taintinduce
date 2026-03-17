from taintinduce.classifier.categories import InstructionCategory
from taintinduce.instrumentation.instrument import instrument_instruction
from taintinduce.isa.x86_registers import X86_REG_EAX, X86_REG_EBX
from taintinduce.state.state import Observation, State
from taintinduce.types import Architecture, StateValue


def test_instrument_mapped() -> None:
    state_fmt = [X86_REG_EAX(), X86_REG_EBX()]

    # Simulating mov eax, ebx
    seed_in = State(64, StateValue(0))
    seed_out = State(64, StateValue(0))

    # ebx is bits 32-63
    mut_in = State(64, StateValue(1 << 32))  # flip bit 0 of ebx
    mut_out = State(64, StateValue((1 << 32) | 1))  # flips bit 0 of ebx (unmodified) + bit 0 of eax

    obs = Observation((seed_in, seed_out), frozenset([(mut_in, mut_out)]), 'mock_mov', Architecture.X86, state_fmt)

    circuit = instrument_instruction([obs], InstructionCategory.MAPPED)
    assert len(circuit.assignments) == 2

    # We should see EBX -> EBX (unmodified pass through) and EBX -> EAX (the mapped change)
    output_str = str(circuit)
    assert 'T_EBX[0] = T_EBX[0]' in output_str
    assert 'T_EAX[0] = T_EBX[0]' in output_str


def test_instrument_monotonic() -> None:
    state_fmt = [X86_REG_EAX(), X86_REG_EBX()]

    # Simulating or eax, ebx
    seed_in = State(64, StateValue(0))
    seed_out = State(64, StateValue(0))

    mut_in = State(64, StateValue(1 << 32))  # bit 0 of ebx
    mut_out = State(64, StateValue((1 << 32) | 1))  # modifies ebx unmodified + eax modified

    obs = Observation((seed_in, seed_out), frozenset([(mut_in, mut_out)]), 'mock_or', Architecture.X86, state_fmt)

    circuit = instrument_instruction([obs], InstructionCategory.MONOTONIC)
    output_str = str(circuit)

    assert 'T_EAX[0] =' in output_str
    assert 'C_mock_or[EAX[0:0]]' in output_str


def test_instrument_monotonic_16_bit() -> None:
    """Verify that a 16-bit operation only produces [15:0] constraints and leaves [31:16] alone"""
    state_fmt = [X86_REG_EAX(), X86_REG_EBX()]

    # Simulating 16-bit AND ax, bx
    seed_in = State(64, StateValue(0))
    seed_out = State(64, StateValue(0))

    obs_mutations = []
    # Test random bit flips inside the 16 bit range
    for bit in [0, 7, 15]:
        # flip bit `bit` of ebx
        mut_in = State(64, StateValue(1 << (32 + bit)))
        # Output propagates only to the corresponding EAX bit `bit` (and ebx stays same)
        mut_out = State(64, StateValue((1 << (32 + bit)) | (1 << bit)))
        obs_mutations.append((mut_in, mut_out))

        # also need EAX flips for monotonic inference if we want a 2-variable op
        mut_in_a = State(64, StateValue(1 << bit))
        mut_out_a = State(64, StateValue(1 << bit))
        obs_mutations.append((mut_in_a, mut_out_a))

    obs = Observation((seed_in, seed_out), frozenset(obs_mutations), 'mock_and_16', Architecture.X86, state_fmt)

    circuit = instrument_instruction([obs], InstructionCategory.MONOTONIC)
    output_str = str(circuit)

    assert 'T_EAX[15:0]' in output_str, f'Should target just 15:0 but got: {output_str}'
    assert 'T_EAX[31:0]' not in output_str
