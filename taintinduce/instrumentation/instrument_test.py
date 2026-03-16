from taintinduce.classifier.categories import InstructionCategory
from taintinduce.instrumentation.instrument import instrument_instruction
from taintinduce.isa.x86_registers import X86_REG_EAX, X86_REG_EBX
from taintinduce.state.state import Observation, State
from taintinduce.types import Architecture, StateValue


def test_instrument_mapped():
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
    assert 'T_EBX[31:0] = T_EBX[31:0]' in output_str
    assert 'T_EAX[31:0] = T_EBX[31:0]' in output_str


def test_instrument_monotonic():
    state_fmt = [X86_REG_EAX(), X86_REG_EBX()]

    # Simulating or eax, ebx
    seed_in = State(64, StateValue(0))
    seed_out = State(64, StateValue(0))

    mut_in = State(64, StateValue(1 << 32))  # bit 0 of ebx
    mut_out = State(64, StateValue((1 << 32) | 1))  # modifies ebx unmodified + eax modified

    obs = Observation((seed_in, seed_out), frozenset([(mut_in, mut_out)]), 'mock_or', Architecture.X86, state_fmt)

    circuit = instrument_instruction([obs], InstructionCategory.MONOTONIC)
    output_str = str(circuit)

    assert 'T_EAX[31:0] = T_EBX[31:0]' in output_str
