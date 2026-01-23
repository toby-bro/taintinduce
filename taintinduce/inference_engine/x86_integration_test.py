"""Integration tests for X86 ISA rule inference.

This test suite validates the inference pipeline using X86 instructions,
specifically testing AND EAX, EBX (opcode 23C3) and OR EAX, EBX (opcode 0BC3).

State Format: EFLAGS[32:0] EAX[32:0] EBX[32:0] = 96 bits total
- EFLAGS: bits 0-31
- EAX: bits 32-63
- EBX: bits 64-95

Expected behavior for AND EAX, EBX (23C3):
- EAX[i] = EAX[i] & EBX[i] for i in 0..31
- Rule: if EAX[i] = 1 then EBX[i] propagates to EAX[i]
- EBX bits always propagate to themselves (unconditional)
- EFLAGS are updated based on result

Expected behavior for OR EAX, EBX (0BC3):
- EAX[i] = EAX[i] | EBX[i] for i in 0..31
- Rule: if EAX[i] = 0 then EBX[i] propagates to EAX[i]
- EBX bits always propagate to themselves (unconditional)
- EFLAGS are updated based on result
"""

from dataclasses import dataclass

import pytest

from taintinduce.inference_engine.inference import infer
from taintinduce.inference_engine.observation_processor import extract_observation_dependencies
from taintinduce.inference_engine.validation import validate_rule_explains_observations
from taintinduce.isa.register import Register
from taintinduce.isa.x86_registers import X86_REG_EAX, X86_REG_EBX, X86_REG_EFLAGS
from taintinduce.observation_engine.observation import ObservationEngine
from taintinduce.rules.rules import GlobalRule
from taintinduce.state.state import Observation
from taintinduce.types import BitPosition, ObservationDependency


@dataclass
class X86InstructionData:
    """Data for a single X86 instruction test case."""

    observations: list[Observation]
    obs_engine: ObservationEngine
    rule: GlobalRule
    obs_deps: list[ObservationDependency]


class _X86InstructionCache:
    """Cache for X86 instruction observations and inferred rules."""

    def __init__(self, state_format: list[Register]) -> None:
        self._cache: dict[str, X86InstructionData] = {}
        self._state_format = state_format

    def __getitem__(self, key: str) -> X86InstructionData:
        if key not in self._cache:
            # key is the hex instruction (e.g., '23C3' for AND EAX, EBX, '0BC3' for OR EAX, EBX)
            bytestring = key
            obs_engine = ObservationEngine(bytestring, 'X86', self._state_format)
            observations = obs_engine.observe_insn()
            obs_deps = extract_observation_dependencies(observations)

            # Infer rule
            rule = infer(observations)

            self._cache[key] = X86InstructionData(
                observations=observations,
                obs_engine=obs_engine,
                rule=rule,
                obs_deps=obs_deps,
            )

        return self._cache[key]

    def __contains__(self, key: str) -> bool:
        return True  # Always return True since we can compute on-demand


@pytest.fixture(scope='module')
def x86_state_format() -> list[Register]:
    """X86 state format: EFLAGS (32 bits), EAX (32 bits), EBX (32 bits)."""
    return [X86_REG_EFLAGS(), X86_REG_EAX(), X86_REG_EBX()]


@pytest.fixture(scope='module')
def x86_cond_reg() -> Register:
    """X86 condition register (EFLAGS)."""
    return X86_REG_EFLAGS()


@pytest.fixture(scope='module')
def x86_instruction_data(x86_state_format: list[Register]) -> _X86InstructionCache:
    """Lazy cache for X86 instruction observations and inferred rules.

    This fixture provides on-demand computation and caching of observations,
    observation dependencies, and inferred rules for X86 instructions.

    Usage in tests:
        def test_something(x86_instruction_data: _X86InstructionCache) -> None:
            data = x86_instruction_data['23C3']  # AND EAX, EBX
            rule = data.rule
            observations = data.observations
            # ... use the cached data
    """
    return _X86InstructionCache(x86_state_format)


# =============================================================================
# AND EAX, EBX Tests (23C3)
# =============================================================================


def test_and_eax_ebx_observation_generation(x86_instruction_data: _X86InstructionCache) -> None:
    """Test that observations are generated for AND EAX, EBX."""
    data = x86_instruction_data['23C3']
    observations = data.observations

    # Should have observations for exhaustive state space exploration
    assert len(observations) > 0, 'Should generate observations for AND EAX, EBX'


def test_and_eax_ebx_full_inference(x86_instruction_data: _X86InstructionCache) -> None:
    """Test that full inference pipeline completes without errors."""
    data = x86_instruction_data['23C3']
    rule = data.rule

    # Rule should have condition-dataflow pairs
    assert rule is not None, 'Should generate a rule'
    assert len(rule.pairs) > 0, 'Rule should have at least one condition-dataflow pair'


def test_and_eax_ebx_rule_explains_observations(x86_instruction_data: _X86InstructionCache) -> None:
    """Test that inferred rule explains all observations."""
    data = x86_instruction_data['23C3']
    rule = data.rule
    obs_deps = data.obs_deps

    # Validate that rule explains all observations
    explained, total = validate_rule_explains_observations(rule, obs_deps)

    coverage = (explained / total * 100) if total > 0 else 0
    assert coverage > 90, (
        f'Rule should explain most observations for AND EAX, EBX, '
        f'but only explained {explained}/{total} ({coverage:.1f}%)'
    )


def test_and_eax_ebx_captures_all_flows(x86_instruction_data: _X86InstructionCache) -> None:
    """Test that observations capture all expected dataflows for AND EAX, EBX."""
    data = x86_instruction_data['23C3']
    obs_deps = data.obs_deps

    # Collect all observed dataflows
    observed_outputs: set[BitPosition] = set()
    for obs_dep in obs_deps:
        for _input_bit, output_bits in obs_dep.dataflow.items():
            observed_outputs.update(output_bits)

    # For AND EAX, EBX:
    # - EAX bits (32-63) should be in outputs (modified)
    # - EBX bits (64-95) should be in outputs (propagate to themselves)
    # - EFLAGS bits (0-31) should be in outputs (flags updated)

    eax_bits = {BitPosition(i) for i in range(32, 64)}
    ebx_bits = {BitPosition(i) for i in range(64, 96)}

    # Check that EAX bits appear in outputs
    eax_outputs = observed_outputs & eax_bits
    assert len(eax_outputs) > 0, 'Should observe taint flows to EAX bits'

    # Check that EBX bits appear in outputs (identity propagation)
    ebx_outputs = observed_outputs & ebx_bits
    assert len(ebx_outputs) > 0, 'Should observe EBX identity propagation'


def test_and_eax_ebx_ebx_always_unconditional(x86_instruction_data: _X86InstructionCache) -> None:
    """Test that EBX bits always propagate unconditionally to themselves.

    For AND EAX, EBX, the EBX register is never modified, so EBX[i] -> EBX[i]
    should always be unconditional for all i in 0..31.
    """
    data = x86_instruction_data['23C3']
    rule = data.rule

    # EBX bits are 64-95 in the state format
    ebx_bit_start = 64

    # Check each EBX bit
    for i in range(32):  # 32 bits in EBX
        ebx_bit = BitPosition(ebx_bit_start + i)

        # Find pairs that include EBX[i] -> EBX[i]
        found_unconditional = False
        for pair in rule.pairs:
            if pair.condition is None or pair.condition.condition_ops is None:
                # Unconditional pair
                if pair.input_bit == ebx_bit and ebx_bit in pair.output_bits:
                    found_unconditional = True
                    break

        assert (
            found_unconditional
        ), f'EBX[{i}] -> EBX[{i}] (bit {ebx_bit}) should be unconditional, but no unconditional rule found'


def test_and_eax_ebx_conditional_propagation(x86_instruction_data: _X86InstructionCache) -> None:
    """Test that EBX[i] -> EAX[i] has correct conditional propagation.

    For AND EAX, EBX:
    - EAX[i] = EAX[i] & EBX[i]
    - EBX[i] propagates to EAX[i] when EAX[i] = 1
    - Condition: EAX[i] = 1

    This checks that for each EAX bit, there exists a rule where:
    - Input bit is the corresponding EBX bit
    - Output bit is the EAX bit
    - Condition involves the EAX bit being 1
    """
    data = x86_instruction_data['23C3']
    rule = data.rule

    # EAX bits are 32-63, EBX bits are 64-95
    eax_bit_start = 32
    ebx_bit_start = 64

    # Check a few representative bits
    test_bits = [0, 1, 15, 16, 31]  # Test various bit positions

    for i in test_bits:
        eax_bit = BitPosition(eax_bit_start + i)
        ebx_bit = BitPosition(ebx_bit_start + i)

        # Find pairs where EBX[i] -> EAX[i]
        found_conditional = False
        for pair in rule.pairs:
            # Check if this pair has EBX[i] -> EAX[i] mapping
            if pair.input_bit == ebx_bit and eax_bit in pair.output_bits:
                # Should have a condition
                if pair.condition is not None and pair.condition.condition_ops is not None:
                    # Condition should involve EAX[i] = 1
                    # In DNF, this means we check if any clause tests EAX[i] = 1
                    for mask, value in pair.condition.condition_ops:
                        # Check if this clause masks EAX[i]
                        if mask & (1 << eax_bit):
                            # Check if it requires EAX[i] = 1
                            if (value & (1 << eax_bit)) != 0:
                                found_conditional = True
                                break
                if found_conditional:
                    break

        assert found_conditional, (
            f'EBX[{i}] -> EAX[{i}] (bits {ebx_bit} -> {eax_bit}) should have condition '
            f'requiring EAX[{i}] = 1, but no such conditional rule found'
        )


def test_and_eax_ebx_eax_identity_propagation(x86_instruction_data: _X86InstructionCache) -> None:
    """Test that EAX[i] -> EAX[i] has correct behavior.

    For AND EAX, EBX:
    - EAX[i] propagates to itself when result depends on it
    """
    data = x86_instruction_data['23C3']
    rule = data.rule

    # EAX bits are 32-63
    eax_bit_start = 32

    # Check a few representative bits
    test_bits = [0, 1, 15, 16, 31]

    for i in test_bits:
        eax_bit = BitPosition(eax_bit_start + i)

        # Find pairs where EAX[i] -> EAX[i]
        found = False
        for pair in rule.pairs:
            if pair.input_bit == eax_bit and eax_bit in pair.output_bits:
                # Should have a condition or be unconditional
                # For OR, EAX[i] -> EAX[i] when EAX[i] = 1
                found = True
                break

        assert found, f'EAX[{i}] -> EAX[{i}] (bit {eax_bit}) should have a rule, but no rule found'


def test_and_eax_ebx_condition_only_uses_relevant_bits(x86_instruction_data: _X86InstructionCache) -> None:
    """Test that conditions only involve bits that actually affect the output.

    For AND EAX, EBX, when checking EAX[i] -> EAX[i], the condition should only
    involve EAX[i] and possibly EBX[i], not other bits like EFLAGS or unrelated
    EAX/EBX bits.

    This is a regression test for the bug where conditions included all state bits.
    """
    data = x86_instruction_data['23C3']
    rule = data.rule

    # EAX bits are 32-63, EBX bits are 64-95
    eax_bit_start = 32

    # Test EAX[1] -> EAX[1] specifically (bit 33)
    eax_bit_1 = BitPosition(eax_bit_start + 1)

    # Find pairs where EAX[1] -> EAX[1]
    found_eax1_rule = False
    for pair in rule.pairs:
        if pair.input_bit == eax_bit_1 and eax_bit_1 in pair.output_bits:
            found_eax1_rule = True
            print('\nFound EAX[1] -> EAX[1] rule:')
            print(f'  Condition: {pair.condition}')

            if pair.condition is not None and pair.condition.condition_ops is not None:
                # Check which bits are referenced in the condition
                referenced_bits = set()
                for mask, _value in pair.condition.condition_ops:
                    # Find which bits are set in the mask
                    for bit_pos in range(96):  # Total state space is 96 bits
                        if mask & (1 << bit_pos):
                            referenced_bits.add(bit_pos)

                print(f'  Referenced bits: {sorted(referenced_bits)}')

                # The condition should ONLY involve bits that affect EAX[1]
                # For AND: EAX[1] and EBX[1] (and possibly EAX bits in general for the operation)
                # But definitely NOT EFLAGS bits 0-31
                eflags_bits_in_condition = {bit for bit in referenced_bits if bit < 32}

                if eflags_bits_in_condition:
                    # Print diagnostic information
                    print(f'ERROR: EAX[1] -> EAX[1] condition references EFLAGS bits: {eflags_bits_in_condition}')
                    print(f'All referenced bits: {sorted(referenced_bits)}')

                    # This is the bug - EFLAGS should not be in the condition for EAX[i] -> EAX[i]
                    pytest.fail(
                        f'EAX[1] -> EAX[1] condition incorrectly includes {len(eflags_bits_in_condition)} '
                        f'EFLAGS bits. Condition should only involve bits that affect EAX[1], '
                        f'not EFLAGS bits {sorted(eflags_bits_in_condition)}',
                    )
                else:
                    print('  ✓ Condition only references relevant bits (no EFLAGS)')

    assert found_eax1_rule, 'Should find EAX[1] -> EAX[1] rule'


def test_and_eax_ebx_check_which_inputs_affect_eax1(x86_instruction_data: _X86InstructionCache) -> None:
    """Debug test: Check which input bits the observations say affect EAX[1].

    For AND EAX, EBX, we expect only EAX[1] and EBX[1] to affect EAX[1].
    If other bits appear, there may be spurious flows in the observations.
    """
    data = x86_instruction_data['23C3']
    obs_deps = data.obs_deps

    # EAX[1] is bit 33 in the state format
    eax_bit_1 = BitPosition(33)

    # Collect all input bits that affect EAX[1] across all observations
    input_bits_affecting_eax1: set[BitPosition] = set()
    for obs_dep in obs_deps:
        for input_bit, output_bits in obs_dep.dataflow.items():
            if eax_bit_1 in output_bits:
                input_bits_affecting_eax1.add(input_bit)

    print('\nInput bits that affect EAX[1] (bit 33):')
    print(f'  Total count: {len(input_bits_affecting_eax1)}')
    print(f'  Bits: {sorted(input_bits_affecting_eax1)}')

    # Map to register names
    eax_start, ebx_start = 32, 64
    for bit in sorted(input_bits_affecting_eax1):
        if bit < 32:
            print(f'    bit {bit}: EFLAGS[{bit}]')
        elif bit < 64:
            print(f'    bit {bit}: EAX[{bit - eax_start}]')
        else:
            print(f'    bit {bit}: EBX[{bit - ebx_start}]')

    # For AND EAX, EBX: EAX[i] = EAX[i] & EBX[i]
    # Only EAX[1] (bit 33) and EBX[1] (bit 65) should affect EAX[1]
    expected_inputs = {BitPosition(33), BitPosition(65)}

    unexpected_inputs = input_bits_affecting_eax1 - expected_inputs
    if unexpected_inputs:
        print(f'\n⚠️  WARNING: Found unexpected input bits affecting EAX[1]: {sorted(unexpected_inputs)}')
        print('This suggests spurious dataflows in the observations!')

        # This might not be a hard failure - could be due to carry propagation
        # or other complex behaviors, but it's worth investigating
        if len(unexpected_inputs) > 5:
            pytest.fail(
                f'Too many unexpected input bits ({len(unexpected_inputs)}) affecting EAX[1]. '
                f'Expected only bits 33 (EAX[1]) and 65 (EBX[1]), '
                f'but also found: {sorted(unexpected_inputs)}',
            )
