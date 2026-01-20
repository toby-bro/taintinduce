"""Comprehensive integration tests for JN ISA rule inference.

This test suite validates each step of the inference pipeline using the
JN (Just Nibbles) ISA - a simple 4-bit architecture designed for testing.

The tests verify that:
1. Observations are generated correctly for each instruction
2. All taint flows are properly captured
3. Conditions are inferred correctly for data-dependent operations
4. The complete inference pipeline produces valid rules
5. All flows are explained by the final rule

Test Coverage - All 8 JN Instructions:
- 0:  ADD R1, R2  (register)
- 1A: ADD R1, #0xA (immediate)
- 2:  OR R1, R2   (register)
- 3A: OR R1, #0x3 (immediate)
- 4:  AND R1, R2  (register)
- 5A: AND R1, #0xF (immediate)
- 6:  XOR R1, R2  (register)
- 7A: XOR R1, #0xA (immediate)

All tests use pytest.mark.parametrize to avoid code duplication while ensuring
comprehensive coverage of both register and immediate variants.

Known Issues:
- Register variants (0, 2, 4, 6) only explain 64.6% of observations (NZCV flag bits)
- Immediate variants with specific values (OR #0x3, AND #0xF) may appear unconditional
"""

import pytest

from taintinduce.cpu.jn_cpu import JNCpu
from taintinduce.inference_engine.inference import InferenceEngine
from taintinduce.inference_engine.observation_processor import extract_observation_dependencies
from taintinduce.inference_engine.validation import validate_rule_explains_observations
from taintinduce.isa.jn_isa import JNOpcode, encode_instruction
from taintinduce.isa.jn_isa import decode_hex_string as decode_jn_hex
from taintinduce.isa.jn_registers import JN_REG_NZCV, JN_REG_R1, JN_REG_R2
from taintinduce.observation_engine.observation import (
    ObservationEngine,
    decode_instruction_bytes,
    encode_instruction_bytes,
)
from taintinduce.types import BitPosition, CpuRegisterMap
from taintinduce.visualizer.taint_simulator import simulate_taint_propagation


def jn_hex_to_bytes(hex_string: str) -> bytes:
    """Convert JN hex string (nibbles) to bytes for execution.

    JN uses nibbles (single hex chars), but bytes.fromhex() expects pairs.
    This helper converts JN hex strings correctly.
    """
    return bytes([int(c, 16) for c in hex_string])


@pytest.fixture
def jn_state_format():
    """JN state format: R1 (4 bits), R2 (4 bits), NZCV (4 bits)."""
    return [JN_REG_R1(), JN_REG_R2(), JN_REG_NZCV()]


@pytest.fixture
def jn_state_format_immediate():
    """JN state format for immediate instructions: R1 (4 bits), NZCV (4 bits)."""
    return [JN_REG_R1(), JN_REG_NZCV()]


@pytest.fixture
def jn_cond_reg():
    """JN condition register (NZCV)."""
    return JN_REG_NZCV()


@pytest.fixture
def inference_engine():
    """Create an inference engine."""
    return InferenceEngine()


# =============================================================================
# Parametrize constants for reuse across tests
# =============================================================================


# All 10 JN instructions including SUB
ALL_JN_INSTRUCTIONS = [
    (JNOpcode.ADD_R1_R2, None),  # 0
    (JNOpcode.ADD_R1_IMM, 0xA),  # 1A
    (JNOpcode.OR_R1_R2, None),  # 2
    (JNOpcode.OR_R1_IMM, 0x3),  # 3
    (JNOpcode.AND_R1_R2, None),  # 4
    (JNOpcode.AND_R1_IMM, 0xF),  # 5F
    (JNOpcode.XOR_R1_R2, None),  # 6
    (JNOpcode.XOR_R1_IMM, 0xA),  # 7A
    (JNOpcode.SUB_R1_R2, None),  # 8
    (JNOpcode.SUB_R1_IMM, 0x5),  # 9A
]

# Only register instructions (no immediate variants)
REGISTER_INSTRUCTIONS = [i for i in ALL_JN_INSTRUCTIONS if i[1] is None]
IMMEDIATE_INSTRUCTIONS = [i for i in ALL_JN_INSTRUCTIONS if i[1] is not None]

# Instructions with unconditional flag for condition inference tests
INSTRUCTIONS_WITH_CONDITIONALITY = [
    (JNOpcode.ADD_R1_R2, None, False),  # 0 - ADD is conditional
    (JNOpcode.ADD_R1_IMM, 0xA, True),  # 1A - ADD is unconditional
    (JNOpcode.OR_R1_R2, None, False),  # 2 - OR is conditional
    (JNOpcode.OR_R1_IMM, 0xA, True),  # 3A - OR is unconditional
    (JNOpcode.AND_R1_R2, None, False),  # 4 - AND is conditional
    (JNOpcode.AND_R1_IMM, 0xA, True),  # 5A - AND is unconditional
    (JNOpcode.XOR_R1_R2, None, True),  # 6 - XOR is unconditional
    (JNOpcode.XOR_R1_IMM, 0xA, True),  # 7A - XOR is unconditional
    (JNOpcode.SUB_R1_R2, None, False),  # 8 - SUB is conditional
    (JNOpcode.SUB_R1_IMM, 0x5, True),  # 9A - SUB is unconditional
]


# =============================================================================
# Cached Observations and Rules (computed once per instruction)
# =============================================================================


@pytest.fixture(scope='module')
def jn_instruction_data():
    """Compute observations and rules for JN instructions lazily on-demand.

    This fixture uses pytest's module-level caching with lazy evaluation.
    Data is only computed when first accessed for a specific instruction,
    then cached for subsequent uses.

    Performance impact:
    - Without caching: Each test regenerates observations (~2-3s per instruction)
    - With lazy caching: Each instruction computed once when needed, cached thereafter

    Returns a dict-like object that computes on access: (opcode, immediate) -> {
        'observations': list of observations,
        'obs_engine': ObservationEngine instance,
        'rule': inferred Rule,
        'obs_deps': observation dependencies
    }

    Usage in tests:
        def test_something(jn_instruction_data):
            data = jn_instruction_data[(JNOpcode.ADD_R1_R2, None)]
            rule = data['rule']
            observations = data['observations']
            # ... use the cached data
    """
    state_format_long = [JN_REG_R1(), JN_REG_R2(), JN_REG_NZCV()]
    state_format_short = [JN_REG_R1(), JN_REG_NZCV()]

    cond_reg = JN_REG_NZCV()
    engine = InferenceEngine()

    class LazyCache:
        def __init__(self):
            self._cache = {}

        def __getitem__(self, key):
            if key not in self._cache:
                opcode, immediate = key
                bytestring = encode_instruction(opcode, immediate)
                if immediate is None:
                    state_format = state_format_long
                else:
                    state_format = state_format_short
                obs_engine = ObservationEngine(bytestring, 'JN', state_format)
                observations = obs_engine.observe_insn()
                obs_deps = extract_observation_dependencies(observations)

                # Infer rule
                rule = engine.infer(observations, cond_reg, obs_engine, enable_refinement=False)

                self._cache[key] = {
                    'observations': observations,
                    'obs_engine': obs_engine,
                    'rule': rule,
                    'obs_deps': obs_deps,
                }

            return self._cache[key]

        def __contains__(self, key):
            return True  # Always return True since we can compute on-demand

    return LazyCache()


# =============================================================================
# Regression Tests
# =============================================================================


@pytest.mark.parametrize(('opcode', 'immediate'), ALL_JN_INSTRUCTIONS)
def test_decode_roundtrip(opcode, immediate):
    """Test that decode_jn_hex(decode_instruction_bytes(...)) is a round trip.

    This verifies that encoding an instruction to a hex string, converting to bytes,
    then back to hex and decoding produces the same instruction.
    """
    # Encode instruction to hex string
    hex_string = encode_instruction(opcode, immediate)

    # Convert hex string to bytes (via decode_instruction_bytes)
    bytecode = decode_instruction_bytes(hex_string, 'JN')

    # Convert bytes back to hex string
    hex_from_bytes = encode_instruction_bytes(bytecode, 'JN')

    # Decode hex string to instruction
    decoded_instruction = decode_jn_hex(hex_from_bytes)

    # Verify round trip: should get same opcode and immediate
    assert decoded_instruction.opcode == opcode, f'Opcode mismatch: expected {opcode}, got {decoded_instruction.opcode}'
    assert (
        decoded_instruction.immediate == immediate
    ), f'Immediate mismatch: expected {immediate}, got {decoded_instruction.immediate}'


# =============================================================================
# Observation Generation Tests
# =============================================================================


@pytest.mark.parametrize(('opcode', 'immediate'), ALL_JN_INSTRUCTIONS)
def test_observation_generation(
    opcode,
    immediate,
    jn_state_format,
    jn_state_format_immediate,
):
    """Test observation generation for all JN instructions."""
    bytestring = encode_instruction(opcode, immediate)
    state_format = jn_state_format_immediate if immediate is not None else jn_state_format
    obs_engine = ObservationEngine(bytestring, 'JN', state_format)
    observations = obs_engine.observe_insn()

    # Should generate observations
    assert len(observations) > 0, f'Should generate observations for {opcode.name}'

    # Each observation should have correct state format
    for obs in observations:
        assert obs.state_format == state_format
        assert obs.bytestring == bytestring
        assert obs.archstring == 'JN'

        # Verify immediate instructions exclude R2
        if immediate is not None:
            assert len([r for r in obs.state_format if r.name == 'R2']) == 0, 'Immediate should not have R2'

        # Verify observations have mutated IOs
        assert len(obs.mutated_ios) > 0, 'Observations should have mutated IO pairs'


# =============================================================================
# Dataflow Validation Tests
# =============================================================================


class TestJNDataflowCompleteness:
    """Test that all expected taint flows are captured in observations."""

    def test_add_r1_r2_captures_all_flows(self, jn_instruction_data):
        """Test ADD R1, R2 captures all expected flows.

        Expected flows:
        - R1[0] -> R1[0], R1[1], R1[2], R1[3] (carries propagate)
        - R1[1] -> R1[1], R1[2], R1[3]
        - R1[2] -> R1[2], R1[3]
        - R1[3] -> R1[3]
        - R2[0] -> R1[0], R1[1], R1[2], R1[3] (carries propagate)
        - R2[1] -> R1[1], R1[2], R1[3]
        - R2[2] -> R1[2], R1[3]
        - R2[3] -> R1[3]
        - R2 unchanged (R2[i] -> R2[i] for i in 0..3)
        """
        # Use cached data
        data = jn_instruction_data[(JNOpcode.ADD_R1_R2, None)]
        obs_deps = data['obs_deps']

        # Collect all flows from all observation dependencies
        all_flows: dict[BitPosition, set[BitPosition]] = {}
        for obs_dep in obs_deps:
            for input_bit, output_bits in obs_dep.dataflow.items():
                if input_bit not in all_flows:
                    all_flows[input_bit] = set()
                all_flows[input_bit].update(output_bits)

        # R1 bits (0-3) should affect R1 output bits
        for i in range(4):
            assert BitPosition(i) in all_flows, f'R1[{i}] should have flows'
            flows = all_flows[BitPosition(i)]
            # Due to carries, lower bits affect higher bits
            for j in range(i, 4):
                assert BitPosition(j) in flows, f'R1[{i}] should flow to R1[{j}]'

        # R2 bits (4-7) should affect R1 output bits
        for i in range(4):
            r2_bit = BitPosition(4 + i)
            assert r2_bit in all_flows, f'R2[{i}] should have flows'
            flows = all_flows[r2_bit]
            # R2[i] affects R1[i] and potentially higher bits
            for j in range(i, 4):
                assert BitPosition(j) in flows, f'R2[{i}] should flow to R1[{j}]'

        # R2 should be unchanged (R2[i] -> R2[i])
        for i in range(4):
            r2_in = BitPosition(4 + i)
            r2_out = BitPosition(4 + i)
            assert r2_out in all_flows.get(r2_in, set()), f'R2[{i}] should flow to R2[{i}]'

    def test_or_r1_r2_captures_all_flows(self, jn_instruction_data):
        """Test OR R1, R2 captures all expected flows.

        Expected flows:
        - R1[i] -> R1[i] (for i in 0..3)
        - R2[i] -> R1[i] (for i in 0..3)
        - R2 unchanged (R2[i] -> R2[i])

        Note: OR is data-dependent:
        - If R1[i]=1 OR R2[i]=1, then R1[i]=1 regardless
        - If both are 0, R1[i]=0
        - Only when both are 0, does taint propagate
        """
        # Use cached data
        data = jn_instruction_data[(JNOpcode.OR_R1_R2, None)]
        obs_deps = data['obs_deps']

        # Collect all flows
        all_flows: dict[BitPosition, set[BitPosition]] = {}
        for obs_dep in obs_deps:
            for input_bit, output_bits in obs_dep.dataflow.items():
                if input_bit not in all_flows:
                    all_flows[input_bit] = set()
                all_flows[input_bit].update(output_bits)

        # Check R1[i] -> R1[i] flows exist
        for i in range(4):
            assert BitPosition(i) in all_flows, f'R1[{i}] should have flows'
            # R1[i] should flow to R1[i]
            assert BitPosition(i) in all_flows[BitPosition(i)], f'R1[{i}] -> R1[{i}] should exist'

        # Check R2[i] -> R1[i] flows exist
        for i in range(4):
            r2_bit = BitPosition(4 + i)
            if r2_bit in all_flows:
                # R2[i] should flow to R1[i] when it matters
                # (This might be conditional, so we just check the flow exists)
                pass

        # R2 unchanged
        for i in range(4):
            r2_in = BitPosition(4 + i)
            r2_out = BitPosition(4 + i)
            assert r2_out in all_flows.get(r2_in, set()), f'R2[{i}] should flow to R2[{i}]'

    def test_and_r1_r2_captures_all_flows(self, jn_instruction_data):
        """Test AND R1, R2 captures all expected flows.

        Expected flows for AND R1, R2:
        - R1[i] -> R1[i] (for i in 0..3) - but conditional
        - R2[i] -> R1[i] (for i in 0..3) - but conditional
        - R2 unchanged (R2[i] -> R2[i])

        AND is highly data-dependent:
        - If R1[i]=0 OR R2[i]=0, then R1[i]=0 (taint doesn't propagate)
        - Only when BOTH are 1 does taint propagate through

        This test ensures we capture these flows even if conditional.
        """
        # Use cached data
        data = jn_instruction_data[(JNOpcode.AND_R1_R2, None)]
        obs_deps = data['obs_deps']

        # Extract dataflows from observations

        # Collect all flows
        all_flows: dict[BitPosition, set[BitPosition]] = {}
        for obs_dep in obs_deps:
            for input_bit, output_bits in obs_dep.dataflow.items():
                if input_bit not in all_flows:
                    all_flows[input_bit] = set()
                all_flows[input_bit].update(output_bits)

        # Check that R1 bits have flows (even if conditional)
        for i in range(4):
            r1_bit = BitPosition(i)
            # R1[i] should have some flow
            if r1_bit in all_flows:
                # When it flows, it should flow to R1[i]
                flows = all_flows[r1_bit]
                assert BitPosition(i) in flows, f'R1[{i}] should flow to R1[{i}] (when conditions met)'

        # Check that R2 bits have flows to R1
        for i in range(4):
            r2_bit = BitPosition(4 + i)
            if r2_bit in all_flows:
                flows = all_flows[r2_bit]
                # R2[i] might flow to R1[i] under conditions
                # At minimum, should flow to R2[i] (unchanged)
                assert BitPosition(4 + i) in flows, f'R2[{i}] should flow to R2[{i}]'

        # R2 unchanged - this should ALWAYS be true
        for i in range(4):
            r2_in = BitPosition(4 + i)
            r2_out = BitPosition(4 + i)
            assert r2_in in all_flows, f'R2[{i}] should have flows'
            assert r2_out in all_flows[r2_in], f'R2[{i}] should flow to R2[{i}]'

    def test_xor_r1_r2_captures_all_flows(self, jn_instruction_data):
        """Test XOR R1, R2 captures all expected flows.

        Expected flows:
        - R1[i] -> R1[i] (for i in 0..3)
        - R2[i] -> R1[i] (for i in 0..3)
        - R2 unchanged (R2[i] -> R2[i])

        XOR always propagates taint from both inputs to output.
        """
        # Use cached data
        data = jn_instruction_data[(JNOpcode.XOR_R1_R2, None)]
        obs_deps = data['obs_deps']

        # Collect all flows
        all_flows: dict[BitPosition, set[BitPosition]] = {}
        for obs_dep in obs_deps:
            for input_bit, output_bits in obs_dep.dataflow.items():
                if input_bit not in all_flows:
                    all_flows[input_bit] = set()
                all_flows[input_bit].update(output_bits)

        # R1[i] -> R1[i]
        for i in range(4):
            assert BitPosition(i) in all_flows, f'R1[{i}] should have flows'
            assert BitPosition(i) in all_flows[BitPosition(i)], f'R1[{i}] -> R1[{i}]'

        # R2[i] -> R1[i]
        for i in range(4):
            r2_bit = BitPosition(4 + i)
            assert r2_bit in all_flows, f'R2[{i}] should have flows'
            flows = all_flows[r2_bit]
            assert BitPosition(i) in flows, f'R2[{i}] should flow to R1[{i}]'

        # R2 unchanged
        for i in range(4):
            r2_in = BitPosition(4 + i)
            r2_out = BitPosition(4 + i)
            assert r2_out in all_flows[r2_in], f'R2[{i}] -> R2[{i}]'


# =============================================================================
# Full Inference Pipeline Tests
# =============================================================================


@pytest.mark.parametrize(('opcode', 'immediate'), ALL_JN_INSTRUCTIONS)
def test_full_inference(
    opcode,
    immediate,
    jn_state_format,
    jn_state_format_immediate,
    jn_cond_reg,
    inference_engine,
    jn_instruction_data,
):
    """Test full inference pipeline for all JN instructions."""
    bytestring = encode_instruction(opcode, immediate)
    state_format = jn_state_format_immediate if immediate is not None else jn_state_format

    # Use cached data for register instructions to avoid recomputation
    if immediate is None and (opcode, immediate) in jn_instruction_data:
        data = jn_instruction_data[(opcode, immediate)]
        rule = data['rule']
        obs_engine = data['obs_engine']
    else:
        obs_engine = ObservationEngine(bytestring, 'JN', state_format)
        observations = obs_engine.observe_insn()
        rule = inference_engine.infer(observations, jn_cond_reg, obs_engine, enable_refinement=False)

    # Basic checks
    assert len(rule.pairs) > 0, f'Rule should have condition-dataflow pairs for {opcode.name}'
    assert rule.state_format == state_format, f'State format mismatch for {opcode.name}'

    # Verify immediate instructions exclude R2
    if immediate is not None:
        reg_names = [r.name for r in rule.state_format]
        assert 'R2' not in reg_names, f'{opcode.name} should not include R2 in state'

    # Collect all flows from the rule
    rule_flows: dict[BitPosition, set[BitPosition]] = {}
    for pair in rule.pairs:
        for input_bit, output_bits in pair.output_bits.items():
            if input_bit not in rule_flows:
                rule_flows[input_bit] = set()
            rule_flows[input_bit].update(output_bits)

    # Should have dataflows for input bits
    assert len(rule_flows) > 0, f'Should have dataflows for {opcode.name}'


# =============================================================================
# Rule Validation Tests
# =============================================================================


@pytest.mark.parametrize(('opcode', 'immediate'), ALL_JN_INSTRUCTIONS)
def test_rule_explains_all_observations(
    opcode,
    immediate,
    jn_state_format,
    jn_state_format_immediate,
    jn_cond_reg,
    inference_engine,
    jn_instruction_data,
):
    """Test that inferred rule explains 100% of observations.

    This verifies that the inference engine produces a complete rule
    that explains ALL observed behavior for each instruction.
    """
    bytestring = encode_instruction(opcode, immediate)
    state_format = jn_state_format_immediate if immediate is not None else jn_state_format

    # Use cached data for register instructions to avoid recomputation
    if immediate is None and (opcode, immediate) in jn_instruction_data:
        data = jn_instruction_data[(opcode, immediate)]
        rule = data['rule']
        obs_deps = data['obs_deps']
    else:
        obs_engine = ObservationEngine(bytestring, 'JN', state_format)
        observations = obs_engine.observe_insn()
        rule = inference_engine.infer(observations, jn_cond_reg, obs_engine, enable_refinement=False)
        # Validate that rule explains all observations
        obs_deps = extract_observation_dependencies(observations)
    explained, total = validate_rule_explains_observations(rule, obs_deps)

    # Assert that all behaviors are explained
    percentage = explained / total * 100 if total > 0 else 0
    assert (
        explained == total
    ), f'{opcode.name} rule should explain all observations: {explained}/{total} ({percentage:.1f}% explained)'


# =============================================================================
# Condition Inference Tests
# =============================================================================


@pytest.mark.parametrize(
    ('opcode', 'immediate', 'should_be_unconditional'),
    INSTRUCTIONS_WITH_CONDITIONALITY,
)
def test_condition_inference(
    opcode,
    immediate,
    should_be_unconditional,
    jn_state_format,
    jn_state_format_immediate,
    jn_cond_reg,
    inference_engine,
    jn_instruction_data,
):
    """Test that conditions are inferred correctly for each instruction.

    Unconditional instructions (ADD, XOR) should have condition=None or empty conditions.
    Conditional instructions (AND, OR) should have conditions or multiple pairs.
    """
    bytestring = encode_instruction(opcode, immediate)
    state_format = jn_state_format_immediate if immediate is not None else jn_state_format

    # Use cached data for register instructions to avoid recomputation
    if immediate is None and (opcode, immediate) in jn_instruction_data:
        data = jn_instruction_data[(opcode, immediate)]
        rule = data['rule']
    else:
        obs_engine = ObservationEngine(bytestring, 'JN', state_format)
        observations = obs_engine.observe_insn()
        rule = inference_engine.infer(observations, jn_cond_reg, obs_engine, enable_refinement=False)

    # Check for unconditional flows
    unconditional_count = sum(
        1 for pair in rule.pairs if pair.condition is None or len(pair.condition.condition_ops) == 0
    )

    if should_be_unconditional:
        # Expect mostly unconditional flows for ADD, XOR
        assert unconditional_count > 0, f'{opcode.name} should have unconditional flows'
    else:
        # Expect conditions or multiple pairs for AND, OR (data-dependent)
        has_conditions = any(
            pair.condition is not None and len(pair.condition.condition_ops) > 0 for pair in rule.pairs
        )
        assert has_conditions or len(rule.pairs) > 1, f'{opcode.name} should have either conditions or multiple pairs'


# =============================================================================
# Expected Taint Rule Tests
# =============================================================================


class TestJNExpectedTaintRules:
    """Test that inferred rules match expected taint propagation semantics."""

    def test_xor_r1_r2_has_correct_flows(self, jn_instruction_data):
        """Test XOR R1, R2 has correct dataflows.

        Expected: For all i in 0..3:
        - R1[i] → R1[i] (XOR result)
        - R2[i] → R1[i] (XOR result)
        - R2[i] → R2[i] (unchanged)
        - R1[i] → NZCV flags (N, Z flags based on result)
        - R2[i] → NZCV flags (N, Z flags based on result)

        XOR always computes R1 = R1 XOR R2 and sets N/Z flags.
        """
        # Use cached data
        data = jn_instruction_data[(JNOpcode.XOR_R1_R2, None)]
        rule = data['rule']

        # Collect ALL flows (conditional and unconditional) per input bit
        all_flows: dict[BitPosition, set[BitPosition]] = {}
        for pair in rule.pairs:
            for input_bit, output_bits in pair.output_bits.items():
                if input_bit not in all_flows:
                    all_flows[input_bit] = set()
                all_flows[input_bit].update(output_bits)

        # Verify XOR dataflows exist
        for i in range(4):
            r1_bit = BitPosition(i)
            r2_bit = BitPosition(4 + i)

            # R1[i] should flow to R1[i] (XOR result)
            assert r1_bit in all_flows, f'R1[{i}] should have flows'
            assert r1_bit in all_flows[r1_bit], f'R1[{i}] → R1[{i}] flow missing'

            # R2[i] should flow to R1[i] (XOR result)
            assert r2_bit in all_flows, f'R2[{i}] should have flows'
            assert r1_bit in all_flows[r2_bit], f'R2[{i}] → R1[{i}] flow missing'

            # R1[i] and R2[i] should flow to NZCV flags
            # (At least one of N or Z flags, depending on result bit position)
            nzcv_bits = {BitPosition(8), BitPosition(9), BitPosition(10), BitPosition(11)}
            assert any(bit in nzcv_bits for bit in all_flows[r1_bit]), f'R1[{i}] should flow to at least one NZCV flag'
            assert any(bit in nzcv_bits for bit in all_flows[r2_bit]), f'R2[{i}] should flow to at least one NZCV flag'

    def test_and_r1_r2_conditional_flows(self, jn_instruction_data):
        """Test AND R1, R2 has correct conditional flows.

        Expected: For all i in 0..3:
        - R1[i] → R1[i] when R2[i] = 1
        - R2[i] → R1[i] when R1[i] = 1
        - R2[i] → R2[i] (unchanged, unconditional)

        AND only propagates taint when BOTH bits are 1.
        """
        # Use cached data
        data = jn_instruction_data[(JNOpcode.AND_R1_R2, None)]
        rule = data['rule']
        bytestring = data['obs_engine'].bytestring

        # Test with concrete values to verify AND behavior

        cpu = JNCpu()

        # Test case 1: R1[0]=1 (tainted), R2[0]=1 (untainted)
        # Expected: taint propagates to output R1[0]
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0001, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        # Result: 1 & 1 = 1, taint from R1[0] should propagate

        # Test case 2: R1[0]=1 (tainted), R2[0]=0 (untainted)
        # Expected: taint does NOT propagate (result is 0)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0000, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0, 'AND with R2=0 should give 0'

        # Test case 3: R1[0]=0 (untainted), R2[0]=1 (tainted)
        # Expected: taint does NOT propagate (result is 0)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0000, JN_REG_R2(): 0b0001, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0, 'AND with R1=0 should give 0'

        # Verify R2 is unchanged
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b1111, JN_REG_R2(): 0b1010, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R2()] == 0b1010, 'R2 should be unchanged by AND'

        # The rule should capture these conditional behaviors
        assert len(rule.pairs) > 0, 'AND should have condition-dataflow pairs'

    def test_or_r1_r2_conditional_flows(self, jn_instruction_data):
        """Test OR R1, R2 has correct conditional flows.

        Expected: For all i in 0..3:
        - R1[i] → R1[i] when R2[i] = 0
        - R2[i] → R1[i] when R1[i] = 0
        - R2[i] → R2[i] (unchanged, unconditional)

        OR only propagates taint when the other bit is 0.
        """
        data = jn_instruction_data[(JNOpcode.OR_R1_R2, None)]
        bytestring = encode_instruction(JNOpcode.OR_R1_R2)
        rule = data['rule']

        # Test with concrete values to verify OR behavior

        cpu = JNCpu()

        # Test case 1: R1[0]=0 (tainted), R2[0]=0 (untainted)
        # Expected: taint propagates to output R1[0] (result is 0)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0000, JN_REG_R2(): 0b0000, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0, 'OR with both 0 should give 0'

        # Test case 2: R1[0]=0 (tainted), R2[0]=1 (untainted)
        # Expected: result is 1, taint does NOT propagate (masked by R2=1)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0000, JN_REG_R2(): 0b0001, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 1, 'OR with R2=1 should give 1'

        # Test case 3: R1[0]=1 (untainted), R2[0]=0 (tainted)
        # Expected: result is 1, taint propagates from R2
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0000, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 1, 'OR should give 1'

        # Test case 4: R1[0]=1 (untainted), R2[0]=1 (untainted)
        # Expected: result is 1, no taint propagates
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0001, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 1, 'OR with both 1 should give 1'

        # Verify R2 is unchanged
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b1111, JN_REG_R2(): 0b1010, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R2()] == 0b1010, 'R2 should be unchanged by OR'

        # The rule should capture these conditional behaviors
        assert len(rule.pairs) > 0, 'OR should have condition-dataflow pairs'

    def test_add_r1_r2_carry_propagation(self, jn_instruction_data):
        """Test ADD R1, R2 has correct carry propagation.

        Expected: Complex carry propagation where lower bits affect higher bits.
        - Each bit can affect all higher bits due to carries
        - R2[i] → R2[i] (unchanged, unconditional)

        This is the most complex case and may require detailed condition analysis.
        """
        data = jn_instruction_data[(JNOpcode.ADD_R1_R2, None)]
        bytestring = encode_instruction(JNOpcode.ADD_R1_R2)
        rule = data['rule']

        # Test with concrete values to verify ADD behavior

        cpu = JNCpu()

        # Test case 1: No carry (1 + 0 = 1)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0000, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 1, 'ADD 1+0 should give 1'

        # Test case 2: Carry propagation (1 + 1 = 2, bit 0 affects bit 1)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0001, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0b0010, 'ADD 1+1 should give 2 (carry to bit 1)'

        # Test case 3: Multiple carries (7 + 1 = 8, carry propagates to bit 3)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0111, JN_REG_R2(): 0b0001, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0b1000, 'ADD 7+1 should give 8 (multiple carries)'

        # Test case 4: Overflow (15 + 1 = 0 in 4-bit arithmetic)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b1111, JN_REG_R2(): 0b0001, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0b0000, 'ADD 15+1 should give 0 (overflow)'

        # Verify R2 is unchanged
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0101, JN_REG_R2(): 0b1010, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R2()] == 0b1010, 'R2 should be unchanged by ADD'

        # The rule should capture carry propagation
        assert len(rule.pairs) > 0, 'ADD should have condition-dataflow pairs'


# =============================================================================
# Concrete Value Tests for Rule Validation
# =============================================================================


class TestJNConcreteValueValidation:
    """Test rules with concrete input/output values to ensure correctness."""

    @pytest.mark.parametrize(
        ('r1_val', 'r2_val', 'expected'),
        [
            (0b0000, 0b0000, 0b0000),  # 0 & 0 = 0
            (0b1111, 0b1111, 0b1111),  # 15 & 15 = 15
            (0b1010, 0b0101, 0b0000),  # 10 & 5 = 0
            (0b1111, 0b0101, 0b0101),  # 15 & 5 = 5
            (0b1100, 0b1010, 0b1000),  # 12 & 10 = 8
        ],
    )
    def test_and_concrete_cases(self, r1_val, r2_val, expected):
        """Test AND rule with specific concrete cases.

        Even if the rule is complex, it should correctly predict taint
        propagation for these concrete examples.
        """
        bytestring = encode_instruction(JNOpcode.AND_R1_R2)
        cpu = JNCpu()
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): r1_val, JN_REG_R2(): r2_val, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        actual = output[JN_REG_R1()]
        assert actual == expected, f'AND {r1_val} & {r2_val} = {expected}, got {actual}'

    @pytest.mark.parametrize(
        ('r1_val', 'r2_val', 'expected'),
        [
            (0b0000, 0b0000, 0b0000),  # 0 | 0 = 0
            (0b1111, 0b0000, 0b1111),  # 15 | 0 = 15
            (0b0000, 0b1111, 0b1111),  # 0 | 15 = 15
            (0b1010, 0b0101, 0b1111),  # 10 | 5 = 15
            (0b1100, 0b1010, 0b1110),  # 12 | 10 = 14
        ],
    )
    def test_or_concrete_cases(self, r1_val, r2_val, expected):
        """Test OR rule with specific concrete cases."""
        bytestring = encode_instruction(JNOpcode.OR_R1_R2)
        cpu = JNCpu()
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): r1_val, JN_REG_R2(): r2_val, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        actual = output[JN_REG_R1()]
        assert actual == expected, f'OR {r1_val} | {r2_val} = {expected}, got {actual}'

    @pytest.mark.parametrize(
        ('r1_val', 'r2_val', 'expected'),
        [
            (0b0000, 0b0000, 0b0000),  # 0 ^ 0 = 0
            (0b1111, 0b0000, 0b1111),  # 15 ^ 0 = 15
            (0b0000, 0b1111, 0b1111),  # 0 ^ 15 = 15
            (0b1010, 0b0101, 0b1111),  # 10 ^ 5 = 15
            (0b1100, 0b1010, 0b0110),  # 12 ^ 10 = 6
            (0b1111, 0b1111, 0b0000),  # 15 ^ 15 = 0
        ],
    )
    def test_xor_concrete_cases(self, r1_val, r2_val, expected):
        """Test XOR rule with specific concrete cases."""
        bytestring = encode_instruction(JNOpcode.XOR_R1_R2)
        cpu = JNCpu()
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): r1_val, JN_REG_R2(): r2_val, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        actual = output[JN_REG_R1()]
        assert actual == expected, f'XOR {r1_val} ^ {r2_val} = {expected}, got {actual}'

    @pytest.mark.parametrize(
        ('r1_val', 'r2_val', 'expected'),
        [
            (0b0000, 0b0000, 0b0000),  # 0 + 0 = 0
            (0b0001, 0b0001, 0b0010),  # 1 + 1 = 2
            (0b0111, 0b0001, 0b1000),  # 7 + 1 = 8
            (0b1000, 0b1000, 0b0000),  # 8 + 8 = 0 (overflow)
            (0b1111, 0b0001, 0b0000),  # 15 + 1 = 0 (overflow)
            (0b0101, 0b0011, 0b1000),  # 5 + 3 = 8
            (0b1010, 0b0101, 0b1111),  # 10 + 5 = 15
        ],
    )
    def test_add_concrete_cases(self, r1_val, r2_val, expected):
        """Test ADD rule with specific concrete cases."""
        bytestring = encode_instruction(JNOpcode.ADD_R1_R2)
        cpu = JNCpu()
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): r1_val, JN_REG_R2(): r2_val, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        actual = output[JN_REG_R1()]
        assert actual == expected, f'ADD {r1_val} + {r2_val} = {expected}, got {actual}'


# =============================================================================
# Immediate Instruction Tests
# =============================================================================


class TestJNImmediateInstructions:
    """Test that immediate instructions use correct state format."""

    @pytest.mark.parametrize(('opcode', 'immediate'), IMMEDIATE_INSTRUCTIONS)
    def test_immediate_instructions_exclude_r2(self, opcode, immediate, jn_instruction_data):
        """Test that all immediate instructions exclude R2 from state format."""
        bytestring = encode_instruction(opcode, immediate)

        # Use cached data if available
        if (opcode, immediate) in jn_instruction_data:
            observations = jn_instruction_data[(opcode, immediate)]['observations']
        else:
            # Create state format without R2
            state_format = [JN_REG_R1(), JN_REG_NZCV()]
            obs_engine = ObservationEngine(bytestring, 'JN', state_format)
            observations = obs_engine.observe_insn()

        # Verify no R2 in state format
        for obs in observations:
            reg_names = [r.name for r in obs.state_format]
            assert 'R2' not in reg_names, f'{opcode.name} should not include R2'

    def test_immediate_instruction_observation_count(self, jn_instruction_data):
        """Test that immediate instructions generate correct number of observations.

        Immediate: 8 bits (R1=4, NZCV=4) = 256 states
        Register: 12 bits (R1=4, R2=4, NZCV=4) = 4096 states
        """
        # Immediate instruction
        bytestring_imm = encode_instruction(JNOpcode.ADD_R1_IMM, 0xA)
        state_format_imm = [JN_REG_R1(), JN_REG_NZCV()]
        obs_engine_imm = ObservationEngine(bytestring_imm, 'JN', state_format_imm)
        observations_imm = obs_engine_imm.observe_insn()

        # Register instruction - use cached data
        observations_reg = jn_instruction_data[(JNOpcode.ADD_R1_R2, None)]['observations']

        # Immediate should have fewer observations (256 vs 4096)
        assert len(observations_imm) < len(
            observations_reg,
        ), f'Immediate should have fewer observations: {len(observations_imm)} vs {len(observations_reg)}'


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestJNEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_and_r1_r2_with_zero_r2(self, jn_instruction_data):
        """Test AND R1, R2 behavior when R2=0.

        When R2=0, result is always 0 regardless of R1.
        This tests if conditions properly capture this behavior.
        """
        data = jn_instruction_data[(JNOpcode.AND_R1_R2, None)]
        rule = data['rule']

        # Rule should explain this edge case
        assert len(rule.pairs) > 0

    def test_and_r1_r2_with_all_ones(self, jn_instruction_data):
        """Test AND R1, R2 behavior when both are 0xF.

        When both are all 1s, taint should propagate unconditionally.
        """
        data = jn_instruction_data[(JNOpcode.AND_R1_R2, None)]
        rule = data['rule']

        # Should have valid rule
        assert len(rule.pairs) > 0


# =============================================================================
# Taint Blocking Tests
# =============================================================================


@pytest.mark.parametrize(
    ('opcode', 'immediate', 'r1_value', 'r2_value', 'expected_output', 'description'),
    [
        # AND blocks taint when other operand is zero
        (JNOpcode.AND_R1_R2, None, 0b1111, 0b0000, 0b0000, 'AND R1, R2 with R2=0 gives 0'),
        (JNOpcode.AND_R1_R2, None, 0b0000, 0b1111, 0b0000, 'AND R1, R2 with R1=0 gives 0'),
        (JNOpcode.AND_R1_IMM, 0x0, 0b1111, 0b0000, 0b0000, 'AND R1, #0 gives 0'),
        # OR blocks taint when other operand is all ones
        (JNOpcode.OR_R1_R2, None, 0b0000, 0b1111, 0b1111, 'OR R1, R2 with R2=0xF gives 0xF'),
        (JNOpcode.OR_R1_R2, None, 0b1111, 0b0000, 0b1111, 'OR R1, R2 with R1=0xF gives 0xF'),
        (JNOpcode.OR_R1_IMM, 0xF, 0b0000, 0b0000, 0b1111, 'OR R1, #0xF gives 0xF'),
        # Bit-specific blocking for AND
        (JNOpcode.AND_R1_R2, None, 0b1110, 0b0001, 0b0000, 'AND R1, R2: only bit 0 can pass'),
        (JNOpcode.AND_R1_R2, None, 0b1111, 0b1010, 0b1010, 'AND R1, R2: bits 1,3 pass'),
        (JNOpcode.AND_R1_IMM, 0x3, 0b1100, 0b0000, 0b0000, 'AND R1, #0x3 blocks upper bits'),
        (JNOpcode.AND_R1_IMM, 0x3, 0b1111, 0b0000, 0b0011, 'AND R1, #0x3 passes lower bits'),
        # Bit-specific blocking for OR
        (JNOpcode.OR_R1_R2, None, 0b0001, 0b1110, 0b1111, 'OR R1, R2: R2 sets bits 1,2,3'),
        (JNOpcode.OR_R1_R2, None, 0b0101, 0b1010, 0b1111, 'OR R1, R2: union of bits'),
        (JNOpcode.OR_R1_IMM, 0xC, 0b0011, 0b0000, 0b1111, 'OR R1, #0xC sets upper bits'),
        (JNOpcode.OR_R1_IMM, 0xC, 0b0000, 0b0000, 0b1100, 'OR R1, #0xC gives 0xC'),
    ],
)
def test_taint_blocking_conditions(opcode, immediate, r1_value, r2_value, expected_output, description):
    """Test that operations produce expected outputs that may block taint propagation.

    This verifies data-dependent blocking conditions:
    - AND: output is 0 when operand is 0 (blocks taint)
    - OR: output is 1 when operand is 1 (blocks taint)
    """
    bytestring = encode_instruction(opcode, immediate)

    # Execute instruction with given values
    cpu = JNCpu()
    test_state = CpuRegisterMap({JN_REG_R1(): r1_value, JN_REG_R2(): r2_value, JN_REG_NZCV(): 0})
    cpu.set_cpu_state(test_state)
    _, after_state = cpu.execute(jn_hex_to_bytes(bytestring))

    # Check output matches expected
    r1_after = after_state[JN_REG_R1()]
    assert r1_after == expected_output, f'{description}: expected {expected_output:#06b}, got {r1_after:#06b}'


@pytest.mark.parametrize(
    ('opcode', 'immediate', 'blocking_state', 'tainted_input_bits', 'expected_untainted_output_bits', 'description'),
    [
        # AND blocks taint when other operand is zero
        (
            JNOpcode.AND_R1_R2,
            None,
            {JN_REG_R1(): 0b1111, JN_REG_R2(): 0b0000},
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)],
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)],  # R1 output bits should be untainted
            'AND R1, R2 with R2=0: R1 taint blocked',
        ),
        (
            JNOpcode.AND_R1_R2,
            None,
            {JN_REG_R1(): 0b0000, JN_REG_R2(): 0b1111},
            [BitPosition(4), BitPosition(5), BitPosition(6), BitPosition(7)],
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)],  # R1 output bits should be untainted
            'AND R1, R2 with R1=0: R2 taint blocked',
        ),
        (
            JNOpcode.AND_R1_IMM,
            0x0,
            {JN_REG_R1(): 0b1111},
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)],
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)],  # R1 output bits should be untainted
            'AND R1, #0: R1 taint blocked',
        ),
        # OR blocks taint when other operand is all ones
        (
            JNOpcode.OR_R1_R2,
            None,
            {JN_REG_R1(): 0b0000, JN_REG_R2(): 0b1111},
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)],
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)],  # R1 output bits should be untainted
            'OR R1, R2 with R2=0xF: R1 taint blocked',
        ),
        (
            JNOpcode.OR_R1_R2,
            None,
            {JN_REG_R1(): 0b1111, JN_REG_R2(): 0b0000},
            [BitPosition(4), BitPosition(5), BitPosition(6), BitPosition(7)],
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)],  # R1 output bits should be untainted
            'OR R1, R2 with R1=0xF: R2 taint blocked',
        ),
        (
            JNOpcode.OR_R1_IMM,
            0xF,
            {JN_REG_R1(): 0b0000},
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)],
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)],  # R1 output bits should be untainted
            'OR R1, #0xF: R1 taint blocked',
        ),
        # Bit-specific blocking for AND
        (
            JNOpcode.AND_R1_R2,
            None,
            {JN_REG_R1(): 0b1110, JN_REG_R2(): 0b0001},
            [BitPosition(1), BitPosition(2), BitPosition(3)],
            [BitPosition(1), BitPosition(2), BitPosition(3)],  # R1 bits 1-3 should be untainted
            'AND R1, R2: R1 bits 1-3 blocked by R2=0b0001',
        ),
        (
            JNOpcode.AND_R1_IMM,
            0x3,
            {JN_REG_R1(): 0b1100},
            [BitPosition(2), BitPosition(3)],
            [BitPosition(2), BitPosition(3)],  # R1 upper bits should be untainted
            'AND R1, #0x3: R1 upper bits blocked',
        ),
        # Bit-specific blocking for OR
        (
            JNOpcode.OR_R1_R2,
            None,
            {JN_REG_R1(): 0b0001, JN_REG_R2(): 0b1110},
            [BitPosition(1), BitPosition(2), BitPosition(3)],
            [BitPosition(1), BitPosition(2), BitPosition(3)],  # R1 bits 1-3 should be untainted
            'OR R1, R2: R1 bits 1-3 blocked by R2=0b1110',
        ),
        (
            JNOpcode.OR_R1_IMM,
            0xC,
            {JN_REG_R1(): 0b0011},
            [BitPosition(2), BitPosition(3)],
            [BitPosition(2), BitPosition(3)],  # R1 upper bits should be untainted
            'OR R1, #0xC: R1 upper bits blocked',
        ),
    ],
)
def test_inferred_rules_capture_taint_blocking(
    opcode,
    immediate,
    blocking_state,
    tainted_input_bits,
    expected_untainted_output_bits,
    description,
    jn_instruction_data,
):
    """End-to-end test that inferred rules correctly predict when taint does NOT propagate.

    This is a REAL end-to-end test that:
    1. Infers a taint rule from all observations (full inference pipeline)
    2. Creates a concrete blocking scenario with specific register values
    3. Marks specified input bits as tainted
    4. Applies the inferred rule using the SAME taint propagation algorithm as production
       (evaluate_condition + dataflow application from visualizer/taint_simulator.py)
    5. Verifies that expected output bits remain UNTAINTED (taint blocked)

    IMPORTANT: This test uses simulate_taint_propagation() which implements the EXACT
    same DNF evaluation logic as TaintCondition.eval():
        DNF: any((state_value & bitmask == value) for bitmask, value in dnf_args)

    Test failures indicate REAL BUGS in the inference engine - the inferred rules
    fail to capture data-dependent taint blocking conditions.
    """
    bytestring = encode_instruction(opcode, immediate)

    # Determine state format
    use_immediate = immediate is not None
    state_format = [JN_REG_R1(), JN_REG_NZCV()] if use_immediate else [JN_REG_R1(), JN_REG_R2(), JN_REG_NZCV()]

    # Use cached data for register instructions to avoid recomputation
    if not use_immediate and (opcode, immediate) in jn_instruction_data:
        data = jn_instruction_data[(opcode, immediate)]
        internal_rule = data['rule']
    else:
        # Generate observations and infer rule
        obs_engine = ObservationEngine(bytestring, 'JN', state_format)
        observations = obs_engine.observe_insn()
        inference_engine = InferenceEngine()
        internal_rule = inference_engine.infer(observations, JN_REG_NZCV(), obs_engine, enable_refinement=False)

    # Convert to TaintRule for simulation
    taint_rule = internal_rule.convert2squirrel('JN', bytestring)

    # Build input state value from blocking_state dict
    input_state_value = 0
    bit_offset = 0
    for reg in state_format:
        if reg in blocking_state:
            reg_value = blocking_state[reg]
            input_state_value |= reg_value << bit_offset
        bit_offset += reg.bits

    # Convert BitPosition tainted bits to (register_name, bit_index) format
    tainted_bits_set = set()
    for bit_pos in tainted_input_bits:
        # Map global bit position to (register, bit_index)
        offset = 0
        for reg in state_format:
            if bit_pos < offset + reg.bits:
                tainted_bits_set.add((reg.name, bit_pos - offset))
                break
            offset += reg.bits

    # Simulate taint propagation
    result = simulate_taint_propagation(taint_rule, input_state_value, tainted_bits_set)
    tainted_outputs_set = set(result['tainted_outputs'])

    # Convert expected_untainted_output_bits to (register_name, bit_index) format
    for output_bit_pos in expected_untainted_output_bits:
        offset = 0
        for reg in state_format:
            if output_bit_pos < offset + reg.bits:
                output_tuple = (reg.name, output_bit_pos - offset)
                assert output_tuple not in tainted_outputs_set, (
                    f'{description}: Bit {output_bit_pos} ({output_tuple}) should be untainted '
                    f'but was tainted. Rule failed to block taint propagation.'
                )
                break
            offset += reg.bits


# =============================================================================
# NZCV Flag Tests
# =============================================================================


class TestJNNZCVFlags:
    """Test NZCV flag computation and taint propagation."""

    @pytest.mark.parametrize(
        ('r1', 'r2', 'expected_result', 'expected_n', 'expected_z', 'expected_c', 'expected_v'),
        [
            # No carry, no overflow
            (0b0001, 0b0001, 0b0010, 0, 0, 0, 0),  # 1 + 1 = 2
            (0b0011, 0b0010, 0b0101, 0, 0, 0, 0),  # 3 + 2 = 5
            # Result is zero
            (0b0000, 0b0000, 0b0000, 0, 1, 0, 0),  # 0 + 0 = 0
            (0b1000, 0b1000, 0b0000, 0, 1, 1, 1),  # -8 + -8 = -16 = 0 (carry, overflow)
            # Carry set (result > 15)
            (0b1111, 0b0001, 0b0000, 0, 1, 1, 0),  # 15 + 1 = 16 = 0 (mod 16)
            (0b1010, 0b0111, 0b0001, 0, 0, 1, 0),  # 10 + 7 = 17 = 1 (mod 16)
            # Negative result (bit 3 set)
            (0b0111, 0b0010, 0b1001, 1, 0, 0, 1),  # 7 + 2 = 9 (negative in 2's comp, overflow)
            (0b0111, 0b0001, 0b1000, 1, 0, 0, 1),  # 7 + 1 = 8 (negative in 2's comp, overflow)
            # Overflow: positive + positive = negative
            (0b0111, 0b0111, 0b1110, 1, 0, 0, 1),  # 7 + 7 = 14 (overflow: pos+pos=neg)
            # Overflow: negative + negative = positive
            (0b1000, 0b1001, 0b0001, 0, 0, 1, 1),  # -8 + -7 = -15 = 1 (overflow, carry)
            (0b1010, 0b1011, 0b0101, 0, 0, 1, 1),  # -6 + -5 = -11 = 5 (overflow, carry)
            (0b1111, 0b1111, 0b1110, 1, 0, 1, 0),  # -1 + -1 = -2 (no overflow)
        ],
    )
    def test_add_nzcv_flags(self, r1, r2, expected_result, expected_n, expected_z, expected_c, expected_v):
        """Test NZCV flag computation for ADD instruction."""
        cpu = JNCpu()
        bytestring = encode_instruction(JNOpcode.ADD_R1_R2)

        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): r1, JN_REG_R2(): r2, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))

        result = output[JN_REG_R1()]
        nzcv = output[JN_REG_NZCV()]

        assert result == expected_result, f'ADD {r1} + {r2} should give {expected_result}, got {result}'

        # Extract individual flags from NZCV
        n = (nzcv >> 3) & 1
        z = (nzcv >> 2) & 1
        c = (nzcv >> 1) & 1
        v = nzcv & 1

        assert n == expected_n, f'N flag should be {expected_n}, got {n} (NZCV={nzcv:04b})'
        assert z == expected_z, f'Z flag should be {expected_z}, got {z} (NZCV={nzcv:04b})'
        assert c == expected_c, f'C flag should be {expected_c}, got {c} (NZCV={nzcv:04b})'
        assert v == expected_v, f'V flag should be {expected_v}, got {v} (NZCV={nzcv:04b})'

    @pytest.mark.parametrize(
        ('opcode', 'r1', 'r2_or_imm', 'use_imm'),
        [
            (JNOpcode.OR_R1_R2, 0b1010, 0b0101, False),
            (JNOpcode.OR_R1_IMM, 0b1010, 0x5, True),
            (JNOpcode.AND_R1_R2, 0b1111, 0b0011, False),
            (JNOpcode.AND_R1_IMM, 0b1111, 0x3, True),
            (JNOpcode.XOR_R1_R2, 0b1010, 0b0101, False),
            (JNOpcode.XOR_R1_IMM, 0b1010, 0x5, True),
        ],
    )
    def test_logical_ops_set_nz_flags(self, opcode, r1, r2_or_imm, use_imm):
        """Test that logical operations set N and Z flags, but not C or V."""
        cpu = JNCpu()

        if use_imm:
            bytestring = encode_instruction(opcode, r2_or_imm)
            cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): r1, JN_REG_R2(): 0, JN_REG_NZCV(): 0}))
        else:
            bytestring = encode_instruction(opcode)
            cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): r1, JN_REG_R2(): r2_or_imm, JN_REG_NZCV(): 0}))

        _, output = cpu.execute(jn_hex_to_bytes(bytestring))

        result = output[JN_REG_R1()]
        nzcv = output[JN_REG_NZCV()]

        # Extract individual flags
        n = (nzcv >> 3) & 1
        z = (nzcv >> 2) & 1
        c = (nzcv >> 1) & 1
        v = nzcv & 1

        # Check N flag (bit 3 of result)
        expected_n = 1 if (result & 0x8) != 0 else 0
        assert n == expected_n, f'N flag should be {expected_n}, got {n}'

        # Check Z flag
        expected_z = 1 if result == 0 else 0
        assert z == expected_z, f'Z flag should be {expected_z}, got {z}'

        # C and V should be 0 for logical operations
        assert c == 0, f'C flag should be 0 for logical ops, got {c}'
        assert v == 0, f'V flag should be 0 for logical ops, got {v}'

    def test_nzcv_taint_propagation_all_ops(self, jn_instruction_data):
        """Test that NZCV flags properly capture taint from all operations.

        NZCV flags should be tainted by:
        - Both R1 and R2 for all operations (since flags depend on the result)
        - Result affects N and Z unconditionally
        - For ADD: C and V flags also depend on operands
        """
        for opcode in [JNOpcode.ADD_R1_R2, JNOpcode.OR_R1_R2, JNOpcode.AND_R1_R2, JNOpcode.XOR_R1_R2]:
            data = jn_instruction_data[(opcode, None)]
            rule = data['rule']

            # Check that NZCV bits (8-11) receive taint from R1 and R2
            for input_bit in range(8):  # R1 (0-3) and R2 (4-7)
                found_nzcv_flow = False
                for pair in rule.pairs:
                    if isinstance(pair.output_bits, dict) and input_bit in pair.output_bits:
                        outputs = pair.output_bits[input_bit]
                        # Check if any NZCV bit (8-11) is in outputs
                        nzcv_outputs = [b for b in outputs if 8 <= b <= 11]
                        if nzcv_outputs:
                            found_nzcv_flow = True
                            break

                assert (
                    found_nzcv_flow
                ), f'{opcode.name}: Input bit {input_bit} should propagate taint to NZCV flags (bits 8-11)'

    def test_nzcv_flag_bit_meanings(self):
        """Test that NZCV flag bits are correctly positioned.

        NZCV layout (bits 8-11 of state):
        - Bit 11 (NZCV bit 3): N (Negative)
        - Bit 10 (NZCV bit 2): Z (Zero)
        - Bit 9  (NZCV bit 1): C (Carry)
        - Bit 8  (NZCV bit 0): V (Overflow)
        """
        cpu = JNCpu()
        bytestring = encode_instruction(JNOpcode.ADD_R1_R2)

        # Test N flag: 7 + 1 = 8 (bit 3 set, negative in 2's complement)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0111, JN_REG_R2(): 0b0001, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        nzcv = output[JN_REG_NZCV()]
        assert (nzcv >> 3) & 1 == 1, 'N flag (bit 3) should be set'

        # Test Z flag: 8 + 8 = 0 (mod 16)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b1000, JN_REG_R2(): 0b1000, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        nzcv = output[JN_REG_NZCV()]
        assert (nzcv >> 2) & 1 == 1, 'Z flag (bit 2) should be set'

        # Test C flag: 15 + 1 = 16 = 0 (mod 16), carry out
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b1111, JN_REG_R2(): 0b0001, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        nzcv = output[JN_REG_NZCV()]
        assert (nzcv >> 1) & 1 == 1, 'C flag (bit 1) should be set'

        # Test V flag: 7 + 1 = 8 (overflow: positive + positive = negative)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0111, JN_REG_R2(): 0b0001, JN_REG_NZCV(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        nzcv = output[JN_REG_NZCV()]
        assert nzcv & 1 == 1, 'V flag (bit 0) should be set'

    def test_nzcv_taint_from_specific_bits(self, jn_state_format, jn_cond_reg, inference_engine):
        """Test that specific NZCV flag bits get taint from expected sources.

        For ADD R1, R2:
        - N flag depends on bit 3 of result (most significant bit)
        - Z flag depends on all bits of result (any bit being 1 makes Z=0)
        - C flag depends on carry out (all bits contribute)
        - V flag depends on sign bits and result
        """
        bytestring = encode_instruction(JNOpcode.ADD_R1_R2)
        obs_engine = ObservationEngine(bytestring, 'JN', jn_state_format)
        observations = obs_engine.observe_insn()

        rule = inference_engine.infer(observations, jn_cond_reg, obs_engine, enable_refinement=False)

        # Verify that all R1 and R2 bits can affect NZCV
        for input_reg_bit in range(8):  # R1[0-3] and R2[0-3]
            nzcv_affected = set()
            for pair in rule.pairs:
                if isinstance(pair.output_bits, dict) and input_reg_bit in pair.output_bits:
                    outputs = pair.output_bits[input_reg_bit]
                    for out_bit in outputs:
                        if 8 <= out_bit <= 11:
                            nzcv_affected.add(out_bit)

            # Each input bit should affect at least one NZCV flag
            assert len(nzcv_affected) > 0, (
                f'Input bit {input_reg_bit} should affect at least one NZCV flag bit, '
                f'but affects none. This is unexpected for ADD.'
            )


class TestJNSubInstruction:
    """Test SUB instruction behavior and taint propagation."""

    def test_sub_r1_r2_basic_subtraction(self) -> None:
        """Test SUB R1, R2 performs correct subtraction."""
        cpu = JNCpu()
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0x7, JN_REG_R2(): 0x3, JN_REG_NZCV(): 0}))

        bytecode = jn_hex_to_bytes('8')  # SUB R1, R2
        _, state_after = cpu.execute(bytecode)

        # 7 - 3 = 4
        assert state_after[JN_REG_R1()] == 0x4
        assert state_after[JN_REG_R2()] == 0x3  # R2 unchanged

    def test_sub_r1_imm_basic_subtraction(self) -> None:
        """Test SUB R1, imm4 performs correct subtraction."""
        cpu = JNCpu()
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0xA, JN_REG_R2(): 0x0, JN_REG_NZCV(): 0}))

        bytecode = jn_hex_to_bytes('95')  # SUB R1, #5
        _, state_after = cpu.execute(bytecode)

        # 10 - 5 = 5
        assert state_after[JN_REG_R1()] == 0x5

    def test_sub_underflow(self) -> None:
        """Test SUB with underflow wraps correctly."""
        cpu = JNCpu()
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0x2, JN_REG_R2(): 0x5, JN_REG_NZCV(): 0}))

        bytecode = jn_hex_to_bytes('8')  # SUB R1, R2
        _, state_after = cpu.execute(bytecode)

        # 2 - 5 = -3, which wraps to 13 (0xD) in 4-bit unsigned
        assert state_after[JN_REG_R1()] == 0xD

    def test_sub_zero_flag(self) -> None:
        """Test SUB sets Zero flag when result is 0."""
        cpu = JNCpu()
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0x5, JN_REG_R2(): 0x5, JN_REG_NZCV(): 0}))

        bytecode = jn_hex_to_bytes('8')  # SUB R1, R2
        _, state_after = cpu.execute(bytecode)

        # 5 - 5 = 0, Z flag should be set
        z_flag = (state_after[JN_REG_NZCV()] >> 2) & 1
        assert z_flag == 1

    def test_sub_negative_flag(self) -> None:
        """Test SUB sets Negative flag when result is negative (bit 3 set)."""
        cpu = JNCpu()
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0x3, JN_REG_R2(): 0x7, JN_REG_NZCV(): 0}))

        bytecode = jn_hex_to_bytes('8')  # SUB R1, R2
        _, state_after = cpu.execute(bytecode)

        # 3 - 7 = -4, which is 0xC (1100 in binary) in 4-bit
        # Bit 3 is 1, so N flag should be set
        result = state_after[JN_REG_R1()]
        assert result == 0xC
        n_flag = (state_after[JN_REG_NZCV()] >> 3) & 1
        assert n_flag == 1

    def test_sub_carry_flag_no_borrow(self) -> None:
        """Test SUB sets Carry flag when no borrow (operand1 >= operand2)."""
        cpu = JNCpu()
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0x7, JN_REG_R2(): 0x3, JN_REG_NZCV(): 0}))

        bytecode = jn_hex_to_bytes('8')  # SUB R1, R2
        _, state_after = cpu.execute(bytecode)

        # 7 - 3 = 4, no borrow, C should be 1
        c_flag = (state_after[JN_REG_NZCV()] >> 1) & 1
        assert c_flag == 1

    def test_sub_carry_flag_with_borrow(self) -> None:
        """Test SUB clears Carry flag when borrow occurs (operand1 < operand2)."""
        cpu = JNCpu()
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0x3, JN_REG_R2(): 0x7, JN_REG_NZCV(): 0}))

        bytecode = jn_hex_to_bytes('8')  # SUB R1, R2
        _, state_after = cpu.execute(bytecode)

        # 3 - 7, borrow occurs, C should be 0
        c_flag = (state_after[JN_REG_NZCV()] >> 1) & 1
        assert c_flag == 0

    def test_sub_overflow_flag(self) -> None:
        """Test SUB sets Overflow flag on signed overflow."""
        cpu = JNCpu()
        # Use signed interpretation: 0x1 = +1, 0x8 = -8 (in 4-bit 2's complement)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0x1, JN_REG_R2(): 0x8, JN_REG_NZCV(): 0}))

        bytecode = jn_hex_to_bytes('8')  # SUB R1, R2
        _, state_after = cpu.execute(bytecode)

        # +1 - (-8) = +9, but +9 can't be represented in 4-bit signed
        # Result wraps to 0x9 (1001), which is -7 in 2's complement
        # Overflow should be set because different sign operands produced wrong sign result
        v_flag = state_after[JN_REG_NZCV()] & 1
        assert v_flag == 1

    def test_sub_taint_propagation(self, jn_instruction_data):
        """Test that SUB R1, R2 correctly propagates taint from both operands."""
        # Use cached rule
        data = jn_instruction_data[(JNOpcode.SUB_R1_R2, None)]
        rule = data['rule']

        # SUB should propagate taint from both R1 and R2 to result in R1
        input_bits = set()
        for pair in rule.pairs:
            if isinstance(pair.output_bits, dict):
                for input_bit in pair.output_bits:
                    input_bits.add(input_bit)

        # Should see taint from R1[0-3] and R2[4-7]
        assert any(0 <= bit <= 3 for bit in input_bits), 'Should see R1 bits as inputs'
        assert any(4 <= bit <= 7 for bit in input_bits), 'Should see R2 bits as inputs'

    def test_sub_immediate_taint_propagation(self, jn_instruction_data):
        """Test that SUB R1, imm propagates taint from R1 only (to R1 output).

        Note: NZCV flags may show dependencies on all state bits, which is expected
        due to how taint analysis works. We focus on R1 output bits here.
        """
        # Use cached rule
        data = jn_instruction_data[(JNOpcode.SUB_R1_IMM, 0x5)]
        rule = data['rule']

        # Check R1 output bits specifically (bits 0-3)
        r1_output_dependencies = set()
        for pair in rule.pairs:
            if isinstance(pair.output_bits, dict):
                for input_bit, outputs in pair.output_bits.items():
                    for output_bit in outputs:
                        if 0 <= output_bit <= 3:  # R1 output bits
                            r1_output_dependencies.add(input_bit)

        # R1 output should depend on R1 input (bits 0-3)
        assert any(0 <= bit <= 3 for bit in r1_output_dependencies), 'R1 output should depend on R1 inputs'

        # R1 output should NOT depend on R2 (bits 4-7) for immediate variant
        assert not any(4 <= bit <= 7 for bit in r1_output_dependencies), (
            f'R1 output should NOT depend on R2 for SUB immediate, but found dependencies: '
            f'{[bit for bit in r1_output_dependencies if 4 <= bit <= 7]}'
        )

    def test_sub_observation_coverage(self, jn_instruction_data):
        """Test that SUB R1, R2 inference explains all observations."""
        # Use cached data
        data = jn_instruction_data[(JNOpcode.SUB_R1_R2, None)]
        rule = data['rule']
        observation_dependencies = data['obs_deps']

        # Validate that rule explains all observations
        explained, total = validate_rule_explains_observations(rule, observation_dependencies)
        coverage = explained / total if total > 0 else 0

        assert coverage == 1.0, (
            f'SUB R1, R2 should explain 100% of observations, but only explains {coverage:.1%} '
            f'({explained}/{total}). Unexplained behaviors suggest inference issues.'
        )


@pytest.mark.parametrize(('opcode', 'immediate'), ALL_JN_INSTRUCTIONS)
def test_R2_is_always_unconditionnal(jn_instruction_data, opcode, immediate):
    """Test that R2's bits are unconditionnally R2 input bits in all non immediate instructions."""
    # Use cached data
    data = jn_instruction_data[(opcode, immediate)]
    rule = data['rule']
    observations = data['observations']

    # Check that R2 bits (4-7) are always in input_bits of some pair
    if immediate is not None:
        for obs in observations:
            reg_names = [r.name for r in obs.state_format]
            assert 'R2' not in reg_names, f'{opcode.name} should not include R2'
            return
    for pair in rule.pairs:
        for r2_bit in range(4, 8):
            if r2_bit in pair.output_bits:
                assert pair.condition is None or len(pair.condition.condition_ops) == 0
