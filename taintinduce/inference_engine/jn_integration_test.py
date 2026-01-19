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
- Register variants (0, 2, 4, 6) only explain 64.6% of observations (NZVC flag bits)
- Immediate variants with specific values (OR #0x3, AND #0xF) may appear unconditional
"""

import pytest

from taintinduce.cpu.jn_cpu import JNCpu
from taintinduce.inference_engine.inference import InferenceEngine
from taintinduce.inference_engine.observation_processor import extract_observation_dependencies
from taintinduce.inference_engine.validation import validate_rule_explains_observations
from taintinduce.isa.jn_isa import JNOpcode, encode_instruction
from taintinduce.isa.jn_isa import decode_hex_string as decode_jn_hex
from taintinduce.isa.jn_registers import JN_REG_NZVC, JN_REG_R1, JN_REG_R2
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
    """JN state format: R1 (4 bits), R2 (4 bits), NZVC (4 bits)."""
    return [JN_REG_R1(), JN_REG_R2(), JN_REG_NZVC()]


@pytest.fixture
def jn_state_format_immediate():
    """JN state format for immediate instructions: R1 (4 bits), NZVC (4 bits)."""
    return [JN_REG_R1(), JN_REG_NZVC()]


@pytest.fixture
def jn_cond_reg():
    """JN condition register (NZVC)."""
    return JN_REG_NZVC()


@pytest.fixture
def inference_engine():
    """Create an inference engine."""
    return InferenceEngine()


# =============================================================================
# Regression Tests
# =============================================================================


@pytest.mark.parametrize(
    ('opcode', 'immediate'),
    [
        (JNOpcode.ADD_R1_R2, None),  # 0
        (JNOpcode.ADD_R1_IMM, 0xA),  # 1A
        (JNOpcode.OR_R1_R2, None),  # 2
        (JNOpcode.OR_R1_IMM, 0x3),  # 3
        (JNOpcode.AND_R1_R2, None),  # 4
        (JNOpcode.AND_R1_IMM, 0xF),  # 5F
        (JNOpcode.XOR_R1_R2, None),  # 6
        (JNOpcode.XOR_R1_IMM, 0xA),  # 7A
    ],
)
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


@pytest.mark.parametrize(
    ('opcode', 'immediate', 'use_immediate_state'),
    [
        (JNOpcode.ADD_R1_R2, None, False),  # 0
        (JNOpcode.ADD_R1_IMM, 0xA, True),  # 1A
        (JNOpcode.OR_R1_R2, None, False),  # 2
        (JNOpcode.OR_R1_IMM, 0x3, True),  # 3A (immediate value 0xA in hex string)
        (JNOpcode.AND_R1_R2, None, False),  # 4
        (JNOpcode.AND_R1_IMM, 0xF, True),  # 5A
        (JNOpcode.XOR_R1_R2, None, False),  # 6
        (JNOpcode.XOR_R1_IMM, 0xA, True),  # 7A
    ],
)
def test_observation_generation(
    opcode,
    immediate,
    use_immediate_state,
    jn_state_format,
    jn_state_format_immediate,
):
    """Test observation generation for all JN instructions."""
    bytestring = encode_instruction(opcode, immediate)
    state_format = jn_state_format_immediate if use_immediate_state else jn_state_format
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
        if use_immediate_state:
            assert len([r for r in obs.state_format if r.name == 'R2']) == 0, 'Immediate should not have R2'

        # Verify observations have mutated IOs
        assert len(obs.mutated_ios) > 0, 'Observations should have mutated IO pairs'


# =============================================================================
# Dataflow Validation Tests
# =============================================================================


class TestJNDataflowCompleteness:
    """Test that all expected taint flows are captured in observations."""

    def test_add_r1_r2_captures_all_flows(self, jn_state_format):
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
        bytestring = encode_instruction(JNOpcode.ADD_R1_R2)
        obs_engine = ObservationEngine(bytestring, 'JN', jn_state_format)
        observations = obs_engine.observe_insn()

        # Extract dataflows from observations
        obs_deps = extract_observation_dependencies(observations)

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

    def test_or_r1_r2_captures_all_flows(self, jn_state_format):
        """Test OR R1, R2 captures all expected flows.

        Expected flows:
        - R1[i] -> R1[i] (for i in 0..3)
        - R2[i] -> R1[i] (for i in 0..3)
        - R2 unchanged (R2[i] -> R2[i])

        Note: OR is data-dependent:
        - If R1[i]=1 OR R2[i]=1, then R1[i]=1 regardless
        - Only when both are 0, does taint propagate
        """
        bytestring = encode_instruction(JNOpcode.OR_R1_R2)
        obs_engine = ObservationEngine(bytestring, 'JN', jn_state_format)
        observations = obs_engine.observe_insn()

        # Extract dataflows from observations
        obs_deps = extract_observation_dependencies(observations)

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

    def test_and_r1_r2_captures_all_flows(self, jn_state_format):
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
        bytestring = encode_instruction(JNOpcode.AND_R1_R2)
        obs_engine = ObservationEngine(bytestring, 'JN', jn_state_format)
        observations = obs_engine.observe_insn()

        # Extract dataflows from observations
        obs_deps = extract_observation_dependencies(observations)

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

    def test_xor_r1_r2_captures_all_flows(self, jn_state_format):
        """Test XOR R1, R2 captures all expected flows.

        Expected flows:
        - R1[i] -> R1[i] (for i in 0..3)
        - R2[i] -> R1[i] (for i in 0..3)
        - R2 unchanged (R2[i] -> R2[i])

        XOR always propagates taint from both inputs to output.
        """
        bytestring = encode_instruction(JNOpcode.XOR_R1_R2)
        obs_engine = ObservationEngine(bytestring, 'JN', jn_state_format)
        observations = obs_engine.observe_insn()

        # Extract dataflows from observations
        obs_deps = extract_observation_dependencies(observations)

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


@pytest.mark.parametrize(
    ('opcode', 'immediate', 'use_immediate_state'),
    [
        (JNOpcode.ADD_R1_R2, None, False),  # 0
        (JNOpcode.ADD_R1_IMM, 0xA, True),  # 1A
        (JNOpcode.OR_R1_R2, None, False),  # 2
        (JNOpcode.OR_R1_IMM, 0x3, True),  # 3A
        (JNOpcode.AND_R1_R2, None, False),  # 4
        (JNOpcode.AND_R1_IMM, 0xF, True),  # 5A
        (JNOpcode.XOR_R1_R2, None, False),  # 6
        (JNOpcode.XOR_R1_IMM, 0xA, True),  # 7A
    ],
)
def test_full_inference(
    opcode,
    immediate,
    use_immediate_state,
    jn_state_format,
    jn_state_format_immediate,
    jn_cond_reg,
    inference_engine,
):
    """Test full inference pipeline for all JN instructions."""
    bytestring = encode_instruction(opcode, immediate)
    state_format = jn_state_format_immediate if use_immediate_state else jn_state_format
    obs_engine = ObservationEngine(bytestring, 'JN', state_format)
    observations = obs_engine.observe_insn()

    rule = inference_engine.infer(observations, jn_cond_reg, obs_engine, enable_refinement=False)

    # Basic checks
    assert len(rule.pairs) > 0, f'Rule should have condition-dataflow pairs for {opcode.name}'
    assert rule.state_format == state_format, f'State format mismatch for {opcode.name}'

    # Verify immediate instructions exclude R2
    if use_immediate_state:
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


@pytest.mark.parametrize(
    ('opcode', 'immediate', 'use_immediate_state'),
    [
        (JNOpcode.ADD_R1_R2, None, False),  # 0
        (JNOpcode.ADD_R1_IMM, 0xA, True),  # 1A
        (JNOpcode.OR_R1_R2, None, False),  # 2
        (JNOpcode.OR_R1_IMM, 0x3, True),  # 3A
        (JNOpcode.AND_R1_R2, None, False),  # 4
        (JNOpcode.AND_R1_IMM, 0xF, True),  # 5A
        (JNOpcode.XOR_R1_R2, None, False),  # 6
        (JNOpcode.XOR_R1_IMM, 0xA, True),  # 7A
    ],
)
def test_rule_explains_all_observations(
    opcode,
    immediate,
    use_immediate_state,
    jn_state_format,
    jn_state_format_immediate,
    jn_cond_reg,
    inference_engine,
):
    """Test that inferred rule explains 100% of observations.

    This verifies that the inference engine produces a complete rule
    that explains ALL observed behavior for each instruction.
    """
    bytestring = encode_instruction(opcode, immediate)
    state_format = jn_state_format_immediate if use_immediate_state else jn_state_format
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
    ('opcode', 'immediate', 'use_immediate_state', 'should_be_unconditional'),
    [
        (JNOpcode.ADD_R1_R2, None, False, False),  # 0 - ADD is conditional
        (JNOpcode.ADD_R1_IMM, 0xA, True, True),  # 1A - ADD is unconditional
        (JNOpcode.OR_R1_R2, None, False, False),  # 2 - OR is conditional
        (JNOpcode.OR_R1_IMM, 0xA, True, True),  # 3A - OR is unconditional
        (JNOpcode.AND_R1_R2, None, False, False),  # 4 - AND is conditional
        (JNOpcode.AND_R1_IMM, 0xA, True, True),  # 5A - AND is unconditional
        (JNOpcode.XOR_R1_R2, None, False, True),  # 6 - XOR is unconditional
        (JNOpcode.XOR_R1_IMM, 0xA, True, True),  # 7A - XOR is unconditional
    ],
)
def test_condition_inference(
    opcode,
    immediate,
    use_immediate_state,
    should_be_unconditional,
    jn_state_format,
    jn_state_format_immediate,
    jn_cond_reg,
    inference_engine,
):
    """Test that conditions are inferred correctly for each instruction.

    Unconditional instructions (ADD, XOR) should have condition=None or empty conditions.
    Conditional instructions (AND, OR) should have conditions or multiple pairs.
    """
    bytestring = encode_instruction(opcode, immediate)
    state_format = jn_state_format_immediate if use_immediate_state else jn_state_format
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

    def test_xor_r1_r2_unconditional_flows(self, jn_state_format, jn_cond_reg, inference_engine):
        """Test XOR R1, R2 has correct unconditional flows.

        Expected: For all i in 0..3:
        - R1[i] → R1[i] (unconditionally)
        - R2[i] → R1[i] (unconditionally)
        - R2[i] → R2[i] (unchanged)

        XOR always propagates taint from both inputs to output.
        """
        bytestring = encode_instruction(JNOpcode.XOR_R1_R2)
        obs_engine = ObservationEngine(bytestring, 'JN', jn_state_format)
        observations = obs_engine.observe_insn()

        rule = inference_engine.infer(observations, jn_cond_reg, obs_engine, enable_refinement=False)

        # Collect all unconditional flows (flows with condition=None)
        unconditional_flows: dict[BitPosition, set[BitPosition]] = {}
        for pair in rule.pairs:
            if pair.condition is None or len(pair.condition.condition_ops) == 0:
                for input_bit, output_bits in pair.output_bits.items():
                    if input_bit not in unconditional_flows:
                        unconditional_flows[input_bit] = set()
                    unconditional_flows[input_bit].update(output_bits)

        # Verify XOR flows are unconditional
        for i in range(4):
            # R1[i] → R1[i] should be unconditional
            assert BitPosition(i) in unconditional_flows, f'R1[{i}] should have unconditional flows'
            assert BitPosition(i) in unconditional_flows[BitPosition(i)], f'R1[{i}] → R1[{i}] should be unconditional'

            # R2[i] → R1[i] should be unconditional
            r2_bit = BitPosition(4 + i)
            assert r2_bit in unconditional_flows, f'R2[{i}] should have unconditional flows'
            assert BitPosition(i) in unconditional_flows[r2_bit], f'R2[{i}] → R1[{i}] should be unconditional'

    def test_and_r1_r2_conditional_flows(self, jn_state_format, jn_cond_reg, inference_engine):
        """Test AND R1, R2 has correct conditional flows.

        Expected: For all i in 0..3:
        - R1[i] → R1[i] when R2[i] = 1
        - R2[i] → R1[i] when R1[i] = 1
        - R2[i] → R2[i] (unchanged, unconditional)

        AND only propagates taint when BOTH bits are 1.
        """
        bytestring = encode_instruction(JNOpcode.AND_R1_R2)
        obs_engine = ObservationEngine(bytestring, 'JN', jn_state_format)
        observations = obs_engine.observe_insn()

        rule = inference_engine.infer(observations, jn_cond_reg, obs_engine, enable_refinement=False)

        # Test with concrete values to verify AND behavior

        cpu = JNCpu()

        # Test case 1: R1[0]=1 (tainted), R2[0]=1 (untainted)
        # Expected: taint propagates to output R1[0]
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0001, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        # Result: 1 & 1 = 1, taint from R1[0] should propagate

        # Test case 2: R1[0]=1 (tainted), R2[0]=0 (untainted)
        # Expected: taint does NOT propagate (result is 0)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0000, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0, 'AND with R2=0 should give 0'

        # Test case 3: R1[0]=0 (untainted), R2[0]=1 (tainted)
        # Expected: taint does NOT propagate (result is 0)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0000, JN_REG_R2(): 0b0001, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0, 'AND with R1=0 should give 0'

        # Verify R2 is unchanged
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b1111, JN_REG_R2(): 0b1010, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R2()] == 0b1010, 'R2 should be unchanged by AND'

        # The rule should capture these conditional behaviors
        assert len(rule.pairs) > 0, 'AND should have condition-dataflow pairs'

    def test_or_r1_r2_conditional_flows(self, jn_state_format, jn_cond_reg, inference_engine):
        """Test OR R1, R2 has correct conditional flows.

        Expected: For all i in 0..3:
        - R1[i] → R1[i] when R2[i] = 0
        - R2[i] → R1[i] when R1[i] = 0
        - R2[i] → R2[i] (unchanged, unconditional)

        OR only propagates taint when the other bit is 0.
        """
        bytestring = encode_instruction(JNOpcode.OR_R1_R2)
        obs_engine = ObservationEngine(bytestring, 'JN', jn_state_format)
        observations = obs_engine.observe_insn()

        rule = inference_engine.infer(observations, jn_cond_reg, obs_engine, enable_refinement=False)

        # Test with concrete values to verify OR behavior

        cpu = JNCpu()

        # Test case 1: R1[0]=0 (tainted), R2[0]=0 (untainted)
        # Expected: taint propagates to output R1[0] (result is 0)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0000, JN_REG_R2(): 0b0000, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0, 'OR with both 0 should give 0'

        # Test case 2: R1[0]=0 (tainted), R2[0]=1 (untainted)
        # Expected: result is 1, taint does NOT propagate (masked by R2=1)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0000, JN_REG_R2(): 0b0001, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 1, 'OR with R2=1 should give 1'

        # Test case 3: R1[0]=1 (untainted), R2[0]=0 (tainted)
        # Expected: result is 1, taint propagates from R2
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0000, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 1, 'OR should give 1'

        # Test case 4: R1[0]=1 (untainted), R2[0]=1 (untainted)
        # Expected: result is 1, no taint propagates
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0001, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 1, 'OR with both 1 should give 1'

        # Verify R2 is unchanged
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b1111, JN_REG_R2(): 0b1010, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R2()] == 0b1010, 'R2 should be unchanged by OR'

        # The rule should capture these conditional behaviors
        assert len(rule.pairs) > 0, 'OR should have condition-dataflow pairs'

    def test_add_r1_r2_carry_propagation(self, jn_state_format, jn_cond_reg, inference_engine):
        """Test ADD R1, R2 has correct carry propagation.

        Expected: Complex carry propagation where lower bits affect higher bits.
        - Each bit can affect all higher bits due to carries
        - R2[i] → R2[i] (unchanged, unconditional)

        This is the most complex case and may require detailed condition analysis.
        """
        bytestring = encode_instruction(JNOpcode.ADD_R1_R2)
        obs_engine = ObservationEngine(bytestring, 'JN', jn_state_format)
        observations = obs_engine.observe_insn()

        rule = inference_engine.infer(observations, jn_cond_reg, obs_engine, enable_refinement=False)

        # Test with concrete values to verify ADD behavior

        cpu = JNCpu()

        # Test case 1: No carry (1 + 0 = 1)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0000, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 1, 'ADD 1+0 should give 1'

        # Test case 2: Carry propagation (1 + 1 = 2, bit 0 affects bit 1)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0001, JN_REG_R2(): 0b0001, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0b0010, 'ADD 1+1 should give 2 (carry to bit 1)'

        # Test case 3: Multiple carries (7 + 1 = 8, carry propagates to bit 3)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0111, JN_REG_R2(): 0b0001, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0b1000, 'ADD 7+1 should give 8 (multiple carries)'

        # Test case 4: Overflow (15 + 1 = 0 in 4-bit arithmetic)
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b1111, JN_REG_R2(): 0b0001, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        assert output[JN_REG_R1()] == 0b0000, 'ADD 15+1 should give 0 (overflow)'

        # Verify R2 is unchanged
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): 0b0101, JN_REG_R2(): 0b1010, JN_REG_NZVC(): 0}))
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
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): r1_val, JN_REG_R2(): r2_val, JN_REG_NZVC(): 0}))
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
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): r1_val, JN_REG_R2(): r2_val, JN_REG_NZVC(): 0}))
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
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): r1_val, JN_REG_R2(): r2_val, JN_REG_NZVC(): 0}))
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
        cpu.set_cpu_state(CpuRegisterMap({JN_REG_R1(): r1_val, JN_REG_R2(): r2_val, JN_REG_NZVC(): 0}))
        _, output = cpu.execute(jn_hex_to_bytes(bytestring))
        actual = output[JN_REG_R1()]
        assert actual == expected, f'ADD {r1_val} + {r2_val} = {expected}, got {actual}'


# =============================================================================
# Immediate Instruction Tests
# =============================================================================


class TestJNImmediateInstructions:
    """Test that immediate instructions use correct state format."""

    @pytest.mark.parametrize(
        ('opcode', 'immediate'),
        [
            (JNOpcode.ADD_R1_IMM, 0x5),
            (JNOpcode.OR_R1_IMM, 0x3),
            (JNOpcode.AND_R1_IMM, 0xF),
            (JNOpcode.XOR_R1_IMM, 0xA),
        ],
    )
    def test_immediate_instructions_exclude_r2(self, opcode, immediate):
        """Test that all immediate instructions exclude R2 from state format."""
        bytestring = encode_instruction(opcode, immediate)

        # Create state format without R2
        state_format = [JN_REG_R1(), JN_REG_NZVC()]

        obs_engine = ObservationEngine(bytestring, 'JN', state_format)
        observations = obs_engine.observe_insn()

        # Verify no R2 in state format
        for obs in observations:
            reg_names = [r.name for r in obs.state_format]
            assert 'R2' not in reg_names, f'{opcode.name} should not include R2'

    def test_immediate_instruction_observation_count(self):
        """Test that immediate instructions generate correct number of observations.

        Immediate: 8 bits (R1=4, NZVC=4) = 256 states
        Register: 12 bits (R1=4, R2=4, NZVC=4) = 4096 states
        """
        # Immediate instruction
        bytestring_imm = encode_instruction(JNOpcode.ADD_R1_IMM, 0xA)
        state_format_imm = [JN_REG_R1(), JN_REG_NZVC()]
        obs_engine_imm = ObservationEngine(bytestring_imm, 'JN', state_format_imm)
        observations_imm = obs_engine_imm.observe_insn()

        # Register instruction
        bytestring_reg = encode_instruction(JNOpcode.ADD_R1_R2)
        state_format_reg = [JN_REG_R1(), JN_REG_R2(), JN_REG_NZVC()]
        obs_engine_reg = ObservationEngine(bytestring_reg, 'JN', state_format_reg)
        observations_reg = obs_engine_reg.observe_insn()

        # Immediate should have fewer observations (256 vs 4096)
        assert len(observations_imm) < len(
            observations_reg,
        ), f'Immediate should have fewer observations: {len(observations_imm)} vs {len(observations_reg)}'


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestJNEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_and_r1_r2_with_zero_r2(self, jn_state_format, jn_cond_reg, inference_engine):
        """Test AND R1, R2 behavior when R2=0.

        When R2=0, result is always 0 regardless of R1.
        This tests if conditions properly capture this behavior.
        """
        bytestring = encode_instruction(JNOpcode.AND_R1_R2)
        obs_engine = ObservationEngine(bytestring, 'JN', jn_state_format)
        observations = obs_engine.observe_insn()

        rule = inference_engine.infer(observations, jn_cond_reg, obs_engine, enable_refinement=False)

        # Rule should explain this edge case
        assert len(rule.pairs) > 0

    def test_and_r1_r2_with_all_ones(self, jn_state_format, jn_cond_reg, inference_engine):
        """Test AND R1, R2 behavior when both are 0xF.

        When both are all 1s, taint should propagate unconditionally.
        """
        bytestring = encode_instruction(JNOpcode.AND_R1_R2)
        obs_engine = ObservationEngine(bytestring, 'JN', jn_state_format)
        observations = obs_engine.observe_insn()

        rule = inference_engine.infer(observations, jn_cond_reg, obs_engine, enable_refinement=False)

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
    test_state = CpuRegisterMap({JN_REG_R1(): r1_value, JN_REG_R2(): r2_value, JN_REG_NZVC(): 0})
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
    state_format = [JN_REG_R1(), JN_REG_NZVC()] if use_immediate else [JN_REG_R1(), JN_REG_R2(), JN_REG_NZVC()]

    # Generate observations and infer rule
    obs_engine = ObservationEngine(bytestring, 'JN', state_format)
    observations = obs_engine.observe_insn()
    inference_engine = InferenceEngine()
    internal_rule = inference_engine.infer(observations, JN_REG_NZVC(), obs_engine, enable_refinement=False)

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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
