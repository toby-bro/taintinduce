"""Negative test cases to verify validation correctly detects incorrect rules."""

from taintinduce.inference_engine.observation_processor import extract_observation_dependencies
from taintinduce.inference_engine.validation import validate_rule_explains_observations
from taintinduce.isa.jn_isa import JNOpcode, encode_instruction
from taintinduce.isa.jn_registers import JN_REG_NZCV, JN_REG_R1, JN_REG_R2
from taintinduce.observation_engine.observation import ObservationEngine
from taintinduce.rules.conditions import LogicType, TaintCondition
from taintinduce.rules.rules import ConditionDataflowPair, GlobalRule
from taintinduce.types import BitPosition


def test_validation_detects_incomplete_rule():
    """Test that validation fails when rule doesn't cover all observed behaviors."""
    # Setup: Generate observations for XOR R1, R2
    state_format = [JN_REG_R1(), JN_REG_R2(), JN_REG_NZCV()]
    bytestring = encode_instruction(JNOpcode.XOR_R1_R2, None)

    obs_engine = ObservationEngine(bytestring, 'JN', state_format)
    observations = obs_engine.observe_insn()

    # Extract observation dependencies
    obs_deps = extract_observation_dependencies(observations)

    # Create an INCOMPLETE rule: only include R2 -> R2 flows, missing R1 and R2 -> R1 flows
    # This should cause validation to fail
    # Only add R2 bits mapping to themselves (bits 4-7 -> 4-7)

    incomplete_rule = GlobalRule(
        state_format,
        pairs=[
            ConditionDataflowPair(condition=None, input_bit=BitPosition(4), output_bits=frozenset({BitPosition(4)})),
        ],
    )

    # Validate: should detect that many behaviors are unexplained
    explained, total = validate_rule_explains_observations(incomplete_rule, obs_deps)

    # Assert: validation should show incomplete coverage
    assert explained < total, f'Validation should detect incomplete rule, but reported {explained}/{total} explained'
    # For XOR with 12 input bits, we expect lots of observations
    # The incomplete rule only covers 4 R2 bits, so should explain much less than 50%
    coverage = explained / total if total > 0 else 0
    assert coverage < 0.5, f'Incomplete rule should explain less than 50%, but got {coverage:.1%}'


def test_validation_detects_wrong_condition():
    """Test that validation fails when rule has wrong conditions."""
    # Setup: Generate observations for OR R1, R2
    state_format = [JN_REG_R1(), JN_REG_R2(), JN_REG_NZCV()]
    bytestring = encode_instruction(JNOpcode.OR_R1_R2, None)

    obs_engine = ObservationEngine(bytestring, 'JN', state_format)
    observations = obs_engine.observe_insn()

    # Extract observation dependencies
    obs_deps = extract_observation_dependencies(observations)

    # Create a rule with WRONG condition
    # For OR: R1[0] affects R1[0] when R2[0] = 0 (correct)
    # But we'll use the AND condition: R2[0] = 1 (wrong)
    wrong_condition = TaintCondition(
        LogicType.DNF,
        frozenset([(1 << 4, 1 << 4)]),  # R2[0] = 1 (AND condition, wrong for OR)
        None,
    )

    wrong_dataflow = frozenset({BitPosition(0)})

    wrong_rule = GlobalRule(
        state_format,
        pairs=[
            ConditionDataflowPair(condition=wrong_condition, input_bit=BitPosition(0), output_bits=wrong_dataflow),
        ],
    )

    # Validate: should detect that the condition is wrong
    explained, total = validate_rule_explains_observations(wrong_rule, obs_deps)

    # Assert: validation should show incomplete coverage due to wrong condition
    assert explained < total, f'Validation should detect wrong condition, but reported {explained}/{total} explained'
    # With wrong condition, should explain much less than the observations
    coverage = explained / total if total > 0 else 0
    assert coverage < 0.9, f'Rule with wrong condition should explain less than 90%, but got {coverage:.1%}'


def test_validation_detects_missing_outputs():
    """Test that validation fails when rule is missing some output bits."""
    # Setup: Generate observations for ADD R1, R2
    state_format = [JN_REG_R1(), JN_REG_R2(), JN_REG_NZCV()]
    bytestring = encode_instruction(JNOpcode.ADD_R1_R2, None)

    obs_engine = ObservationEngine(bytestring, 'JN', state_format)
    observations = obs_engine.observe_insn()

    # Extract observation dependencies
    obs_deps = extract_observation_dependencies(observations)

    # Create a rule that's missing flag outputs
    # ADD affects R1 bits and NZCV flags, but we'll only include R1 bits
    incomplete_dataflow = frozenset({BitPosition(i) for i in range(4)})

    incomplete_rule = GlobalRule(
        state_format,
        pairs=[ConditionDataflowPair(condition=None, input_bit=BitPosition(4), output_bits=incomplete_dataflow)],
    )

    # Validate: should detect missing flag outputs
    explained, total = validate_rule_explains_observations(incomplete_rule, obs_deps)

    # Assert: validation should show incomplete coverage
    assert explained < total, f'Validation should detect missing outputs, but reported {explained}/{total} explained'
    # Missing all flag outputs, should explain significantly less
    coverage = explained / total if total > 0 else 0
    assert coverage < 0.8, f'Rule missing flag outputs should explain less than 80%, but got {coverage:.1%}'
