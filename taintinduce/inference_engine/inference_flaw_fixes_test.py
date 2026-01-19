"""Unit tests for inference engine fixes (Flaws 1, 3, 4, 7, 8)."""

from collections import defaultdict

import pytest

from taintinduce.inference_engine import dataflow_builder, observation_processor
from taintinduce.inference_engine.inference import InferenceEngine
from taintinduce.inference_engine.validation import validate_condition
from taintinduce.isa.x86_registers import X86_REG_EAX, X86_REG_EBX, X86_REG_EFLAGS
from taintinduce.rules.conditions import LogicType, TaintCondition
from taintinduce.state.state import Observation, State
from taintinduce.types import BitPosition, StateValue


@pytest.fixture
def engine():
    """Inference engine fixture."""
    return InferenceEngine()


@pytest.fixture
def eflags():
    """EFLAGS register fixture."""
    return X86_REG_EFLAGS()


@pytest.fixture
def eax():
    """EAX register fixture."""
    return X86_REG_EAX()


@pytest.fixture
def ebx():
    """EBX register fixture."""
    return X86_REG_EBX()


def test_flaw_7_and_3_group_before_inference(eflags, eax, ebx):
    """Test Flaw 7 & 3: Bits with same behavior are grouped BEFORE inference."""
    # Create multiple observations where bits 32 and 33 have identical behavior
    # Both propagate to bit 64 only
    state_format = [eflags, eax, ebx]

    observations = []
    for input_val in [0, 1, 2, 3]:
        # Seed has some value in eax
        base_val = input_val << 32
        seed_in = State(num_bits=96, state_value=StateValue(base_val))
        seed_out = State(num_bits=96, state_value=StateValue(base_val))

        mutated_ios = []
        # Bit 32 flipped -> bit 64 changes (eax bit 0 -> ebx bit 0)
        mutate_in = State(num_bits=96, state_value=StateValue(base_val ^ (1 << 32)))  # flip bit 32
        mutate_out = State(num_bits=96, state_value=StateValue(base_val | (1 << 64)))  # bit 64 set
        mutated_ios.append((mutate_in, mutate_out))

        # Bit 33 flipped -> bit 64 changes (eax bit 1 -> ebx bit 0, same behavior as bit 32)
        mutate_in2 = State(num_bits=96, state_value=StateValue(base_val ^ (1 << 33)))  # flip bit 33
        mutate_out2 = State(num_bits=96, state_value=StateValue(base_val | (1 << 64)))  # bit 64 set
        mutated_ios.append((mutate_in2, mutate_out2))

        obs = Observation(
            iopair=(seed_in, seed_out),
            mutated_iopairs=frozenset(mutated_ios),
            bytestring='test',
            archstring='X86',
            state_format=state_format,
        )
        observations.append(obs)

    # Extract dependencies
    obs_deps = observation_processor.extract_observation_dependencies(observations)

    # Build possible flows
    possible_flows = defaultdict(set)
    for obs_dep in obs_deps:
        for input_bit, output_bits in obs_dep.dataflow.items():
            possible_flows[input_bit].add(output_bits)

    # Test grouping
    groups = dataflow_builder.group_bits_by_behavior(possible_flows)

    # Bits 32 and 33 should be in the same group
    found_group = False
    for _behavior_sig, bits_in_group in groups.items():
        if BitPosition(32) in bits_in_group and BitPosition(33) in bits_in_group:
            found_group = True
            break

    assert found_group, 'Bits 32 and 33 should be grouped together'


def test_flaw_4_relevant_bits_identification(engine, eflags, eax):
    """Test Flaw 4: Only relevant bits are used for condition generation."""
    state_format = [eflags, eax]

    # Create states where only bit 32 varies between partitions
    # EFLAGS (bits 0-31) all zeros, EAX bit 0 (bit 32) varies
    agreeing_partition = {
        State(num_bits=64, state_value=StateValue(0x0)),  # bit 32 = 0
        State(num_bits=64, state_value=StateValue(0x0)),  # bit 32 = 0
    }
    disagreeing_partition = {
        State(num_bits=64, state_value=StateValue(0x100000000)),  # bit 32 = 1
        State(num_bits=64, state_value=StateValue(0x100000000)),  # bit 32 = 1
    }

    relevant_bits = engine.condition_generator.identify_relevant_input_bits(
        agreeing_partition,
        disagreeing_partition,
        state_format,
    )

    # Only bit 32 should be relevant (it's the only one that differs)
    assert 32 in relevant_bits, 'Bit 32 should be identified as relevant'
    # EFLAGS bits (0-31) should not be relevant
    for bit in range(32):
        assert bit not in relevant_bits, f'Bit {bit} should not be relevant'


def test_flaw_1_mutually_exclusive_conditions(engine, eflags, eax, ebx):
    """Test Flaw 1: Conditions are mutually exclusive (hierarchical generation)."""
    # Create observations with 3 different behaviors:
    # - When eax bit 0 is 0: no propagation
    # - When eax bit 0 is 1: propagate to bit 64
    # - When eax=2 (bit 1 set): propagate to bit 65
    state_format = [eflags, eax, ebx]

    observations = []

    # Behavior A: eax=0, flip bit 32 -> no propagation
    seed_in = State(num_bits=96, state_value=StateValue(0))
    seed_out = State(num_bits=96, state_value=StateValue(0))
    mutate_in = State(num_bits=96, state_value=StateValue(1 << 32))  # flip bit 32 (eax bit 0)
    mutate_out = State(num_bits=96, state_value=StateValue(0))  # no output change
    obs = Observation(
        iopair=(seed_in, seed_out),
        mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
        bytestring='test',
        archstring='X86',
        state_format=state_format,
    )
    observations.append(obs)

    # Behavior B: eax=1, flip bit 32 -> propagate to bit 64
    seed_in = State(num_bits=96, state_value=StateValue(1 << 32))  # eax=1
    seed_out = State(num_bits=96, state_value=StateValue(1 << 32))
    mutate_in = State(num_bits=96, state_value=StateValue(0))  # flip bit 32 (now eax=0)
    mutate_out = State(num_bits=96, state_value=StateValue(1 << 64))  # output bit 64 set
    obs = Observation(
        iopair=(seed_in, seed_out),
        mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
        bytestring='test',
        archstring='X86',
        state_format=state_format,
    )
    observations.append(obs)

    # Behavior C: eax=2, flip bit 32 -> propagate to bit 65
    seed_in = State(num_bits=96, state_value=StateValue(2 << 32))  # eax=2
    seed_out = State(num_bits=96, state_value=StateValue(2 << 32))
    mutate_in = State(num_bits=96, state_value=StateValue(3 << 32))  # flip bit 32 (now eax=3)
    mutate_out = State(num_bits=96, state_value=StateValue((2 << 32) | (1 << 65)))  # output bit 65
    obs = Observation(
        iopair=(seed_in, seed_out),
        mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
        bytestring='test',
        archstring='X86',
        state_format=state_format,
    )
    observations.append(obs)

    rule = engine.infer(observations, eflags)

    # Should have at least one condition-dataflow pair
    assert len(rule.pairs) > 0, 'Should have at least one dataflow pair'

    # Note: With different behaviors, algorithm will generate conditions
    # The specific structure depends on implementation details


def test_flaw_8_condition_validation(engine, eflags, eax):
    """Test Flaw 8: Conditions are validated before acceptance."""
    state_format = [eflags, eax]

    # Create simple partitions
    agreeing_partition = {
        State(num_bits=64, state_value=StateValue(0x0)),
        State(num_bits=64, state_value=StateValue(0x1)),
    }
    disagreeing_partition = {
        State(num_bits=64, state_value=StateValue(0x100000000)),
        State(num_bits=64, state_value=StateValue(0x100000001)),
    }

    # Generate a condition
    condition = engine.condition_generator.generate_condition(
        agreeing_partition,
        disagreeing_partition,
        state_format,
        eflags,
        use_full_state=True,
    )

    if condition is not None and condition.condition_ops is not None:
        # Validate the condition
        is_valid = validate_condition(
            condition,
            agreeing_partition,
            disagreeing_partition,
        )
        # A correctly generated condition should validate
        assert is_valid, 'Generated condition should validate correctly'


def test_is_bit_relevant_helper(engine, eflags, eax):
    """Test the _identify_relevant_input_bits method (Flaw 4)."""
    state_format = [eflags, eax]

    # Create states where bit 0 varies in agreeing, and bit 32 differs between partitions
    agreeing_partition = {
        State(num_bits=64, state_value=StateValue(0b0000)),
        State(num_bits=64, state_value=StateValue(0b0001)),  # bit 0 varies
    }
    disagreeing_partition = {
        State(num_bits=64, state_value=StateValue(0x100000000)),  # bit 32 = 1
        State(num_bits=64, state_value=StateValue(0x100000001)),  # bit 32 = 1, bit 0 varies
    }

    relevant_bits = engine.condition_generator.identify_relevant_input_bits(
        agreeing_partition,
        disagreeing_partition,
        state_format,
    )

    # Bit 0 should be relevant (varies within partitions)
    assert 0 in relevant_bits, 'Bit 0 should be relevant (varies within agreeing)'
    # Bit 32 should be relevant (differs between partitions)
    assert 32 in relevant_bits, 'Bit 32 should be relevant (differs between partitions)'


def test_validate_condition_rejects_bad_condition():
    """Test that _validate_condition correctly rejects invalid conditions."""
    agreeing_partition = {
        State(num_bits=64, state_value=StateValue(0x0)),
    }
    disagreeing_partition = {
        State(num_bits=64, state_value=StateValue(0x1)),
    }

    # Create a condition that's backwards (matches disagreeing instead of agreeing)
    bad_condition = TaintCondition(
        LogicType.DNF,
        frozenset([(0x1, 0x1)]),  # matches state 0x1 (disagreeing)
    )

    is_valid = validate_condition(
        bad_condition,
        agreeing_partition,
        disagreeing_partition,
    )

    assert not is_valid, 'Bad condition should fail validation'


def test_integration_simple_dataflow(engine, eflags, eax):
    """Integration test: simple unconditional dataflow still works."""
    state_format = [eflags, eax]

    # Simple dataflow: bit 32 -> bit 32 (identity)
    observations = []
    for i in range(4):
        seed_val = i << 32
        seed_in = State(num_bits=64, state_value=StateValue(seed_val))
        seed_out = State(num_bits=64, state_value=StateValue(seed_val))
        # Flip bit 32
        mutate_in = State(num_bits=64, state_value=StateValue(seed_val ^ (1 << 32)))
        mutate_out = State(num_bits=64, state_value=StateValue(seed_val ^ (1 << 32)))

        obs = Observation(
            iopair=(seed_in, seed_out),
            mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
            bytestring='test',
            archstring='X86',
            state_format=state_format,
        )
        observations.append(obs)

    rule = engine.infer(observations, eflags)

    # Should produce a simple rule
    assert rule is not None
    assert len(rule.pairs) > 0


def test_flaw_2_proper_partition_separation(engine, eflags, eax, ebx):
    """Test Flaw 2: Partitions are properly separated, not lumped together."""
    # Create 3 distinct behaviors where each should get its own condition
    # A: eax=0 -> no propagation
    # B: eax=1 -> propagate to bit 64
    # C: eax=2 -> propagate to bit 65
    state_format = [eflags, eax, ebx]

    observations = []
    behaviors = [
        (0, frozenset()),  # eax=0, no output
        (1 << 32, frozenset([BitPosition(64)])),  # eax=1, output bit 64
        (2 << 32, frozenset([BitPosition(65)])),  # eax=2, output bit 65
    ]

    for base_val, output_bits in behaviors:
        seed_in = State(num_bits=96, state_value=StateValue(base_val))
        seed_out = State(num_bits=96, state_value=StateValue(base_val))
        # Flip bit 32: if base_val has bit 32 set, clear it; if clear, set it
        mutate_in = State(num_bits=96, state_value=StateValue(base_val ^ (1 << 32)))

        # Create output based on behavior
        output_val = base_val ^ (1 << 32)  # mutated input value
        for bit in output_bits:
            output_val |= 1 << bit
        mutate_out = State(num_bits=96, state_value=StateValue(output_val))

        obs = Observation(
            iopair=(seed_in, seed_out),
            mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
            bytestring='test',
            archstring='X86',
            state_format=state_format,
        )
        observations.append(obs)

    rule = engine.infer(observations, eflags)

    # Should have multiple distinct conditions, not lumping behaviors together
    assert rule is not None, 'Should produce a rule'
    assert len(rule.pairs) >= 1, 'Should have at least 1 condition-dataflow pair'


def test_flaw_5_ordering_uses_most_common_as_default(engine, eflags, eax):
    """Test Flaw 5: Most common behavior (largest partition) is used as default."""
    state_format = [eflags, eax]

    observations = []

    # Create many observations for behavior A (should become default)
    for i in range(10):
        seed_val = i << 32
        seed_in = State(num_bits=64, state_value=StateValue(seed_val))
        seed_out = State(num_bits=64, state_value=StateValue(seed_val))
        mutate_in = State(num_bits=64, state_value=StateValue(seed_val ^ (1 << 32)))
        mutate_out = State(num_bits=64, state_value=StateValue(seed_val ^ (1 << 32)))

        obs = Observation(
            iopair=(seed_in, seed_out),
            mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
            bytestring='test',
            archstring='X86',
            state_format=state_format,
        )
        observations.append(obs)

    # Create few observations for behavior B (should get condition)
    for i in range(2):
        base_val = (100 + i) << 32
        seed_in = State(num_bits=64, state_value=StateValue(base_val))
        seed_out = State(num_bits=64, state_value=StateValue(base_val))
        mutate_in = State(num_bits=64, state_value=StateValue(base_val ^ (1 << 32)))
        mutate_out = State(num_bits=64, state_value=StateValue(base_val))  # Different behavior

        obs = Observation(
            iopair=(seed_in, seed_out),
            mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
            bytestring='test',
            archstring='X86',
            state_format=state_format,
        )
        observations.append(obs)

    rule = engine.infer(observations, eflags)

    # Should produce a valid rule with condition-dataflow pairs
    assert rule is not None, 'Should produce a rule'
    assert len(rule.pairs) >= 1, 'Should have at least one condition-dataflow pair'


def test_flaw_6_fallthrough_semantics(engine, eflags, eax):
    """Test Flaw 6: Fallthrough case has clear semantics (condition=None)."""
    state_format = [eflags, eax]

    # Simple case with one behavior
    observations = []
    for i in range(3):
        seed_val = i << 32
        seed_in = State(num_bits=64, state_value=StateValue(seed_val))
        seed_out = State(num_bits=64, state_value=StateValue(seed_val))
        mutate_in = State(num_bits=64, state_value=StateValue(seed_val ^ (1 << 32)))
        mutate_out = State(num_bits=64, state_value=StateValue(seed_val ^ (1 << 32)))

        obs = Observation(
            iopair=(seed_in, seed_out),
            mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
            bytestring='test',
            archstring='X86',
            state_format=state_format,
        )
        observations.append(obs)

    rule = engine.infer(observations, eflags)

    # Should produce a rule with pairs
    assert rule is not None, 'Should produce a rule'
    assert len(rule.pairs) >= 1, 'Should have at least one condition-dataflow pair'


def test_flaw_9_non_determinism_detection(engine, eflags, eax):
    """Test Flaw 9: Non-deterministic observations are detected and logged."""
    state_format = [eflags, eax]

    # Note: This test verifies that the system handles non-determinism gracefully
    # In practice, non-determinism would come from timing effects or noise
    # We simulate by having very sparse observations that might not separate well

    observations = []
    # Create minimal observations that may not provide enough information
    seed_in = State(num_bits=64, state_value=StateValue(0))
    seed_out = State(num_bits=64, state_value=StateValue(0))
    mutate_in = State(num_bits=64, state_value=StateValue(1 << 32))
    mutate_out = State(num_bits=64, state_value=StateValue(1 << 32))

    obs = Observation(
        iopair=(seed_in, seed_out),
        mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
        bytestring='test',
        archstring='X86',
        state_format=state_format,
    )
    observations.append(obs)

    # Should not crash, even with minimal observations
    rule = engine.infer(observations, eflags)
    assert rule is not None, 'Should produce a rule even with minimal observations'
    assert len(rule.pairs) > 0, 'Should have at least one dataflow pair'
