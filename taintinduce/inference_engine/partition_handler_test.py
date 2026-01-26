"""Tests for partition handler functions.

Tests for the current partition_handler API including:
- get_non_redundant_inputs_and_relevant_output_refs
- evaluate_output_bit_taint_states
- is_output_tainted
- augment_states_with_output_bit_taints
- handle_multiple_partitions_output_centric
"""

from taintinduce.rules.conditions import LogicType, OutputBitRef, TaintCondition
from taintinduce.rules.rules import ConditionDataflowPair
from taintinduce.state.state import State
from taintinduce.types import BitPosition, StateValue

from .partition_handler import (
    augment_states_with_output_bit_taints,
    evaluate_output_bit_taint_states,
    get_non_redundant_inputs_and_relevant_output_refs,
    is_output_tainted,
)


class TestGetNonRedundantInputsAndRelevantOutputRefs:
    """Tests for get_non_redundant_inputs_and_relevant_output_refs function."""

    def test_no_completed_outputs_returns_all_inputs(self) -> None:
        """When no completed outputs, should return all input bits and no refs."""
        studied_output = BitPosition(10)
        completed_outputs: frozenset[BitPosition] = frozenset()
        outputs_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0), BitPosition(1), BitPosition(2)]),
        }

        filtered_bits, output_refs = get_non_redundant_inputs_and_relevant_output_refs(
            studied_output,
            completed_outputs,
            outputs_to_inputs,
        )

        assert filtered_bits == frozenset([BitPosition(0), BitPosition(1), BitPosition(2)])
        assert len(output_refs) == 0

    def test_subset_outputs_included_as_refs(self) -> None:
        """Completed outputs with subset inputs should be included as refs."""
        studied_output = BitPosition(10)
        completed_outputs = frozenset([BitPosition(8), BitPosition(9)])
        outputs_to_inputs = {
            BitPosition(8): frozenset([BitPosition(0)]),  # Subset
            BitPosition(9): frozenset([BitPosition(0), BitPosition(1)]),  # Subset
            BitPosition(10): frozenset([BitPosition(0), BitPosition(1), BitPosition(2)]),  # Studied
        }

        _filtered_bits, output_refs = get_non_redundant_inputs_and_relevant_output_refs(
            studied_output,
            completed_outputs,
            outputs_to_inputs,
        )

        assert len(output_refs) == 2
        assert OutputBitRef(BitPosition(8)) in output_refs
        assert OutputBitRef(BitPosition(9)) in output_refs

    def test_superset_outputs_excluded(self) -> None:
        """Completed outputs with superset inputs should NOT be included."""
        studied_output = BitPosition(10)
        completed_outputs = frozenset([BitPosition(11)])
        outputs_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0), BitPosition(1)]),  # Studied
            BitPosition(11): frozenset([BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)]),  # Superset
        }

        _filtered_bits, output_refs = get_non_redundant_inputs_and_relevant_output_refs(
            studied_output,
            completed_outputs,
            outputs_to_inputs,
        )

        assert len(output_refs) == 0

    def test_filters_multiply_covered_input_bits(self) -> None:
        """Input bits appearing in 2+ subset flows should be filtered."""
        studied_output = BitPosition(10)
        completed_outputs = frozenset([BitPosition(8), BitPosition(9)])
        outputs_to_inputs = {
            BitPosition(8): frozenset([BitPosition(0), BitPosition(1)]),  # Covers 0,1
            BitPosition(9): frozenset([BitPosition(1), BitPosition(2)]),  # Covers 1,2
            BitPosition(10): frozenset([BitPosition(0), BitPosition(1), BitPosition(2)]),  # Studied
        }

        filtered_bits, _output_refs = get_non_redundant_inputs_and_relevant_output_refs(
            studied_output,
            completed_outputs,
            outputs_to_inputs,
        )

        # Bit 1 appears in both subsets, so should be filtered
        assert BitPosition(1) not in filtered_bits
        assert BitPosition(0) in filtered_bits
        assert BitPosition(2) in filtered_bits


class TestEvaluateOutputBitTaintStates:
    """Tests for evaluate_output_bit_taint_states function."""

    def test_unconditional_flow_always_tainted(self) -> None:
        """Output bit with unconditional flow should always be tainted."""
        state = State(num_bits=8, state_value=StateValue(0b10101010))
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10))])
        output_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0)]),
        }
        # Unconditional pair
        all_conditions = [
            ConditionDataflowPair(condition=None, input_bit=BitPosition(0), output_bit=BitPosition(10)),
        ]

        result = evaluate_output_bit_taint_states(
            state,
            output_bit_refs,
            output_to_inputs,
            all_conditions,
        )

        assert result[BitPosition(10)] == 1

    def test_conditional_flow_evaluates_condition(self) -> None:
        """Output bit with conditional flow should evaluate condition."""
        state = State(num_bits=8, state_value=StateValue(0b00000001))  # Bit 0 is 1
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10))])
        output_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0)]),
        }
        # Condition: bit 0 must be 1
        condition = TaintCondition(LogicType.DNF, frozenset([(0b1, 0b1)]))
        all_conditions = [
            ConditionDataflowPair(condition=condition, input_bit=BitPosition(0), output_bit=BitPosition(10)),
        ]

        result = evaluate_output_bit_taint_states(
            state,
            output_bit_refs,
            output_to_inputs,
            all_conditions,
        )

        assert result[BitPosition(10)] == 1

    def test_condition_not_met_not_tainted(self) -> None:
        """Output bit should not be tainted when condition not met."""
        state = State(num_bits=8, state_value=StateValue(0b00000000))  # Bit 0 is 0
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10))])
        output_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0)]),
        }
        # Condition: bit 0 must be 1
        condition = TaintCondition(LogicType.DNF, frozenset([(0b1, 0b1)]))
        all_conditions = [
            ConditionDataflowPair(condition=condition, input_bit=BitPosition(0), output_bit=BitPosition(10)),
        ]

        result = evaluate_output_bit_taint_states(
            state,
            output_bit_refs,
            output_to_inputs,
            all_conditions,
        )

        assert result[BitPosition(10)] == 0

    def test_output_bit_with_output_bit_ref_dependency(self) -> None:
        """Test taint by induction: output bit depends on another output bit."""
        state = State(num_bits=8, state_value=StateValue(0b00000001))  # Bit 0 is 1
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10)), OutputBitRef(BitPosition(11))])
        output_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0)]),
            BitPosition(11): frozenset([BitPosition(1)]),
        }
        # Bit 10: unconditional flow from bit 0
        # Bit 11: conditional on bit 1 AND output bit 10 being tainted
        condition_bit10 = None  # Unconditional
        condition_bit11 = TaintCondition(
            LogicType.DNF,
            frozenset([(0b10, 0b10)]),  # Bit 1 must be 1
            frozenset([OutputBitRef(BitPosition(10))]),  # AND bit 10 must be tainted
        )
        all_conditions = [
            ConditionDataflowPair(condition=condition_bit10, input_bit=BitPosition(0), output_bit=BitPosition(10)),
            ConditionDataflowPair(condition=condition_bit11, input_bit=BitPosition(1), output_bit=BitPosition(11)),
        ]

        result = evaluate_output_bit_taint_states(
            state,
            output_bit_refs,
            output_to_inputs,
            all_conditions,
        )

        # Bit 10 should be tainted (unconditional)
        assert result[BitPosition(10)] == 1
        # Bit 11 should NOT be tainted (bit 1 is 0, even though bit 10 is tainted)
        assert result[BitPosition(11)] == 0

    def test_output_bit_ref_dependency_satisfied(self) -> None:
        """Test when output bit ref dependency is satisfied."""
        state = State(num_bits=8, state_value=StateValue(0b00000011))  # Bits 0 and 1 are 1
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10)), OutputBitRef(BitPosition(11))])
        output_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0)]),
            BitPosition(11): frozenset([BitPosition(1)]),
        }
        # Bit 10: unconditional
        # Bit 11: conditional on bit 1 AND output bit 10 being tainted
        condition_bit11 = TaintCondition(
            LogicType.DNF,
            frozenset([(0b10, 0b10)]),  # Bit 1 must be 1
            frozenset([OutputBitRef(BitPosition(10))]),  # AND bit 10 must be tainted
        )
        all_conditions = [
            ConditionDataflowPair(condition=None, input_bit=BitPosition(0), output_bit=BitPosition(10)),
            ConditionDataflowPair(condition=condition_bit11, input_bit=BitPosition(1), output_bit=BitPosition(11)),
        ]

        result = evaluate_output_bit_taint_states(
            state,
            output_bit_refs,
            output_to_inputs,
            all_conditions,
        )

        # Both bits should be tainted
        assert result[BitPosition(10)] == 1
        assert result[BitPosition(11)] == 1

    def test_chain_of_output_dependencies(self) -> None:
        """Test chain: bit 10 -> bit 11 -> bit 12."""
        state = State(num_bits=8, state_value=StateValue(0b00000111))  # Bits 0, 1, 2 are 1
        output_bit_refs = frozenset(
            [
                OutputBitRef(BitPosition(10)),
                OutputBitRef(BitPosition(11)),
                OutputBitRef(BitPosition(12)),
            ],
        )
        output_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0)]),
            BitPosition(11): frozenset([BitPosition(1)]),
            BitPosition(12): frozenset([BitPosition(2)]),
        }
        # Bit 10: unconditional
        # Bit 11: depends on bit 10
        # Bit 12: depends on bit 11
        condition_bit11 = TaintCondition(
            LogicType.DNF,
            frozenset([(0b10, 0b10)]),
            frozenset([OutputBitRef(BitPosition(10))]),
        )
        condition_bit12 = TaintCondition(
            LogicType.DNF,
            frozenset([(0b100, 0b100)]),
            frozenset([OutputBitRef(BitPosition(11))]),
        )
        all_conditions = [
            ConditionDataflowPair(condition=None, input_bit=BitPosition(0), output_bit=BitPosition(10)),
            ConditionDataflowPair(condition=condition_bit11, input_bit=BitPosition(1), output_bit=BitPosition(11)),
            ConditionDataflowPair(condition=condition_bit12, input_bit=BitPosition(2), output_bit=BitPosition(12)),
        ]

        result = evaluate_output_bit_taint_states(
            state,
            output_bit_refs,
            output_to_inputs,
            all_conditions,
        )

        # All bits should be tainted (chain propagates)
        assert result[BitPosition(10)] == 1
        assert result[BitPosition(11)] == 1
        assert result[BitPosition(12)] == 1

    def test_broken_chain_stops_propagation(self) -> None:
        """Test that broken chain stops propagation."""
        state = State(num_bits=8, state_value=StateValue(0b00000101))  # Bits 0 and 2 are 1, bit 1 is 0
        output_bit_refs = frozenset(
            [
                OutputBitRef(BitPosition(10)),
                OutputBitRef(BitPosition(11)),
                OutputBitRef(BitPosition(12)),
            ],
        )
        output_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0)]),
            BitPosition(11): frozenset([BitPosition(1)]),
            BitPosition(12): frozenset([BitPosition(2)]),
        }
        # Bit 10: unconditional
        # Bit 11: depends on bit 10 AND bit 1 (which is 0)
        # Bit 12: depends on bit 11
        condition_bit11 = TaintCondition(
            LogicType.DNF,
            frozenset([(0b10, 0b10)]),  # Bit 1 must be 1 (but it's 0!)
            frozenset([OutputBitRef(BitPosition(10))]),
        )
        condition_bit12 = TaintCondition(
            LogicType.DNF,
            frozenset([(0b100, 0b100)]),
            frozenset([OutputBitRef(BitPosition(11))]),
        )
        all_conditions = [
            ConditionDataflowPair(condition=None, input_bit=BitPosition(0), output_bit=BitPosition(10)),
            ConditionDataflowPair(condition=condition_bit11, input_bit=BitPosition(1), output_bit=BitPosition(11)),
            ConditionDataflowPair(condition=condition_bit12, input_bit=BitPosition(2), output_bit=BitPosition(12)),
        ]

        result = evaluate_output_bit_taint_states(
            state,
            output_bit_refs,
            output_to_inputs,
            all_conditions,
        )

        # Bit 10 is tainted, but bit 11 is not (condition fails), so bit 12 is also not
        assert result[BitPosition(10)] == 1
        assert result[BitPosition(11)] == 0
        assert result[BitPosition(12)] == 0

    def test_empty_output_bit_refs(self) -> None:
        """Test with empty output_bit_refs returns empty dict."""
        state = State(num_bits=8, state_value=StateValue(0))
        output_bit_refs: frozenset[OutputBitRef] = frozenset()
        output_to_inputs: dict[BitPosition, frozenset[BitPosition]] = {}
        all_conditions: list[ConditionDataflowPair] = []

        result = evaluate_output_bit_taint_states(
            state,
            output_bit_refs,
            output_to_inputs,
            all_conditions,
        )

        assert result == {}

    def test_multiple_input_bits_same_output(self) -> None:
        """Test output bit influenced by multiple input bits."""
        state = State(num_bits=8, state_value=StateValue(0b00000011))  # Bits 0 and 1 are 1
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10))])
        output_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0), BitPosition(1)]),
        }
        # Bit 10 is tainted if EITHER bit 0 OR bit 1 flows to it
        condition0 = TaintCondition(LogicType.DNF, frozenset([(0b1, 0b1)]))
        condition1 = TaintCondition(LogicType.DNF, frozenset([(0b10, 0b10)]))
        all_conditions = [
            ConditionDataflowPair(condition=condition0, input_bit=BitPosition(0), output_bit=BitPosition(10)),
            ConditionDataflowPair(condition=condition1, input_bit=BitPosition(1), output_bit=BitPosition(10)),
        ]

        result = evaluate_output_bit_taint_states(
            state,
            output_bit_refs,
            output_to_inputs,
            all_conditions,
        )

        # Output bit 10 should be tainted (both conditions satisfied)
        assert result[BitPosition(10)] == 1


class TestIsOutputTainted:
    """Tests for is_output_tainted function."""

    def test_unconditional_flow_returns_true(self) -> None:
        """Unconditional flow should always return True."""
        state = State(num_bits=8, state_value=StateValue(0))
        output_state = State(num_bits=8, state_value=StateValue(0))
        inputs_to_flows = {
            BitPosition(0): [
                ConditionDataflowPair(condition=None, input_bit=BitPosition(0), output_bit=BitPosition(10)),
            ],
        }
        influencing_inputs = frozenset([BitPosition(0)])
        target_output_bit = BitPosition(10)

        result = is_output_tainted(state, output_state, inputs_to_flows, influencing_inputs, target_output_bit)

        assert result is True

    def test_condition_met_returns_true(self) -> None:
        """Should return True when condition is met."""
        state = State(num_bits=8, state_value=StateValue(0b00000001))
        output_state = State(num_bits=8, state_value=StateValue(0))
        condition = TaintCondition(LogicType.DNF, frozenset([(0b1, 0b1)]))
        inputs_to_flows = {
            BitPosition(0): [
                ConditionDataflowPair(condition=condition, input_bit=BitPosition(0), output_bit=BitPosition(10)),
            ],
        }
        influencing_inputs = frozenset([BitPosition(0)])
        target_output_bit = BitPosition(10)

        result = is_output_tainted(state, output_state, inputs_to_flows, influencing_inputs, target_output_bit)

        assert result is True

    def test_condition_not_met_returns_false(self) -> None:
        """Should return False when no condition is met."""
        state = State(num_bits=8, state_value=StateValue(0b00000000))
        output_state = State(num_bits=8, state_value=StateValue(0))
        condition = TaintCondition(LogicType.DNF, frozenset([(0b1, 0b1)]))
        inputs_to_flows = {
            BitPosition(0): [
                ConditionDataflowPair(condition=condition, input_bit=BitPosition(0), output_bit=BitPosition(10)),
            ],
        }
        influencing_inputs = frozenset([BitPosition(0)])
        target_output_bit = BitPosition(10)

        result = is_output_tainted(state, output_state, inputs_to_flows, influencing_inputs, target_output_bit)

        assert result is False

    def test_output_bit_ref_in_condition_satisfied(self) -> None:
        """Should return True when output_bit_ref dependency is satisfied."""
        state = State(num_bits=8, state_value=StateValue(0b00000001))
        # Output state has bit 10 tainted
        output_state = State(num_bits=16, state_value=StateValue(1 << 10))
        condition = TaintCondition(
            LogicType.DNF,
            frozenset([(0b1, 0b1)]),  # Bit 0 must be 1
            frozenset([OutputBitRef(BitPosition(10))]),  # AND bit 10 must be tainted
        )
        inputs_to_flows = {
            BitPosition(0): [
                ConditionDataflowPair(condition=condition, input_bit=BitPosition(0), output_bit=BitPosition(11)),
            ],
        }
        influencing_inputs = frozenset([BitPosition(0)])
        target_output_bit = BitPosition(11)

        result = is_output_tainted(state, output_state, inputs_to_flows, influencing_inputs, target_output_bit)

        assert result is True

    def test_output_bit_ref_in_condition_not_satisfied(self) -> None:
        """Should return False when output_bit_ref dependency is not satisfied."""
        state = State(num_bits=8, state_value=StateValue(0b00000001))
        # Output state does NOT have bit 10 tainted
        output_state = State(num_bits=16, state_value=StateValue(0))
        condition = TaintCondition(
            LogicType.DNF,
            frozenset([(0b1, 0b1)]),  # Bit 0 must be 1
            frozenset([OutputBitRef(BitPosition(10))]),  # AND bit 10 must be tainted
        )
        inputs_to_flows = {
            BitPosition(0): [
                ConditionDataflowPair(condition=condition, input_bit=BitPosition(0), output_bit=BitPosition(11)),
            ],
        }
        influencing_inputs = frozenset([BitPosition(0)])
        target_output_bit = BitPosition(11)

        result = is_output_tainted(state, output_state, inputs_to_flows, influencing_inputs, target_output_bit)

        assert result is False

    def test_filters_by_target_output_bit(self) -> None:
        """Should only consider flows targeting the specific output bit."""
        state = State(num_bits=8, state_value=StateValue(0b00000001))
        output_state = State(num_bits=16, state_value=StateValue(0))
        condition = TaintCondition(LogicType.DNF, frozenset([(0b1, 0b1)]))
        inputs_to_flows = {
            BitPosition(0): [
                # Flow to bit 10 (not our target)
                ConditionDataflowPair(condition=condition, input_bit=BitPosition(0), output_bit=BitPosition(10)),
                # Flow to bit 11 (our target) - unconditional
                ConditionDataflowPair(condition=None, input_bit=BitPosition(0), output_bit=BitPosition(11)),
            ],
        }
        influencing_inputs = frozenset([BitPosition(0)])
        target_output_bit = BitPosition(11)

        result = is_output_tainted(state, output_state, inputs_to_flows, influencing_inputs, target_output_bit)

        # Should return True because the unconditional flow to bit 11 exists
        assert result is True


class TestAugmentStatesWithOutputBitTaints:
    """Tests for augment_states_with_output_bit_taints function."""

    def test_augments_states_with_output_taint_values(self) -> None:
        """Should augment states with evaluated output bit taint values."""
        state1 = State(num_bits=8, state_value=StateValue(0b00000001))
        state2 = State(num_bits=8, state_value=StateValue(0b00000000))
        output_state1 = State(num_bits=16, state_value=StateValue(0b00000000))
        output_state2 = State(num_bits=16, state_value=StateValue(0b00000000))
        propagating_states = {(state1, output_state1)}
        non_propagating_states = {(state2, output_state2)}
        relevant_input_bits = frozenset([BitPosition(0)])
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10))])
        output_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0)]),
        }
        # Unconditional flow
        all_conditions = [
            ConditionDataflowPair(condition=None, input_bit=BitPosition(0), output_bit=BitPosition(10)),
        ]

        _aug_prop, _aug_non_prop, output_list = augment_states_with_output_bit_taints(
            propagating_states,
            non_propagating_states,
            relevant_input_bits,
            output_bit_refs,
            output_to_inputs,
            all_conditions,
        )

        # Output bit should be tainted (set to 1) in both cases (unconditional)
        # Augmented state has original bits + output bit taint in higher position
        assert len(_aug_prop) == 1
        assert len(_aug_non_prop) == 1
        assert output_list == [BitPosition(10)]

    def test_handles_multiple_output_refs(self) -> None:
        """Should handle multiple output bit refs."""
        state = State(num_bits=8, state_value=StateValue(0b00000001))
        output_state = State(num_bits=16, state_value=StateValue(0b00000000))
        propagating_states = {(state, output_state)}
        non_propagating_states: set[tuple[State, State]] = set()
        relevant_input_bits = frozenset([BitPosition(0)])
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10)), OutputBitRef(BitPosition(11))])
        output_to_inputs = {
            BitPosition(10): frozenset([BitPosition(0)]),
            BitPosition(11): frozenset([BitPosition(0)]),
        }
        all_conditions = [
            ConditionDataflowPair(condition=None, input_bit=BitPosition(0), output_bit=BitPosition(10)),
            ConditionDataflowPair(condition=None, input_bit=BitPosition(0), output_bit=BitPosition(11)),
        ]

        _aug_prop, _aug_non_prop, output_list = augment_states_with_output_bit_taints(
            propagating_states,
            non_propagating_states,
            relevant_input_bits,
            output_bit_refs,
            output_to_inputs,
            all_conditions,
        )

        assert len(output_list) == 2
        assert BitPosition(10) in output_list
        assert BitPosition(11) in output_list
