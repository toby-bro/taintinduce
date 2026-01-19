"""Unit tests for validation module."""

from taintinduce.inference_engine.validation import (
    check_condition_satisfied,
    check_dataflow_matches,
    validate_condition,
)
from taintinduce.rules.conditions import LogicType, TaintCondition
from taintinduce.rules.rules import ConditionDataflowPair
from taintinduce.state.state import State
from taintinduce.types import BitPosition, Dataflow, StateValue


def test_check_condition_satisfied_unconditional():
    """Test that unconditional (None) conditions are always satisfied."""
    state = State(num_bits=64, state_value=StateValue(0x12345678))
    assert check_condition_satisfied(None, state)


def test_check_condition_satisfied_empty():
    """Test that empty conditions are always satisfied."""
    empty_condition = TaintCondition(LogicType.DNF, frozenset())
    state = State(num_bits=64, state_value=StateValue(0x12345678))
    assert check_condition_satisfied(empty_condition, state)


def test_check_condition_satisfied_matching():
    """Test that matching DNF clause is satisfied."""
    # Condition: bit 0 must be 1
    condition = TaintCondition(LogicType.DNF, frozenset([(0x1, 0x1)]))
    state = State(num_bits=64, state_value=StateValue(0x1))
    assert check_condition_satisfied(condition, state)


def test_check_condition_satisfied_not_matching():
    """Test that non-matching state is not satisfied."""
    # Condition: bit 0 must be 1
    condition = TaintCondition(LogicType.DNF, frozenset([(0x1, 0x1)]))
    state = State(num_bits=64, state_value=StateValue(0x0))
    assert not check_condition_satisfied(condition, state)


def test_check_dataflow_matches_dict():
    """Test dataflow matching with dictionary output_bits."""
    dataflow = Dataflow({BitPosition(32): frozenset([BitPosition(64)])})
    pair = ConditionDataflowPair(condition=None, output_bits=dataflow)

    # Matching case
    assert check_dataflow_matches(pair, BitPosition(32), frozenset([BitPosition(64)]))

    # Non-matching output bits
    assert not check_dataflow_matches(pair, BitPosition(32), frozenset([BitPosition(65)]))

    # Non-matching input bit
    assert not check_dataflow_matches(pair, BitPosition(33), frozenset([BitPosition(64)]))


def test_check_dataflow_matches_frozenset():
    """Test dataflow matching with frozenset output_bits."""
    output_bits = frozenset([BitPosition(64)])
    pair = ConditionDataflowPair(condition=None, output_bits=output_bits)

    # Matching case
    assert check_dataflow_matches(pair, BitPosition(32), frozenset([BitPosition(64)]))

    # Non-matching case
    assert not check_dataflow_matches(pair, BitPosition(32), frozenset([BitPosition(65)]))


def test_validate_condition_empty():
    """Test that empty condition is always valid."""
    condition = TaintCondition(LogicType.DNF, None)
    agreeing = {State(num_bits=64, state_value=StateValue(0x0))}
    disagreeing = {State(num_bits=64, state_value=StateValue(0x1))}
    assert validate_condition(condition, agreeing, disagreeing)


def test_validate_condition_valid():
    """Test validation of a correct condition."""
    # Condition: bit 0 = 1 (matches only odd numbers)
    condition = TaintCondition(LogicType.DNF, frozenset([(0x1, 0x1)]))

    agreeing = {
        State(num_bits=64, state_value=StateValue(0x1)),
        State(num_bits=64, state_value=StateValue(0x3)),
    }
    disagreeing = {
        State(num_bits=64, state_value=StateValue(0x0)),
        State(num_bits=64, state_value=StateValue(0x2)),
    }

    assert validate_condition(condition, agreeing, disagreeing)


def test_validate_condition_invalid_agreeing():
    """Test that validation fails when agreeing state doesn't satisfy condition."""
    # Condition: bit 0 = 1
    condition = TaintCondition(LogicType.DNF, frozenset([(0x1, 0x1)]))

    # Agreeing partition has state with bit 0 = 0 (doesn't satisfy)
    agreeing = {State(num_bits=64, state_value=StateValue(0x0))}
    disagreeing = {State(num_bits=64, state_value=StateValue(0x2))}

    assert not validate_condition(condition, agreeing, disagreeing)


def test_validate_condition_invalid_disagreeing():
    """Test that validation fails when disagreeing state satisfies condition."""
    # Condition: bit 0 = 1
    condition = TaintCondition(LogicType.DNF, frozenset([(0x1, 0x1)]))

    agreeing = {State(num_bits=64, state_value=StateValue(0x1))}
    # Disagreeing partition has state with bit 0 = 1 (satisfies - should not!)
    disagreeing = {State(num_bits=64, state_value=StateValue(0x3))}

    assert not validate_condition(condition, agreeing, disagreeing)
