"""Tests for output bit reference functionality in conditions."""

from taintinduce.rules.conditions import LogicType, OutputBitRef, TaintCondition
from taintinduce.state.state import State
from taintinduce.types import BitPosition, StateValue


class TestOutputBitRef:
    """Tests for OutputBitRef functionality."""

    def test_output_bit_ref_creation(self) -> None:
        """Test creating an OutputBitRef."""
        ref = OutputBitRef(BitPosition(5))
        assert ref.output_bit == BitPosition(5)

    def test_output_bit_ref_equality(self) -> None:
        """Test OutputBitRef equality."""
        ref1 = OutputBitRef(BitPosition(5))
        ref2 = OutputBitRef(BitPosition(5))
        ref3 = OutputBitRef(BitPosition(6))

        assert ref1 == ref2
        assert ref1 != ref3

    def test_output_bit_ref_hashable(self) -> None:
        """Test that OutputBitRef is hashable."""
        ref1 = OutputBitRef(BitPosition(5))
        ref2 = OutputBitRef(BitPosition(6))
        ref_set = {ref1, ref2}
        assert len(ref_set) == 2


class TestTaintConditionWithOutputRefs:
    """Tests for TaintCondition with output bit references."""

    def test_condition_with_output_refs_creation(self) -> None:
        """Test creating a condition with output bit references."""
        output_refs = frozenset([OutputBitRef(BitPosition(0)), OutputBitRef(BitPosition(1))])
        cond = TaintCondition(
            LogicType.DNF,
            frozenset([(0xFF, 0x01)]),
            output_bit_refs=output_refs,
        )

        assert cond.condition_ops == frozenset([(0xFF, 0x01)])
        assert cond.output_bit_refs == output_refs

    def test_condition_equality_with_output_refs(self) -> None:
        """Test condition equality when output refs are involved."""
        output_refs1 = frozenset([OutputBitRef(BitPosition(0))])
        output_refs2 = frozenset([OutputBitRef(BitPosition(0))])
        output_refs3 = frozenset([OutputBitRef(BitPosition(1))])

        cond1 = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]), output_bit_refs=output_refs1)
        cond2 = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]), output_bit_refs=output_refs2)
        cond3 = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]), output_bit_refs=output_refs3)
        cond4 = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]))

        assert cond1 == cond2
        assert cond1 != cond3
        assert cond1 != cond4

    def test_condition_hash_with_output_refs(self) -> None:
        """Test that conditions with output refs are hashable."""
        output_refs = frozenset([OutputBitRef(BitPosition(0))])
        cond1 = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]), output_bit_refs=output_refs)
        cond2 = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x02)]), output_bit_refs=output_refs)

        cond_set = {cond1, cond2}
        assert len(cond_set) == 2

    def test_condition_repr_with_output_refs(self) -> None:
        """Test condition representation with output refs."""
        output_refs = frozenset([OutputBitRef(BitPosition(5))])
        cond = TaintCondition(
            LogicType.DNF,
            frozenset([(0xFF, 0x01)]),
            output_bit_refs=output_refs,
        )

        repr_str = repr(cond)
        assert 'output_refs' in repr_str
        assert '5' in repr_str


class TestConditionEvalWithOutputRefs:
    """Tests for evaluating conditions with output bit references."""

    def test_eval_without_output_state_backward_compat(self) -> None:
        """Test that eval works without output_state (backward compatibility)."""
        # Condition without output refs should work as before
        cond = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]))
        input_state = State(8, StateValue(0x01))

        result = cond.eval(input_state)
        assert result is True

    def test_eval_with_output_refs_no_output_state(self) -> None:
        """Test eval with output refs but no output state provided (backward compat)."""
        output_refs = frozenset([OutputBitRef(BitPosition(5))])
        cond = TaintCondition(
            LogicType.DNF,
            frozenset([(0xFF, 0x01)]),
            output_bit_refs=output_refs,
        )
        input_state = State(8, StateValue(0x01))

        # Should still satisfy input condition even without output state
        result = cond.eval(input_state)
        assert result is True

    def test_eval_with_output_refs_and_output_state(self) -> None:
        """Test eval with output refs and output state provided."""
        # Condition: input bit 0 = 1 AND output bit 5 is set
        output_refs = frozenset([OutputBitRef(BitPosition(5))])
        cond = TaintCondition(
            LogicType.DNF,
            frozenset([(0x01, 0x01)]),  # bit 0 = 1
            output_bit_refs=output_refs,
        )

        input_state = State(8, StateValue(0x01))  # bit 0 = 1
        output_state_match = State(8, StateValue(0x20))  # bit 5 = 1
        output_state_no_match = State(8, StateValue(0x00))  # bit 5 = 0

        # Both input and output conditions satisfied
        assert cond.eval(input_state, output_state_match) is True

        # Input satisfied but output not satisfied
        assert cond.eval(input_state, output_state_no_match) is False

    def test_eval_only_output_refs_no_input_cond(self) -> None:
        """Test eval with only output refs, no input conditions."""
        output_refs = frozenset([OutputBitRef(BitPosition(3))])
        cond = TaintCondition(
            LogicType.DNF,
            None,  # No input conditions
            output_bit_refs=output_refs,
        )

        input_state = State(8, StateValue(0x00))
        output_state_match = State(8, StateValue(0x08))  # bit 3 = 1
        output_state_no_match = State(8, StateValue(0x00))  # bit 3 = 0

        # Should check only output bit
        assert cond.eval(input_state, output_state_match) is True
        assert cond.eval(input_state, output_state_no_match) is False

    def test_eval_multiple_output_refs(self) -> None:
        """Test eval with multiple output bit references."""
        output_refs = frozenset([OutputBitRef(BitPosition(2)), OutputBitRef(BitPosition(4))])
        cond = TaintCondition(
            LogicType.DNF,
            frozenset([(0x01, 0x01)]),
            output_bit_refs=output_refs,
        )

        input_state = State(8, StateValue(0x01))
        output_both_set = State(8, StateValue(0x14))  # bits 2 and 4 set
        output_partial = State(8, StateValue(0x04))  # only bit 2 set
        output_none = State(8, StateValue(0x00))  # no bits set

        # All conditions satisfied
        assert cond.eval(input_state, output_both_set) is True

        # Not all output bits set
        assert cond.eval(input_state, output_partial) is False
        assert cond.eval(input_state, output_none) is False


class TestBackwardCompatibility:
    """Tests to ensure backward compatibility with existing code."""

    def test_condition_without_output_refs(self) -> None:
        """Test that conditions work normally without output refs."""
        cond = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]))

        assert cond.condition_ops == frozenset([(0xFF, 0x01)])
        assert not hasattr(cond, 'output_bit_refs') or cond.output_bit_refs is None

    def test_eval_without_output_refs(self) -> None:
        """Test eval works normally without output refs."""
        cond = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]))
        input_state = State(8, StateValue(0x01))

        assert cond.eval(input_state) is True
        assert cond.eval(State(8, StateValue(0x00))) is False

    def test_serialization_compatibility(self) -> None:
        """Test that old serialized conditions still work."""
        # Create old-style condition
        cond = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]))

        # Should work normally
        assert cond.condition_type == LogicType.DNF
        assert cond.condition_ops == frozenset([(0xFF, 0x01)])
