"""Tests for dataflow utility functions."""

import pytest

from taintinduce.types import BitPosition, Dataflow

from .dataflow_utils import (
    count_input_bits,
    get_dataflow_input_bits,
    is_strict_superset_dataflow,
    is_superset_dataflow,
)


class TestGetDataflowInputBits:
    """Tests for get_dataflow_input_bits function."""

    def test_empty_dataflow(self) -> None:
        """Test with empty dataflow."""
        dataflow = Dataflow()
        result = get_dataflow_input_bits(dataflow)
        assert result == frozenset()

    def test_single_input(self) -> None:
        """Test with single input bit."""
        dataflow = Dataflow({BitPosition(0): frozenset([BitPosition(0)])})
        result = get_dataflow_input_bits(dataflow)
        assert result == frozenset([BitPosition(0)])

    def test_multiple_inputs(self) -> None:
        """Test with multiple input bits."""
        dataflow = Dataflow(
            {
                BitPosition(0): frozenset([BitPosition(0)]),
                BitPosition(1): frozenset([BitPosition(1)]),
                BitPosition(5): frozenset([BitPosition(5), BitPosition(6)]),
            },
        )
        result = get_dataflow_input_bits(dataflow)
        assert result == frozenset([BitPosition(0), BitPosition(1), BitPosition(5)])


class TestIsSupersetDataflow:
    """Tests for is_superset_dataflow function."""

    def test_identical_flows(self) -> None:
        """Test with identical dataflows."""
        flow1 = Dataflow({BitPosition(0): frozenset([BitPosition(0)])})
        flow2 = Dataflow({BitPosition(0): frozenset([BitPosition(0)])})
        assert is_superset_dataflow(flow1, flow2)
        assert is_superset_dataflow(flow2, flow1)

    def test_superset_relationship(self) -> None:
        """Test when one flow is a superset of another."""
        larger_flow = Dataflow(
            {
                BitPosition(0): frozenset([BitPosition(0)]),
                BitPosition(1): frozenset([BitPosition(1)]),
                BitPosition(2): frozenset([BitPosition(2)]),
            },
        )
        smaller_flow = Dataflow(
            {
                BitPosition(0): frozenset([BitPosition(0)]),
                BitPosition(1): frozenset([BitPosition(1)]),
            },
        )

        assert is_superset_dataflow(larger_flow, smaller_flow)
        assert not is_superset_dataflow(smaller_flow, larger_flow)

    def test_no_relationship(self) -> None:
        """Test when flows have different inputs with no superset relationship."""
        flow1 = Dataflow(
            {
                BitPosition(0): frozenset([BitPosition(0)]),
                BitPosition(1): frozenset([BitPosition(1)]),
            },
        )
        flow2 = Dataflow(
            {
                BitPosition(2): frozenset([BitPosition(2)]),
                BitPosition(3): frozenset([BitPosition(3)]),
            },
        )

        assert not is_superset_dataflow(flow1, flow2)
        assert not is_superset_dataflow(flow2, flow1)

    def test_empty_flows(self) -> None:
        """Test with empty dataflows."""
        empty = Dataflow()
        non_empty = Dataflow({BitPosition(0): frozenset([BitPosition(0)])})

        assert is_superset_dataflow(empty, empty)
        assert is_superset_dataflow(non_empty, empty)
        assert not is_superset_dataflow(empty, non_empty)

    def test_add_vs_xor_example(self) -> None:
        """Test realistic example: ADD with carry vs simple XOR."""
        # ADD eax, ebx for bit 2 depends on bits 0, 1, 2 (carry propagation)
        add_flow = Dataflow(
            {
                BitPosition(0): frozenset([BitPosition(2)]),
                BitPosition(1): frozenset([BitPosition(2)]),
                BitPosition(2): frozenset([BitPosition(2)]),
            },
        )

        # XOR for bit 0 only depends on bit 0
        xor_flow = Dataflow(
            {
                BitPosition(0): frozenset([BitPosition(0)]),
            },
        )

        assert is_superset_dataflow(add_flow, xor_flow)
        assert not is_superset_dataflow(xor_flow, add_flow)


class TestIsStrictSupersetDataflow:
    """Tests for is_strict_superset_dataflow function."""

    def test_identical_flows_not_strict(self) -> None:
        """Test that identical flows are not strict supersets."""
        flow1 = Dataflow({BitPosition(0): frozenset([BitPosition(0)])})
        flow2 = Dataflow({BitPosition(0): frozenset([BitPosition(0)])})
        assert not is_strict_superset_dataflow(flow1, flow2)
        assert not is_strict_superset_dataflow(flow2, flow1)

    def test_strict_superset(self) -> None:
        """Test strict superset relationship."""
        larger_flow = Dataflow(
            {
                BitPosition(0): frozenset([BitPosition(0)]),
                BitPosition(1): frozenset([BitPosition(1)]),
            },
        )
        smaller_flow = Dataflow(
            {
                BitPosition(0): frozenset([BitPosition(0)]),
            },
        )

        assert is_strict_superset_dataflow(larger_flow, smaller_flow)
        assert not is_strict_superset_dataflow(smaller_flow, larger_flow)

    def test_no_strict_relationship(self) -> None:
        """Test when there's no strict superset relationship."""
        flow1 = Dataflow(
            {
                BitPosition(0): frozenset([BitPosition(0)]),
                BitPosition(1): frozenset([BitPosition(1)]),
            },
        )
        flow2 = Dataflow(
            {
                BitPosition(1): frozenset([BitPosition(1)]),
                BitPosition(2): frozenset([BitPosition(2)]),
            },
        )

        assert not is_strict_superset_dataflow(flow1, flow2)
        assert not is_strict_superset_dataflow(flow2, flow1)


class TestCountInputBits:
    """Tests for count_input_bits function."""

    def test_empty_dataflow(self) -> None:
        """Test counting inputs in empty dataflow."""
        dataflow = Dataflow()
        assert count_input_bits(dataflow) == 0

    def test_single_input(self) -> None:
        """Test counting single input."""
        dataflow = Dataflow({BitPosition(0): frozenset([BitPosition(0)])})
        assert count_input_bits(dataflow) == 1

    def test_multiple_inputs(self) -> None:
        """Test counting multiple inputs."""
        dataflow = Dataflow(
            {
                BitPosition(0): frozenset([BitPosition(0)]),
                BitPosition(1): frozenset([BitPosition(1)]),
                BitPosition(5): frozenset([BitPosition(5), BitPosition(6)]),
            },
        )
        assert count_input_bits(dataflow) == 3


@pytest.mark.parametrize(
    ('larger_inputs', 'smaller_inputs', 'expected'),
    [
        ({0, 1, 2}, {0, 1}, True),
        ({0, 1}, {0, 1, 2}, False),
        ({0, 1, 2}, {0, 1, 2}, True),
        ({0, 1}, {2, 3}, False),
        (set(), set(), True),
        ({0}, set(), True),
        (set(), {0}, False),
    ],
)
def test_superset_parametrized(
    larger_inputs: set[int],
    smaller_inputs: set[int],
    expected: bool,
) -> None:
    """Parametrized test for superset relationships."""
    larger_flow = Dataflow({BitPosition(i): frozenset([BitPosition(i)]) for i in larger_inputs})
    smaller_flow = Dataflow({BitPosition(i): frozenset([BitPosition(i)]) for i in smaller_inputs})

    assert is_superset_dataflow(larger_flow, smaller_flow) == expected
