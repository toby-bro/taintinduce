"""Utilities for dataflow analysis and comparison."""

from taintinduce.types import BitPosition, Dataflow


def get_dataflow_input_bits(dataflow: Dataflow) -> frozenset[BitPosition]:
    """Extract all input bit positions from a dataflow.

    Args:
        dataflow: Dataflow mapping input bits to output bits

    Returns:
        Frozenset of all input bit positions
    """
    return frozenset(dataflow.keys())


def is_superset_dataflow(
    larger_flow: Dataflow,
    smaller_flow: Dataflow,
) -> bool:
    """Check if larger_flow's input bits are a superset of smaller_flow's input bits.

    This determines if larger_flow uses all the input bits that smaller_flow uses,
    plus potentially more. This is useful for detecting when a condition should
    include output bits from smaller flows.

    Args:
        larger_flow: The dataflow with potentially more input bits
        smaller_flow: The dataflow with potentially fewer input bits

    Returns:
        True if larger_flow's inputs are a superset of smaller_flow's inputs

    Examples:
        >>> # ADD with carry propagation uses more bits than simple XOR
        >>> add_flow = Dataflow({BitPosition(0): frozenset([BitPosition(0)]),
        ...                       BitPosition(1): frozenset([BitPosition(1)]),
        ...                       BitPosition(2): frozenset([BitPosition(2)])})
        >>> xor_flow = Dataflow({BitPosition(0): frozenset([BitPosition(0)])})
        >>> is_superset_dataflow(add_flow, xor_flow)
        True
        >>> is_superset_dataflow(xor_flow, add_flow)
        False
    """
    larger_inputs = get_dataflow_input_bits(larger_flow)
    smaller_inputs = get_dataflow_input_bits(smaller_flow)
    return larger_inputs >= smaller_inputs


def is_strict_superset_dataflow(
    larger_flow: Dataflow,
    smaller_flow: Dataflow,
) -> bool:
    """Check if larger_flow's input bits are a strict superset of smaller_flow's input bits.

    Similar to is_superset_dataflow but requires larger_flow to have strictly more inputs.

    Args:
        larger_flow: The dataflow with more input bits
        smaller_flow: The dataflow with fewer input bits

    Returns:
        True if larger_flow's inputs are a strict superset of smaller_flow's inputs
    """
    larger_inputs = get_dataflow_input_bits(larger_flow)
    smaller_inputs = get_dataflow_input_bits(smaller_flow)
    return larger_inputs > smaller_inputs


def count_input_bits(dataflow: Dataflow) -> int:
    """Count the number of input bits in a dataflow.

    Args:
        dataflow: Dataflow to count inputs for

    Returns:
        Number of input bit positions
    """
    return len(dataflow)
