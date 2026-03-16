import pytest

from taintinduce.state.state import check_ones
from taintinduce.types import BitPosition


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        (0, frozenset()),
        (1, frozenset({BitPosition(0)})),
        (2, frozenset({BitPosition(1)})),
        (3, frozenset({BitPosition(0), BitPosition(1)})),
        (5, frozenset({BitPosition(0), BitPosition(2)})),
        (1024, frozenset({BitPosition(10)})),
        ((1 << 50) | (1 << 100), frozenset({BitPosition(50), BitPosition(100)})),
    ],
)
def test_check_ones(value: int, expected: frozenset[BitPosition]) -> None:
    assert check_ones(value) == expected
