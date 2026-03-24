from unittest.mock import MagicMock, patch

from taintinduce.classifier.categories import InstructionCategory
from taintinduce.instrumentation.ast import (
    BinaryExpr,
    InstructionCellExpr,
    LogicCircuit,
    Op,
)
from taintinduce.isa.register import Register
from taintinduce.sleigh.engine import _map_sleigh_to_state, generate_static_rule
from taintinduce.types import Architecture


class DummyRegister(Register):
    def __init__(self, name: str, size: int):
        self.name = name
        self.size = size
        self.uc_const = 0
        self.bits = size * 8
        self.structure: list[int] = []
        self.value = None
        self.address = None


def test_map_sleigh_to_state_x86_flags() -> None:
    ctx = MagicMock()
    state_format: list[Register] = [DummyRegister('FLAGS', size=8)]
    res = _map_sleigh_to_state(ctx, 'X86', state_format, 514, 1)
    assert res == ('FLAGS', 2, 2)


def test_map_sleigh_to_state_register() -> None:
    ctx = MagicMock()
    reg_mock = MagicMock()
    reg_mock.offset = 16
    reg_mock.size = 8

    ctx.registers.get.side_effect = lambda name: reg_mock if name == 'RAX' else None
    state_format: list[Register] = [DummyRegister('RAX', size=8)]

    res = _map_sleigh_to_state(ctx, 'X86', state_format, 16, 8)
    assert res == ('RAX', 0, 63)


def test_map_sleigh_to_state_partial_register() -> None:
    ctx = MagicMock()
    reg_mock = MagicMock()
    reg_mock.offset = 16
    reg_mock.size = 8

    ctx.registers.get.side_effect = lambda name: reg_mock if name == 'RAX' else None

    state_format: list[Register] = [DummyRegister('RAX', size=8)]

    res = _map_sleigh_to_state(ctx, 'X86', state_format, 16, 4)
    assert res == ('RAX', 0, 31)

    res2 = _map_sleigh_to_state(ctx, 'X86', state_format, 18, 2)
    assert res2 == ('RAX', 16, 31)


def test_map_sleigh_to_state_not_found() -> None:
    ctx = MagicMock()
    ctx.registers.get.return_value = None
    state_format: list[Register] = [DummyRegister('RAX', size=8)]
    res = _map_sleigh_to_state(ctx, 'X86', state_format, 128, 4)
    assert res is None


@patch('taintinduce.sleigh.engine.get_context')
@patch('taintinduce.sleigh.engine.lift_instruction')
@patch('taintinduce.sleigh.engine.slice_backward')
@patch('taintinduce.sleigh.engine.determine_category')
@patch('taintinduce.sleigh.engine.compute_polarity')
def test_generate_static_rule_mapped(
    mock_compute_polarity: MagicMock,
    mock_determine_category: MagicMock,
    mock_slice_backward: MagicMock,
    mock_lift_instruction: MagicMock,
    mock_get_context: MagicMock,
) -> None:
    ctx = MagicMock()
    mock_get_context.return_value = ctx

    reg_mock1 = MagicMock()
    reg_mock1.offset = 16
    reg_mock1.size = 8
    reg_mock2 = MagicMock()
    reg_mock2.offset = 32
    reg_mock2.size = 8

    def mock_get(name: str) -> MagicMock | None:
        if name == 'RAX':
            return reg_mock1
        if name == 'RBX':
            return reg_mock2
        return None

    ctx.registers.get.side_effect = mock_get

    translation = MagicMock()
    mock_op = MagicMock()
    mock_op.output.space.name = 'register'
    mock_op.output.offset = 16
    mock_op.output.size = 8

    # Mocking _get_varnode_id behavior: output is RAX
    translation.ops = [mock_op]
    mock_lift_instruction.return_value = translation

    mock_slice_backward.return_value = [mock_op]
    mock_determine_category.return_value = InstructionCategory.MAPPED
    mock_compute_polarity.return_value = {'register:32:8': 1}

    state_format: list[Register] = [DummyRegister('RAX', size=8), DummyRegister('RBX', size=8)]
    bytestring = b'\x00'

    rule = generate_static_rule(Architecture.X86, bytestring, state_format)

    assert isinstance(rule, LogicCircuit)
    assert len(rule.assignments) == 1
    assignment = rule.assignments[0]

    assert assignment.target.name == 'RAX'
    assert len(assignment.dependencies) == 1
    assert assignment.dependencies[0].name == 'RBX'
    assert 'OR' not in str(assignment.expression)


@patch('taintinduce.sleigh.engine.get_context')
@patch('taintinduce.sleigh.engine.lift_instruction')
@patch('taintinduce.sleigh.engine.slice_backward')
@patch('taintinduce.sleigh.engine.determine_category')
@patch('taintinduce.sleigh.engine.compute_polarity')
def test_generate_static_rule_transportable(
    mock_compute_polarity: MagicMock,
    mock_determine_category: MagicMock,
    mock_slice_backward: MagicMock,
    mock_lift_instruction: MagicMock,
    mock_get_context: MagicMock,
) -> None:
    ctx = MagicMock()
    mock_get_context.return_value = ctx
    reg_mock1 = MagicMock()
    reg_mock1.offset = 16
    reg_mock1.size = 8
    reg_mock2 = MagicMock()
    reg_mock2.offset = 32
    reg_mock2.size = 8

    ctx.registers.get.side_effect = lambda name: reg_mock1 if name == 'RAX' else (reg_mock2 if name == 'RBX' else None)

    translation = MagicMock()
    mock_op = MagicMock()
    mock_op.output.space.name = 'register'
    mock_op.output.offset = 16
    mock_op.output.size = 8

    translation.ops = [mock_op]
    mock_lift_instruction.return_value = translation
    mock_slice_backward.return_value = [mock_op]
    mock_determine_category.return_value = InstructionCategory.TRANSPORTABLE
    mock_compute_polarity.return_value = {'register:32:8': 0}

    state_format: list[Register] = [DummyRegister('RAX', size=8), DummyRegister('RBX', size=8)]

    rule = generate_static_rule(Architecture.X86, b'\x00', state_format)
    assert len(rule.assignments) == 1
    expr = rule.assignments[0].expression
    assert isinstance(expr, BinaryExpr)
    assert expr.op == Op.OR


@patch('taintinduce.sleigh.engine.get_context')
@patch('taintinduce.sleigh.engine.lift_instruction')
@patch('taintinduce.sleigh.engine.slice_backward')
@patch('taintinduce.sleigh.engine.determine_category')
@patch('taintinduce.sleigh.engine.compute_polarity')
def test_generate_static_rule_unknown(
    mock_compute_polarity: MagicMock,
    mock_determine_category: MagicMock,
    mock_slice_backward: MagicMock,
    mock_lift_instruction: MagicMock,
    mock_get_context: MagicMock,
) -> None:
    ctx = MagicMock()
    mock_get_context.return_value = ctx
    reg_mock1 = MagicMock()
    reg_mock1.offset = 16
    reg_mock1.size = 8
    reg_mock2 = MagicMock()
    reg_mock2.offset = 32
    reg_mock2.size = 8

    ctx.registers.get.side_effect = lambda name: reg_mock1 if name == 'RAX' else (reg_mock2 if name == 'RBX' else None)

    translation = MagicMock()
    mock_op = MagicMock()
    mock_op.output.space.name = 'register'
    mock_op.output.offset = 16
    mock_op.output.size = 8

    translation.ops = [mock_op]
    mock_lift_instruction.return_value = translation
    mock_slice_backward.return_value = [mock_op]
    mock_determine_category.return_value = InstructionCategory.UNKNOWN
    mock_compute_polarity.return_value = {'register:32:8': 1}

    state_format: list[Register] = [DummyRegister('RAX', size=8), DummyRegister('RBX', size=8)]

    rule = generate_static_rule(Architecture.X86, b'\x00', state_format)
    assert len(rule.assignments) == 1
    expr = rule.assignments[0].expression
    assert isinstance(expr, InstructionCellExpr)
