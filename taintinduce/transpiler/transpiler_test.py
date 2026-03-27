from taintinduce.instrumentation.ast import (
    BinaryExpr,
    InstructionCellExpr,
    LogicCircuit,
    Op,
    TaintAssignment,
    TaintOperand,
    UnaryExpr,
)
from taintinduce.transpiler.transpiler import make_transpiler
from taintinduce.types import Architecture


def test_transpiler_x86() -> None:
    # Construct a simple AST
    t_eax = TaintOperand('EAX', 0, 31, is_taint=True)
    v_eax = TaintOperand('EAX', 0, 31, is_taint=False)

    expr = BinaryExpr(Op.AND, v_eax, UnaryExpr(Op.NOT, t_eax))

    # InstructionCellExpr: and eax, ebx (21d8)
    cell = InstructionCellExpr(Architecture.X86, '21d8', 'EAX', 0, 31, {'EAX': expr})

    assignment = TaintAssignment(t_eax, [t_eax], cell)
    circuit = LogicCircuit([assignment], Architecture.X86, '21d8', [])

    transpiler = make_transpiler(Architecture.X86)
    asm = transpiler.transpile(circuit)

    assert 'mov eax, dword ptr [V_EAX_31_0]' in asm
    assert 'mov ebx, dword ptr [T_EAX_31_0]' in asm
    assert 'not ebx' in asm
    assert 'and eax, ebx' in asm
    assert '.byte 0x21, 0xd8' in asm


def test_transpiler_amd64() -> None:
    t_rax = TaintOperand('RAX', 0, 63, is_taint=True)
    v_rax = TaintOperand('RAX', 0, 63, is_taint=False)

    expr = BinaryExpr(Op.OR, v_rax, t_rax)
    assignment = TaintAssignment(t_rax, [t_rax], expr)
    circuit = LogicCircuit([assignment], Architecture.AMD64, '4809c3', [])

    transpiler = make_transpiler(Architecture.AMD64)
    asm = transpiler.transpile(circuit)

    assert 'mov rax, qword ptr [V_RAX_63_0]' in asm
    assert 'mov rbx, qword ptr [T_RAX_63_0]' in asm
    assert 'or rax, rbx' in asm


def test_transpiler_arm64() -> None:
    t_x0 = TaintOperand('X0', 0, 63, is_taint=True)
    v_x0 = TaintOperand('X0', 0, 63, is_taint=False)

    expr = BinaryExpr(Op.XOR, v_x0, t_x0)
    assignment = TaintAssignment(t_x0, [t_x0], expr)
    circuit = LogicCircuit([assignment], Architecture.ARM64, '8a010000', [])

    transpiler = make_transpiler(Architecture.ARM64)
    asm = transpiler.transpile(circuit)

    assert 'ldr x0, =V_X0_63_0' in asm
    assert 'ldr x0, =T_X0_63_0' in asm
    assert 'eor x2, x2, x3' in asm
