from taintinduce.instrumentation.ast import (
    AvalancheExpr,
    BinaryExpr,
    Constant,
    Expr,
    InstructionCellExpr,
    LogicCircuit,
    Op,
    TaintAssignment,
    TaintOperand,
    UnaryExpr,
)
from taintinduce.types import Architecture


class Transpiler:
    def transpile(self, circuit: LogicCircuit) -> str:
        raise NotImplementedError

    def format_var_name(self, var: TaintOperand) -> str:
        return str(var).replace('[', '_').replace(']', '').replace(':', '_')


class RegisterAllocator:
    def __init__(self, regs: list[str]) -> None:
        self.regs = regs.copy()
        self.in_use: set[str] = set()

    def alloc(self) -> str:
        for r in self.regs:
            if r not in self.in_use:
                self.in_use.add(r)
                return r
        raise RuntimeError('Out of registers')

    def free(self, r: str) -> None:
        self.in_use.remove(r)


class RegisterAllocatorTranspiler(Transpiler):
    def __init__(self, regs: list[str]) -> None:
        self.code: list[str] = []
        self.allocator = RegisterAllocator(regs)

    def emit(self, instr: str) -> None:
        self.code.append(instr)

    def transpile(self, circuit: LogicCircuit) -> str:
        self.code = []
        for assignment in circuit.assignments:
            self.transpile_assignment(assignment)
        return '\n'.join(self.code)

    def ptr_size(self) -> str:
        raise NotImplementedError

    def load_val(self, reg: str, val: int) -> None:
        raise NotImplementedError

    def load_var(self, reg: str, var_name: str) -> None:
        raise NotImplementedError

    def store_var(self, var_name: str, reg: str) -> None:
        raise NotImplementedError

    def emit_op(self, op: Op, lhs: str, rhs: str) -> None:
        raise NotImplementedError

    def emit_not(self, reg: str) -> None:
        raise NotImplementedError

    def emit_avalanche(self, reg: str) -> None:
        raise NotImplementedError

    def emit_push(self, reg: str) -> None:
        raise NotImplementedError

    def emit_pop(self, reg: str) -> None:
        raise NotImplementedError

    def emit_mov(self, dst: str, src: str) -> None:
        raise NotImplementedError

    def emit_byte(self, bytes_str: str) -> None:
        raise NotImplementedError

    def emit_shr(self, reg: str, count: int) -> None:
        raise NotImplementedError

    def emit_and_imm(self, reg: str, imm: int) -> None:
        raise NotImplementedError

    def transpile_assignment(self, assignment: TaintAssignment) -> None:
        target_var = 'OUT_' + self.format_var_name(assignment.target)
        if assignment.expression is None and len(assignment.dependencies) == 1:
            dep = assignment.dependencies[0]
            if str(dep) == str(assignment.target):
                reg = self.allocator.alloc()
                self.load_var(reg, self.format_var_name(dep))
                self.store_var(target_var, reg)
                self.allocator.free(reg)
                return

        if assignment.expression is not None:
            res_reg = self.transpile_expr(assignment.expression)
            self.store_var(target_var, res_reg)
            self.allocator.free(res_reg)
        else:
            if not assignment.dependencies:
                reg = self.allocator.alloc()
                self.load_val(reg, 0)
                self.store_var(target_var, reg)
                self.allocator.free(reg)
            else:
                res_reg = self.transpile_expr(assignment.dependencies[0])
                for dep in assignment.dependencies[1:]:
                    dep_reg = self.transpile_expr(dep)
                    self.emit_op(Op.OR, res_reg, dep_reg)
                    self.allocator.free(dep_reg)
                self.store_var(target_var, res_reg)
                self.allocator.free(res_reg)

    def transpile_expr(self, expr: Expr) -> str:  # noqa: C901
        if isinstance(expr, Constant):
            reg = self.allocator.alloc()
            self.load_val(reg, expr.value)
            return reg
        if isinstance(expr, TaintOperand):
            reg = self.allocator.alloc()
            self.load_var(reg, self.format_var_name(expr))
            return reg
        if isinstance(expr, UnaryExpr):
            reg = self.transpile_expr(expr.expr)
            if expr.op == Op.NOT:
                self.emit_not(reg)
            else:
                raise NotImplementedError
            return reg
        if isinstance(expr, AvalancheExpr):
            reg = self.transpile_expr(expr.expr)
            self.emit_avalanche(reg)
            return reg
        if isinstance(expr, BinaryExpr):
            lhs_reg = self.transpile_expr(expr.lhs)
            rhs_reg = self.transpile_expr(expr.rhs)
            self.emit_op(expr.op, lhs_reg, rhs_reg)
            self.allocator.free(rhs_reg)
            return lhs_reg
        if isinstance(expr, InstructionCellExpr):
            in_use_before = sorted(self.allocator.in_use)
            for r in in_use_before:
                self.emit_push(r)

            keys = list(expr.inputs.keys())
            for k in keys:
                reg = self.transpile_expr(expr.inputs[k])
                self.emit_push(reg)
                self.allocator.free(reg)

            arch_regs = [str(k).lower() for k in keys]
            for arch in reversed(arch_regs):
                self.emit_pop(arch)

            bytes_str = ', '.join([f'0x{expr.instruction[i : i + 2]}' for i in range(0, len(expr.instruction), 2)])
            self.emit_byte(bytes_str)

            out_arch = expr.out_reg.lower()

            res_reg = self.allocator.alloc()

            # Save the result immediately. Since res_reg was just allocated and wasn't in in_use_before,
            # this is unconditionally safe if we pop in_use_before AFTERWARD!
            # Wait: What if out_arch was one of in_use_before? Then popping in_use_before could overwrite
            # the real value of that register that the cell output generated! BUT we just moved it to res_reg safely!
            # So the out_arch value is backed up in res_reg!
            # Then we restore the original out_arch value that it had BEFORE the cell! (which is absolutely correct).
            self.emit_mov(res_reg, out_arch)

            for r in reversed(in_use_before):
                self.emit_pop(r)

            if expr.out_bit_start > 0:
                self.emit_shr(res_reg, expr.out_bit_start)

            mask = (1 << (expr.out_bit_end - expr.out_bit_start + 1)) - 1
            if mask not in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
                self.emit_and_imm(res_reg, mask)

            return res_reg
        raise NotImplementedError


class X86Transpiler(RegisterAllocatorTranspiler):
    def __init__(self) -> None:
        super().__init__(['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'])

    def ptr_size(self) -> str:
        return 'dword ptr'

    def load_val(self, reg: str, val: int) -> None:
        self.emit(f'mov {reg}, {val}')

    def load_var(self, reg: str, var_name: str) -> None:
        self.emit(f'mov {reg}, {self.ptr_size()} [{var_name}]')

    def store_var(self, var_name: str, reg: str) -> None:
        self.emit(f'mov {self.ptr_size()} [{var_name}], {reg}')

    def emit_op(self, op: Op, lhs: str, rhs: str) -> None:
        if op == Op.AND:
            self.emit(f'and {lhs}, {rhs}')
        elif op == Op.OR:
            self.emit(f'or {lhs}, {rhs}')
        elif op == Op.XOR:
            self.emit(f'xor {lhs}, {rhs}')
        else:
            raise NotImplementedError

    def emit_not(self, reg: str) -> None:
        self.emit(f'not {reg}')

    def emit_avalanche(self, reg: str) -> None:
        self.emit(f'neg {reg}')
        self.emit(f'sbb {reg}, {reg}')

    def emit_push(self, reg: str) -> None:
        if reg == 'eflags':
            self.emit('pushfd')
        else:
            self.emit(f'push {reg}')

    def emit_pop(self, reg: str) -> None:
        if reg == 'eflags':
            self.emit('popfd')
        else:
            self.emit(f'pop {reg}')

    def emit_mov(self, dst: str, src: str) -> None:
        if src == 'eflags':
            self.emit('pushfd')
            self.emit(f'pop {dst}')
        elif dst == 'eflags':
            self.emit(f'push {src}')
            self.emit('popfd')
        elif dst != src:
            self.emit(f'mov {dst}, {src}')

    def emit_byte(self, bytes_str: str) -> None:
        self.emit(f'.byte {bytes_str}')

    def emit_shr(self, reg: str, count: int) -> None:
        self.emit(f'shr {reg}, {count}')

    def emit_and_imm(self, reg: str, imm: int) -> None:
        self.emit(f'and {reg}, {imm}')


class AMD64Transpiler(RegisterAllocatorTranspiler):
    def __init__(self) -> None:
        super().__init__(['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9'])

    def ptr_size(self) -> str:
        return 'qword ptr'

    def load_val(self, reg: str, val: int) -> None:
        self.emit(f'mov {reg}, {val}')

    def load_var(self, reg: str, var_name: str) -> None:
        self.emit(f'mov {reg}, {self.ptr_size()} [{var_name}]')

    def store_var(self, var_name: str, reg: str) -> None:
        self.emit(f'mov {self.ptr_size()} [{var_name}], {reg}')

    def emit_op(self, op: Op, lhs: str, rhs: str) -> None:
        if op == Op.AND:
            self.emit(f'and {lhs}, {rhs}')
        elif op == Op.OR:
            self.emit(f'or {lhs}, {rhs}')
        elif op == Op.XOR:
            self.emit(f'xor {lhs}, {rhs}')
        else:
            raise NotImplementedError

    def emit_not(self, reg: str) -> None:
        self.emit(f'not {reg}')

    def emit_avalanche(self, reg: str) -> None:
        self.emit(f'neg {reg}')
        self.emit(f'sbb {reg}, {reg}')

    def emit_push(self, reg: str) -> None:
        if reg in ('eflags', 'rflags'):
            self.emit('pushfq')
        else:
            self.emit(f'push {reg}')

    def emit_pop(self, reg: str) -> None:
        if reg in ('eflags', 'rflags'):
            self.emit('popfq')
        else:
            self.emit(f'pop {reg}')

    def emit_mov(self, dst: str, src: str) -> None:
        if src in ('eflags', 'rflags'):
            self.emit('pushfq')
            self.emit(f'pop {dst}')
        elif dst in ('eflags', 'rflags'):
            self.emit(f'push {src}')
            self.emit('popfq')
        elif dst != src:
            self.emit(f'mov {dst}, {src}')

    def emit_byte(self, bytes_str: str) -> None:
        self.emit(f'.byte {bytes_str}')

    def emit_shr(self, reg: str, count: int) -> None:
        self.emit(f'shr {reg}, {count}')

    def emit_and_imm(self, reg: str, imm: int) -> None:
        self.emit(f'and {reg}, {imm}')


class ARM64Transpiler(RegisterAllocatorTranspiler):
    def __init__(self) -> None:
        # Avoid x0, x1 as they are used for temps sometimes, use x2-x7
        super().__init__(['x2', 'x3', 'x4', 'x5', 'x6', 'x7'])

    def ptr_size(self) -> str:
        return ''

    def load_val(self, reg: str, val: int) -> None:
        self.emit(f'ldr {reg}, ={val}')

    def load_var(self, reg: str, var_name: str) -> None:
        self.emit(f'ldr x0, ={var_name}')
        self.emit(f'ldr {reg}, [x0]')

    def store_var(self, var_name: str, reg: str) -> None:
        self.emit(f'ldr x0, ={var_name}')
        self.emit(f'str {reg}, [x0]')

    def emit_op(self, op: Op, lhs: str, rhs: str) -> None:
        if op == Op.AND:
            self.emit(f'and {lhs}, {lhs}, {rhs}')
        elif op == Op.OR:
            self.emit(f'orr {lhs}, {lhs}, {rhs}')
        elif op == Op.XOR:
            self.emit(f'eor {lhs}, {lhs}, {rhs}')
        else:
            raise NotImplementedError

    def emit_not(self, reg: str) -> None:
        self.emit(f'mvn {reg}, {reg}')

    def emit_push(self, reg: str) -> None:
        self.emit(f'str {reg}, [sp, #-16]!')

    def emit_pop(self, reg: str) -> None:
        self.emit(f'ldr {reg}, [sp], #16')

    def emit_mov(self, dst: str, src: str) -> None:
        if dst != src:
            self.emit(f'mov {dst}, {src}')

    def emit_avalanche(self, reg: str) -> None:
        self.emit(f'cmp {reg}, xzr')
        self.emit(f'csetm {reg}, ne')

    def emit_byte(self, bytes_str: str) -> None:
        self.emit(f'.byte {bytes_str}')

    def emit_shr(self, reg: str, count: int) -> None:
        self.emit(f'lsr {reg}, {reg}, #{count}')

    def emit_and_imm(self, reg: str, imm: int) -> None:
        self.emit(f'ldr x1, ={imm}')
        self.emit(f'and {reg}, {reg}, x1')


def make_transpiler(arch: Architecture | str) -> Transpiler:
    if isinstance(arch, str):
        if arch == 'X86':
            arch = Architecture.X86
        elif arch == 'AMD64':
            arch = Architecture.AMD64
        elif arch == 'ARM64':
            arch = Architecture.ARM64

    if arch == Architecture.X86:
        return X86Transpiler()
    if arch == Architecture.AMD64:
        return AMD64Transpiler()
    if arch == Architecture.ARM64:
        return ARM64Transpiler()
    raise NotImplementedError(f'Transpiler for {arch} not implemented')
