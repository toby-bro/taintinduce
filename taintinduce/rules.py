"""Taint rule structures and conditions."""

import itertools
from enum import Enum
from typing import Any, Optional

import taintinduce.isa.x86_registers as x86_registers
from taintinduce.isa.arm64_registers import ARM64_REG_NZCV
from taintinduce.isa.register import Register
from taintinduce.memory import MemorySlot
from taintinduce.serialization import SerializableMixin
from taintinduce.state import State, check_ones
from taintinduce.types import BitPosition, Dataflow


class LogicType(Enum):
    DNF = 0
    LOGIC = 1
    CMP = 2


class TaintCondition(SerializableMixin):
    """Condition that represents a partition bisection for conditional dataflow.

    Attributes:
        OPS_FN_MAP (dict{String: String}): A mapping that maps the operation string to its function name.

    The condition is represented as a tuple containing the operator in string and
    a list of the arguments to be performed based on the operator. (String, [])
    For example, a DNF can be represented as [('DNF', [(1024, 0),(64,1),...]), ...]
    """

    condition_type: LogicType
    condition_ops: Optional[frozenset[tuple[int, int]]]

    def __repr__(self) -> str:
        if self.condition_ops is None:
            return 'TaintCondition()'
        return f'TaintCondition({self.condition_type}, {self.get_cond_bits()}, {[i for _, i in self.condition_ops]})'

    def __str__(self) -> str:
        return self.__repr__()

    def __init__(
        self,
        condition_type: LogicType,
        conditions: Optional[frozenset[tuple[int, int]]] = None,
        repr_str: Optional[str] = None,
    ) -> None:
        if repr_str:
            self.deserialize(repr_str)
        else:
            self.condition_type = condition_type
            self.condition_ops = conditions

    def __hash__(self) -> int:
        return hash((self.condition_type, self.condition_ops))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TaintCondition):
            return False
        return self.condition_type == other.condition_type and self.condition_ops == other.condition_ops

    def eval(self, state: State) -> bool:
        """The eval() method takes in a State object and checks if the condition evaluates to True or False.

        Args:
            state (State): The State object to which the condition is being evaluated on.
        Returns:
            True if the condition evaluates is satisfied else False.
        Raises:
            None
        """
        result = True
        if self.condition_ops is None:
            return result

        match self.condition_type:
            case LogicType.DNF:
                return self._dnf_eval(state, self.condition_ops)
            case LogicType.CMP:
                return self._cmp_eval(state, self.condition_ops)
            case LogicType.LOGIC:
                return self._logic_eval(state, self.condition_ops)
            case _:
                raise ValueError(f'Condition type {self.condition_type} is not defined')

    def get_cond_bits(self) -> frozenset[BitPosition]:
        if self.condition_ops is None:
            return frozenset()
        cond_bits: set[BitPosition] = set()
        if self.condition_type == LogicType.DNF:
            for mask, _ in self.condition_ops:
                cond_bits |= check_ones(mask)
        return frozenset(cond_bits)

    def _dnf_eval(self, state: State, dnf_args: frozenset[tuple[int, int]]) -> bool:
        if state.state_value is None:
            raise Exception('State value not initialized!')
        return any((state.state_value & bitmask == value) for bitmask, value in dnf_args)

    def _logic_eval(self, state: State, logic_args: Any) -> bool:  # noqa: ARG002
        raise Exception('Not yet implemented')

    def _cmp_eval(self, state: State, cmp_args: Any) -> bool:  # noqa: ARG002
        raise Exception('Not yet implemented')


class TaintRuleFormat:
    """State format metadata for serialized TaintRules.

    Contains architecture info and register/memory layout for taint rules.
    This is distinct from state_format (list[Register]) used for State decoding.
    """

    def __init__(
        self,
        arch: str,
        registers: list[Register],
        mem_slots: list[MemorySlot],
    ) -> None:
        self.arch: str = arch
        self.registers: list[Register] = registers or []
        self.mem_slots: list[MemorySlot] = mem_slots or []

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, TaintRuleFormat):
            return False
        return (
            self.arch == value.arch
            and all(r1 == r2 for r1, r2 in zip(self.registers, value.registers, strict=True))
            and all(m1 == m2 for m1, m2 in zip(self.mem_slots, value.mem_slots, strict=True))
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.arch,
                tuple(self.registers),
                tuple(self.mem_slots),
            ),
        )


class TaintRule(SerializableMixin):
    """Taint propagation rule for an instruction.

    Represents how taint flows from input bits to output bits,
    potentially under certain conditions.
    """

    format: TaintRuleFormat
    conditions: list[TaintCondition]
    dataflows: list[Dataflow]

    def __init__(
        self,
        format: TaintRuleFormat,
        conditions: list[TaintCondition],
        dataflows: list[Dataflow],
    ) -> None:
        self.format = format
        self.conditions = conditions
        self.dataflows = [Dataflow() for _ in dataflows]
        for df_id, dataflow in enumerate(dataflows):
            for src_pos in dataflow:
                self.dataflows[df_id][src_pos] = dataflow[src_pos].copy()

    def __str__(self) -> str:
        num_regs = len(self.format.registers) + len(self.format.mem_slots)
        return f'TaintRule(format={num_regs} regs, conditions={len(self.conditions)}, dataflows={len(self.dataflows)})'

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, TaintRule):
            return False
        return (
            self.format == value.format
            and self.conditions == value.conditions
            and all(
                all(self.dataflows[i][k] == value.dataflows[i][k] for k in self.dataflows[i] if k in value.dataflows[i])
                for i in range(len(self.dataflows))
            )
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.format,
                tuple(self.conditions),
                tuple(frozenset((k, frozenset(v)) for k, v in df.items()) for df in self.dataflows),
            ),
        )


def reg2memslot(reg: Register) -> MemorySlot:
    """Convert a register with MEM in its name to a MemorySlot."""
    assert 'MEM' in reg.name
    mem_access: Optional[str] = None
    mem_slot: Optional[int] = None
    q = reg.name.split('_')
    mem_type = MemorySlot.ADDR if len(q) == 3 else MemorySlot.VALUE
    t = q[1]
    if 'WRITE' in t:
        mem_access = MemorySlot.WRITE
        mem_slot = int(t[5:])
    elif 'READ' in t:
        mem_access = MemorySlot.READ
        mem_slot = int(t[4:])
    mem_size = reg.bits // 8
    if mem_slot is None or mem_access is None:
        raise Exception('Cannot convert register to memslot!')
    if not isinstance(mem_slot, int):
        raise Exception('mem_slot is not int!')
    return MemorySlot.get_mem(mem_slot, mem_access, mem_size, mem_type)


class Rule(SerializableMixin):
    """Internal representation of how data is propagated within a blackbox function.

    Attributes:
        state_format (list of Register): a list of registers that defines the format of the state.
        conditions (list of TaintCondition): conditional taint propagation rules
        dataflows (list of dict): dataflow mappings for each condition
    """

    state_format: list[Register]
    conditions: list[TaintCondition]
    dataflows: list[Dataflow]

    def __init__(
        self,
        state_format: Optional[list[Register]] = None,
        conditions: Optional[list[TaintCondition]] = None,
        dataflows: Optional[list[Dataflow]] = None,
        repr_str: Optional[str] = None,
    ) -> None:
        if repr_str:
            self.deserialize(repr_str)
            if self.state_format is None or self.conditions is None or self.dataflows is None:
                raise Exception('Invalid serialized Rule!')
        else:
            if state_format is None or conditions is None or dataflows is None:
                raise Exception('Invalid arguments to Rule constructor!')
            self.state_format = state_format
            self.conditions = conditions
            self.dataflows = dataflows

    def convert2squirrel(self, archstring: str) -> TaintRule:
        """Convert internal representation to TaintRule format."""
        reg_list: list[Register] = []
        mem_list: list[MemorySlot] = []
        for reg in self.state_format:
            if 'MEM' in reg.name:
                mem_list.append(reg2memslot(reg))
            else:
                reg_list.append(reg)

        taint_rule_format = TaintRuleFormat(archstring, reg_list, mem_list)
        return TaintRule(taint_rule_format, self.conditions, self.dataflows)

    def web_string(self) -> str:
        mystr_list = []
        mystr_list.append(str(self.state_format))
        mystr_list.append('')
        dep_list = list(itertools.zip_longest(self.conditions, self.dataflows))
        for condition, dataflow in dep_list:
            mystr_list.append('Condition:')
            mystr_list.append('{}'.format(condition))
            mystr_list.append('')
            mystr_list.append('Dataflows: &lt;in bit&gt; &rarr; &lt;out bit&gt;')
            for def_bit in dataflow:
                mystr_list.append('{} &rarr; {}'.format(def_bit, dataflow[def_bit]))
        return '<br/>'.join(mystr_list)


class InsnInfo(SerializableMixin):
    """Instruction information including state format and conditional register."""

    archstring: str
    bytestring: str
    state_format: list[Register]
    cond_reg: x86_registers.X86_REG_EFLAGS | ARM64_REG_NZCV

    def __init__(
        self,
        *,
        archstring: Optional[str] = None,
        bytestring: Optional[str] = None,
        state_format: Optional[list[Register]] = None,
        cond_reg: Optional[x86_registers.X86_REG_EFLAGS | ARM64_REG_NZCV] = None,
        repr_str: Optional[str] = None,
    ) -> None:
        if repr_str:
            self.deserialize(repr_str)
        else:
            if state_format is None:
                state_format = []
            if archstring is None or bytestring is None or cond_reg is None:
                raise Exception('Invalid arguments to InsnInfo constructor!')
            self.archstring = archstring
            self.bytestring = bytestring
            self.state_format = state_format
            self.cond_reg = cond_reg
