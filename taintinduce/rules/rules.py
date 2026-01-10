"""Taint rule structures and conditions."""

import itertools
from typing import Optional

from taintinduce.isa.register import Register
from taintinduce.memory import MemorySlot
from taintinduce.serialization import SerializableMixin
from taintinduce.types import Dataflow

from .conditions import TaintCondition


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
