"""Taint rule structures and conditions."""

from typing import Optional

from taintinduce.isa.register import Register
from taintinduce.memory import MemorySlot
from taintinduce.serialization import SerializableMixin
from taintinduce.types import BitPosition, Dataflow

from .conditions import LogicType, TaintCondition


class ConditionDataflowPair:
    """Represents a condition paired with its corresponding dataflow.

    Attributes:
        condition: The TaintCondition for this dataflow, or None for unconditional (default) case
        output_bits: For per-bit conditions, the set of output bit positions affected under this condition.
                     For full dataflows, a Dataflow mapping input bits to output bit sets.
    """

    def __init__(self, condition: Optional[TaintCondition], output_bits: frozenset[BitPosition] | Dataflow):
        self.condition = condition
        self.output_bits = output_bits

    def __repr__(self) -> str:
        return f'ConditionDataflowPair(condition={self.condition}, output_bits={self.output_bits})'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ConditionDataflowPair):
            return NotImplemented
        return self.condition == other.condition and self.output_bits == other.output_bits

    def __hash__(self) -> int:
        # Convert output_bits to a hashable form
        if isinstance(self.output_bits, dict):
            # For Dataflow, convert to frozen items
            output_hash = hash(frozenset(self.output_bits.items()))
        else:
            output_hash = hash(self.output_bits)
        return hash((self.condition, output_hash))


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
    pairs: list[ConditionDataflowPair]
    bytestring: str

    def __init__(
        self,
        format: TaintRuleFormat,
        pairs: list[ConditionDataflowPair],
        bytestring: str = '',
    ) -> None:
        self.format = format
        self.bytestring = bytestring
        # Deep copy dataflows - output_bits should always be a Dataflow for TaintRule
        self.pairs = []
        for pair in pairs:
            dataflow_copy = Dataflow()
            if isinstance(pair.output_bits, dict):
                dataflow = pair.output_bits
                for src_pos in dataflow:
                    dataflow_copy[src_pos] = dataflow[src_pos].copy()
            else:
                raise TypeError(f'TaintRule expects Dataflow in output_bits, got {type(pair.output_bits)}')
            self.pairs.append(
                ConditionDataflowPair(
                    condition=pair.condition,
                    output_bits=dataflow_copy,
                ),
            )

    def __str__(self) -> str:
        num_regs = len(self.format.registers) + len(self.format.mem_slots)
        return f'TaintRule(format={num_regs} regs, pairs={len(self.pairs)})'

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, TaintRule):
            return False
        if self.format != value.format or len(self.pairs) != len(value.pairs):
            return False
        for i in range(len(self.pairs)):
            if self.pairs[i].condition != value.pairs[i].condition:
                return False
            my_df = self.pairs[i].output_bits
            other_df = value.pairs[i].output_bits
            if isinstance(my_df, dict) and isinstance(other_df, dict):
                if not all(my_df.get(k) == other_df.get(k) for k in set(my_df.keys()) | set(other_df.keys())):
                    return False
            elif my_df != other_df:
                return False
        return True

    def __hash__(self) -> int:
        pairs_hash = tuple(
            (
                pair.condition,
                (
                    frozenset((k, frozenset(v)) for k, v in pair.output_bits.items())
                    if isinstance(pair.output_bits, dict)
                    else pair.output_bits
                ),
            )
            for pair in self.pairs
        )
        return hash((self.format, pairs_hash))


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


class GlobalRule(SerializableMixin):
    """Internal representation of how data is propagated within a blackbox function.

    Attributes:
        state_format (list of Register): a list of registers that defines the format of the state.
        pairs (list of ConditionDataflowPair): condition-dataflow associations
    """

    state_format: list[Register]
    pairs: list[ConditionDataflowPair]

    def __init__(
        self,
        state_format: Optional[list[Register]] = None,
        pairs: Optional[list[ConditionDataflowPair]] = None,
        repr_str: Optional[str] = None,
    ) -> None:
        if repr_str:
            self.deserialize(repr_str)
            if self.state_format is None:
                raise Exception('Invalid serialized Rule!')
        else:
            if state_format is None or pairs is None:
                raise Exception('Invalid arguments to Rule constructor!')
            self.state_format = state_format
            self.pairs = pairs

    def convert2squirrel(self, archstring: str, bytestring: str) -> TaintRule:
        """Convert internal representation to TaintRule format."""
        reg_list: list[Register] = []
        mem_list: list[MemorySlot] = []
        for reg in self.state_format:
            if 'MEM' in reg.name:
                mem_list.append(reg2memslot(reg))
            else:
                reg_list.append(reg)

        taint_rule_format = TaintRuleFormat(archstring, reg_list, mem_list)
        # Create pairs from internal ConditionDataflowPair objects
        pairs_list = []
        for pair in self.pairs:
            condition = pair.condition if pair.condition is not None else TaintCondition(LogicType.DNF, frozenset())
            pairs_list.append(
                ConditionDataflowPair(
                    condition=condition,
                    output_bits=pair.output_bits,
                ),
            )
        return TaintRule(taint_rule_format, pairs_list, bytestring)

    def web_string(self) -> str:
        mystr_list = []
        mystr_list.append(str(self.state_format))
        mystr_list.append('')
        # Iterate directly over pairs
        for pair in self.pairs:
            mystr_list.append('Condition:')
            mystr_list.append('{}'.format(pair.condition))
            mystr_list.append('')
            mystr_list.append('Dataflows: &lt;in bit&gt; &rarr; &lt;out bit&gt;')
            dataflow = pair.output_bits
            # dataflow should be a Dataflow (dict-like) at this point
            if isinstance(dataflow, dict):
                for def_bit in dataflow:
                    mystr_list.append('{} &rarr; {}'.format(def_bit, dataflow[def_bit]))
        return '<br/>'.join(mystr_list)
