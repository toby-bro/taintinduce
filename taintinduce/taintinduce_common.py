import itertools
import sys
from typing import Any, ClassVar, Optional, Sequence, TypeAlias

import taintinduce.isa.x86_registers as x86_registers
from taintinduce.isa.arm64_registers import ARM64_REG_NZCV
from taintinduce.isa.register import Register
from taintinduce.serialization import (
    MemorySlot,
    SerializableMixin,
)
from taintinduce.serialization import (
    TaintInduceDecoder as BaseDecoder,
)

# Type alias for register-mapped CPU state representation
CpuRegisterMap: TypeAlias = dict[Register, int]


class TaintInduceDecoder(BaseDecoder):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def object_hook(self, dct: dict[str, Any]) -> Any:
        if '_obj_name' not in dct:
            return dct
        obj_name = dct['_obj_name']
        current_module = sys.modules[__name__]
        if hasattr(current_module, obj_name):
            obj = getattr(current_module, obj_name)()
            obj.__dict__ = dct['data']
        elif hasattr(x86_registers, obj_name):
            obj = getattr(x86_registers, obj_name)()
            obj.__dict__ = dct['data']
        else:
            obj = super().object_hook(dct)
        return obj


# TODO: All these classes should be shared with engine.py
def query_yes_no(question: str, default: Optional[str] = 'yes') -> bool:
    """Ask a yes/no question via raw_input() and return their answer.
    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).
    The "answer" return value is one of "yes" or "no".
    """
    valid = {'yes': True, 'y': True, 'ye': True, 'no': False, 'n': False}
    if default is None:
        prompt = ' [y/n] '
    elif default == 'yes':
        prompt = ' [Y/n] '
    elif default == 'no':
        prompt = ' [y/N] '
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        if choice in valid:
            return valid[choice]
        sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")


def check_ones(value: int) -> set[int]:
    """Obtains the position of bits that are set"""
    result_set: set[int] = set()
    pos = 0
    while value:
        if value & 1:
            result_set.add(pos)
        value >>= 1
        pos += 1
    return result_set


def reg2pos(all_regs: Sequence[Register], reg: Register) -> int:
    """Function which convert reg to its start postition in State value
    Attribute:
        all_regs : a list of reg class
        reg: reg class
    Return:
        pos (int)
    """
    regs_list = sorted(all_regs, key=lambda reg: reg.uc_const)
    pos = 0
    for r in regs_list:
        if r == reg:
            break
        pos += r.bits
    return pos


def convert2rpn(
    all_regs: Sequence[Register],
    regs: Sequence[Register],
    masks: Sequence[int],
    values: Sequence[int],
) -> tuple[Optional[int], Optional[int]]:
    """convert reg+mask+values to condition rpn
    Attribute:
        regs (a list of reg class)
        masks (a list of int): a list of reg mask
        values (a list of int): a list of reg value
    Return:
        rpn (): see Condition class
    """
    if len(regs) == 1:
        reg = regs[0]
        mask = masks[0]
        val = values[0]
        state_mask = mask << reg2pos(all_regs, reg)
        state_val = val << reg2pos(all_regs, reg)
        return state_mask, state_val
    if len(regs) == 2:
        arg = []
        for reg in regs:
            arg.append(((1 << reg.bits) - 1) << reg2pos(all_regs, reg))
        arg1 = arg[0]
        arg2 = arg[1]
        return arg1, arg2
    return None, None


def pos2reg(state1: 'State', state2: 'State', regs: Sequence[Register]) -> list[tuple[Register, int]]:
    """trans posval to reg"""
    pos_val = list(state1.diff(state2))
    pos_val = sorted(pos_val, reverse=True)
    regs_list = sorted(regs, key=lambda reg: reg.uc_const)
    pos = 0
    res_regs = set()

    for reg in regs_list:
        bpos = pos
        pos += reg.bits
        while pos_val:
            p = pos_val[-1]
            if p < pos:
                res_regs.add((reg, p - bpos))
                pos_val.pop()
            else:
                break

    return list(res_regs)


def regs2bits(cpustate: CpuRegisterMap, state_format: Sequence[Register]) -> 'State':
    """Converts CpuRegisterMap into a State object using state_format
    state: cpu_state dict()
    """
    bits = 0
    value = 0
    for reg in state_format:
        value |= cpustate[reg] << bits
        bits += reg.bits

    return State(bits, value)


def regs2bits2(cpustate: CpuRegisterMap, state_format: Sequence[Register]) -> 'State':
    """Converts CpuRegisterMap into a State object using state_format
    state: cpu_state dict()
    """
    bits = 0
    value = 0
    for reg in state_format:
        # print('a:{}->{}'.format(bits, cpustate[reg]))
        print('bin:{:0128b}'.format(cpustate[reg] << bits))
        value |= cpustate[reg] << bits
        bits += reg.bits

    return State(bits, value)


def bits2regs(state: 'State', regs: Sequence[Register]) -> CpuRegisterMap:
    """trans state object to cpu_state dict()
    state: State object
    reg  : regs list
    """
    cpu_state: CpuRegisterMap = {}
    value = state.state_value
    regs_list = sorted(regs, key=lambda reg: reg.uc_const)
    for reg in regs_list:
        cpu_state[reg] = ((2**reg.bits) - 1) & value
        value = value >> reg.bits
    return cpu_state


def bitpos2reg(bitpos: int, state_format: Sequence[Register]) -> Register:
    remaining_pos = bitpos
    for reg in state_format:
        remaining_pos -= reg.bits
        if remaining_pos <= 0:
            break
    return reg


def extract_reg2bits(state: 'State', reg: Register, state_format: Sequence[Register]) -> 'State':
    reg_start_pos = reg_pos(reg, state_format)
    reg_mask = (1 << reg.bits) - 1

    # mask for the state to isolate the register
    state_mask = reg_mask << reg_start_pos
    isolated_reg_value = state.state_value & state_mask
    reg_value = isolated_reg_value >> reg_start_pos

    return State(reg.bits, reg_value)


def print_bin(value: int) -> None:
    print('{:064b}'.format(value))


def reg_pos(reg: Register, state_format: Sequence[Register]) -> int:
    reg_start_pos = 0
    for reg2 in state_format:
        if reg == reg2:
            break
        reg_start_pos += reg2.bits
    return reg_start_pos


"""Some bit manipulation functions
"""


def set_bit(value: int, pos: int) -> int:
    return value | (1 << pos)


def unset_bit(value: int, pos: int) -> int:
    return value & (~(1 << pos))


def invert_bit(value: int, pos: int) -> int:
    return value ^ (1 << pos)


def shift_espresso(
    espresso_cond: set[tuple[int, int]],
    reg: Register,
    state_format: Sequence[Register],
) -> set[tuple[int, int]]:
    reg_start_pos = reg_pos(reg, state_format)
    new_espresso_cond: set[tuple[int, int]] = set()
    for conditional_bitmask, conditional_value in espresso_cond:
        new_bitmask = conditional_bitmask << reg_start_pos
        new_value = conditional_value << reg_start_pos
        new_espresso_cond.add((new_bitmask, new_value))
    return new_espresso_cond


def espresso2cond(espresso_cond: set[tuple[int, int]]) -> 'TaintCondition':
    """Converts ESPRESSO conditions into Condition object"""
    return TaintCondition(('DNF', list(espresso_cond)))


class State(SerializableMixin):
    """Represention of the input / output of an instruction.
    Attributes:
        num_bits (int): Size of state in number of bits.
        state_bits (int): Bitvector to represent the state stored as an integer.
    """

    state_value: int
    num_bits: int

    def __init__(
        self,
        num_bits: Optional[int] = None,
        state_value: Optional[int] = None,
        repr_str: Optional[str] = None,
    ) -> None:
        """Initializes the State object to length num_bits.

        The __init__ method takes in an argument num_bits and initializes the state_array.

        Args:
            num_bits (int): Size of State in bits.
            state_value (int): Integer value representing the bit array.
        Returns:
            None
        Raises:
            None
        """

        if repr_str:
            self.deserialize(repr_str)
        elif num_bits is not None and state_value is not None:
            self.num_bits = num_bits
            self.state_value = state_value
        else:
            raise Exception('Invalid arguments to State constructor!')

    def __str__(self) -> str:
        """Produces the corresponding bit string for the given state.
        Args:
            None
        Returns:
            A bitstring representing the state. For example, for the argument (8, 2), the corresponding string returned
                is "00000010"
        """

        return '{{:<0{}b}}'.format(self.num_bits).format(self.state_value)

    def diff(self, other_state: 'State') -> set[int]:
        """Obtains the difference between two States.
        Args:
            other_state (State): The other state which we will be comparing against.

        Returns:
            A set of integers which identifies which position are different between the two States.
        """
        if self.state_value is None or other_state.state_value is None:
            raise Exception('State values not initialized!')

        value_changed = self.state_value ^ other_state.state_value
        return check_ones(value_changed)


class Observation(SerializableMixin):
    """Collection of states that represents a single observation.
    Made up of an initial input seed state, followed by a set of mutated states obtained by performing a single bit-flip.
    For each state, an 'output' state is included forming a tuple (input_state, output_state) called IOPair.
    Attributes:
        seed_io (IOPair): A tuple representing the seed state. (input_state, output_state).
        mutated_ios (list of IOPair): A list containing all IOPairs of mutated states.
    """  # noqa: E501

    seed_io: tuple[State, State]
    mutated_ios: list[tuple[State, State]]
    bytestring: str
    archstring: str
    state_format: list[Register]

    def __init__(
        self,
        iopair: Optional[tuple[State, State]] = None,
        mutated_iopairs: Optional[list[tuple[State, State]]] = None,
        bytestring: Optional[str] = None,
        archstring: Optional[str] = None,
        state_format: Optional[list[Register]] = None,
        repr_str: Optional[str] = None,
    ) -> None:
        """Initializes the Observation object with the .

        The __init__ method takes in an argument num_bits and initializes the state_array

        Args:
            iopair ((State, State)): seed_state of the form (input_state, output_state)
            mutated_iopairs (list of (State, State)): list of tuple of mutated States of the form [(in_1, out_1), ...]
        Returns:
            None
        Raises:
            None
        """

        if repr_str:
            self.deserialize(repr_str)
            if (
                self.seed_io is None
                or self.mutated_ios is None
                or self.bytestring is None
                or self.archstring is None
                or self.state_format is None
            ):
                raise Exception('Invalid serialized Observation!')
        else:
            if (
                iopair is None
                or mutated_iopairs is None
                or bytestring is None
                or archstring is None
                or state_format is None
            ):
                raise Exception('Invalid arguments to Observation constructor!')
            self.seed_io = iopair
            self.mutated_ios = mutated_iopairs
            self.bytestring = bytestring
            self.archstring = archstring
            self.state_format = state_format


class TaintCondition(SerializableMixin):
    """Condition is a class that represents a condition bisecting a partition into two.

    Attributes:
        OPS_FN_MAP (dict{String: String}): A mapping that maps the operation string to its function name.

    The condition is represented as a tuple containing the operator in string and
    a list of the arguments to be performed based on the operator. (String, [])
    For example, a DNF can be represented as [('DNF', [(1024, 0),(64,1),...]), ...]
    """

    OPS_FN_MAP: ClassVar[dict[str, str]] = {'DNF': '_dnf_eval', 'LOGIC': '_logic_eval', 'CMP': '_cmp_eval'}

    def __init__(
        self,
        conditions: Optional[tuple[str, list[tuple[int, int]]]] = None,
        repr_str: Optional[str] = None,
    ) -> None:
        if repr_str:
            self.deserialize(repr_str)
        else:
            self.condition_ops = conditions

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
        ops_name, ops_args = self.condition_ops
        result &= getattr(self, self.OPS_FN_MAP[ops_name])(state, ops_args)
        return result

    def get_cond_bits(self) -> set[int]:
        if self.condition_ops is None:
            return set()
        ops_name, ops_args = self.condition_ops
        cond_bits = set()
        if ops_name == 'DNF':
            for mask, _ in ops_args:
                cond_bits |= check_ones(mask)
        return cond_bits

    def _dnf_eval(self, state: State, dnf_args: list[tuple[int, int]]) -> bool:
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


class TaintRule(SerializableMixin):
    """
    Simplified TaintRule to replace squirrel.acorn.acorn.TaintRule.
    Represents taint propagation rules.
    """

    format: TaintRuleFormat
    conditions: list[TaintCondition]
    dataflows: list[dict[int, set[int]]]

    def __init__(
        self,
        format: TaintRuleFormat,
        conditions: list[TaintCondition],
        dataflows: list[dict[int, set[int]]],
    ) -> None:
        self.format = format
        self.conditions = conditions
        self.dataflows = [{} for _ in dataflows]
        for df_id, dataflow in enumerate(dataflows):
            for src_pos in dataflow:
                self.dataflows[df_id][src_pos] = dataflow[src_pos].copy()

    def __str__(self) -> str:
        # Handle both list and TaintRuleFormat objects
        num_regs = len(self.format.registers) + len(self.format.mem_slots)

        return f'TaintRule(format={num_regs} regs, conditions={len(self.conditions)}, dataflows={len(self.dataflows)})'

    def __repr__(self) -> str:
        return self.__str__()


def reg2memslot(reg: Register) -> MemorySlot:
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
    # pdb.set_trace()
    if not isinstance(mem_slot, int):
        raise Exception('mem_slot is not int!')
    return MemorySlot.get_mem(mem_slot, mem_access, mem_size, mem_type)


class Rule(SerializableMixin):
    """Object which represents how data is propagated within a blackbox function.

    Attributes:
        state_format (list of Register): a list of registers that defines the format of the state.
        conditions (list of Condition): a list of strings which represents the condition (reverse polish notation)
        dataflows ({True:{int: set(int)}}, False:{int:set(int)}): a list of dictionaries with key being the bit position
            being used and the set being the bit position being defined.
    """

    state_format: list[Register]
    conditions: list[TaintCondition]
    dataflows: list[dict[int, set[int]]]

    def __init__(
        self,
        state_format: Optional[list[Register]] = None,
        conditions: Optional[list[TaintCondition]] = None,
        dataflows: Optional[list[dict[int, set[int]]]] = None,
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
        g = archstring
        reg_list: list[Register] = []
        mem_list: list[MemorySlot] = []
        for reg in self.state_format:
            if 'MEM' in reg.name:
                mem_list.append(reg2memslot(reg))
            else:
                reg_list.append(reg)

        taint_rule_format = TaintRuleFormat(g, reg_list, mem_list)
        # Use TaintCondition objects directly - they're already serializable
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
            self.archstring = archstring
            self.bytestring = bytestring
            self.state_format = state_format
            self.cond_reg = cond_reg
