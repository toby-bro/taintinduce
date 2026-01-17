import pdb
import random
from binascii import unhexlify
from typing import Any, Optional, Sequence

import capstone as cs
import keystone.keystone as ks
import unicorn.unicorn as unc
import unicorn.unicorn_const as uc_const

from taintinduce.isa import x86_registers
from taintinduce.isa.amd64 import AMD64
from taintinduce.isa.arm64 import ARM64
from taintinduce.isa.isa import ISA
from taintinduce.isa.register import Register
from taintinduce.isa.x86 import X86
from taintinduce.types import CpuRegisterMap

from . import cpu


def is_overlap(x1: int, x2: int, y1: int, y2: int) -> bool:
    return x1 <= y2 and y1 <= x2


def sign2unsign(value: int, bits: int) -> int:
    if value >= 0:
        return value
    return int((value + 2 ** (bits - 1)) | 2 ** (bits - 1))


def filter_address(address: int, size: int, state: list[Any]) -> bool:
    if state[2] is not None:
        # the previous address check resulted in a cross page access
        if not is_overlap(address, address + size, state[0], state[1]):
            pdb.set_trace()
        # we'll remove the current accessed set from the intended access set
        current = set(range(address, address + size))
        state[2].difference_update(current)
        if len(state[2]) == 0:
            state[0] = None
            state[1] = None
            state[2] = None
        return False

    # check if address cross two page
    start_page = address & ~0b111111111111
    end_page = (address + size) & ~0b111111111111
    if start_page != end_page:
        state[0] = address
        state[1] = address + size
        state[2] = set(range(state[0], state[1]))
    return True


def is_increase(address: int, size: int, state: list[Any]) -> bool:
    addr_end = address + size
    # [0] - start, [1] - size, [2] - merge
    # print('{} -- {}'.format(state, (address,size)))

    # first memory access
    if all(x is None for x in state):
        state[0] = address
        state[1] = size
        state[2] = False
        return True

    if state[0] + state[1] == address:
        # consective memory...
        state[1] = state[1] + size  # update size
        state[2] = True  # we just merged
    elif state[0] <= address and addr_end <= state[0] + state[1]:
        # access within the bounds of 2 previous accesses
        # probably a cross page mem access
        state[2] = False
    else:
        state[0] = address
        state[1] = size
        state[2] = False
        return True
    return False


def long_to_bytes(val: int, bits: int, endianness: str = 'little') -> bytes:
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack
    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.
    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = bits
    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)
    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)
    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)
    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]
    return s


class OutOfRangeException(Exception):
    pass


class UnicornCPU(cpu.CPU):
    arch: ISA

    def __init__(self, archstring: str, debug: bool = False) -> None:
        self.debug: bool = debug
        match archstring:
            case 'X86':
                self.arch = X86()
            case 'AMD64':
                self.arch = AMD64()
            case 'ARM64':
                self.arch = ARM64()
            case _:
                raise Exception('Unsupported architecture: {}'.format(archstring))
        self.ks: ks.Ks = ks.Ks(self.arch.ks_arch[0], self.arch.ks_arch[1])
        self.mu: unc.Uc = unc.Uc(self.arch.uc_arch[0], self.arch.uc_arch[1])
        self.md: cs.Cs = cs.Cs(self.arch.cs_arch[0], self.arch.cs_arch[1])

        self.pc_reg: Register = self.arch.pc_reg
        self.state_reg = self.arch.state_reg
        self.cpu_regs: list[Register] = self.arch.cpu_regs
        self.mem_regs = CpuRegisterMap()
        self.mem_addrs = CpuRegisterMap()
        self.pages: set[int] = set()
        self.rep_cnt: int = 0

        # Pre-compute address space limit for performance
        # This is checked on EVERY memory access in the hook, so computing it once
        # dramatically improves performance (20-50x speedup for X86)
        self.addr_space_limit: int = 2**self.arch.addr_space

        self.mu.mem_map(self.arch.code_addr, self.arch.code_mem)
        self._mem_invalid_hook_handle = self.mu.hook_add(
            uc_const.UC_HOOK_MEM_READ_UNMAPPED | uc_const.UC_HOOK_MEM_WRITE_UNMAPPED,
            self._invalid_mem,
        )
        # self._mem_invalid_hook2 = self.mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._invalid_mem_fetch)
        self._code_hook_handle = self.mu.hook_add(
            uc_const.UC_HOOK_CODE,
            self._code_hook,
            None,
            self.arch.code_addr,
            self.arch.code_addr + self.arch.code_mem,
        )

        # TODO: have to figure out how to remove this state... :(
        # self.rw_struct = [[0,0],[None, None, None], False]
        self.rw_struct: list[Any] = [[0, 0], [None, None, False], False]
        self._mem_rw_hook_handle = self.mu.hook_add(
            uc_const.UC_HOOK_MEM_WRITE | uc_const.UC_HOOK_MEM_READ,
            self._mem_hook,
            self.rw_struct,
        )

    def _code_hook(self, uc: Any, address: int, size: int, user_data: Any) -> bool:  # noqa: ARG002
        if self.rep_cnt < 1:
            self.rep_cnt += 1
        else:
            self.mu.emu_stop()
        return True

    def _invalid_mem_fetch(
        self,
        uc: Any,  # noqa: ARG002
        access: int,  # noqa: ARG002
        address: int,
        size: int,  # noqa: ARG002
        value: int,  # noqa: ARG002
        user_data: Any,  # noqa: ARG002
    ) -> bool:
        print('Invalid Mem fetch: {}'.format(hex(address)))
        return True

    def _invalid_mem(
        self,
        uc: Any,  # noqa: ARG002
        access: int,  # noqa: ARG002
        address: int,
        size: int,
        value: int,  # noqa: ARG002
        user_data: Any,  # noqa: ARG002
    ) -> bool:
        # print('Invalid Mem: {}'.format(hex(address)))
        page_addresses = set()
        page_addresses.add(address & ~0b111111111111)
        page_addresses.add(address + size & ~0b111111111111)
        for page_address in page_addresses:
            self.mu.mem_map(page_address, 4096)
            # for x in range(4096):
            #    self.mu.mem_write(page_address+x, '\x04')
            self.pages.add(page_address)
        return True

    def _mem_read(self, address: int, size: int, value: int, count: int) -> bool:  # noqa: ARG002
        mem_reg_name = 'MEM_READ{}'.format(count)
        mem_reg = getattr(x86_registers, 'X86_{}'.format(mem_reg_name))()
        mem_addr_reg = getattr(x86_registers, 'X86_{}_ADDR{}'.format(mem_reg_name, self.arch.addr_space))()
        assert mem_reg
        try:
            self.mu.mem_write(address, long_to_bytes(self.mem_regs[mem_reg], size * 8))
            self.mem_addrs[mem_addr_reg] = address
        except Exception as e:
            # print(self.mem_regs[mem_reg])
            print(e)
        return True

    def _mem_write(self, address: int, size: int, value: int, count: int) -> bool:  # noqa: ARG002
        mem_reg_name = 'MEM_WRITE{}'.format(count)
        mem_reg = getattr(x86_registers, 'X86_{}'.format(mem_reg_name))()
        mem_addr_reg = getattr(x86_registers, 'X86_{}_ADDR{}'.format(mem_reg_name, self.arch.addr_space))()
        assert mem_reg
        self.write_reg(mem_reg, value)
        self.mem_addrs[mem_addr_reg] = address
        return True

    def _mem_hook(
        self,
        uc: Any,  # noqa: ARG002
        access: int,
        address: int,
        size: int,
        value: int,
        user_data: Any,
    ) -> bool:
        # check if address is valid
        # Use pre-computed addr_space_limit for performance
        if user_data[2] or address + size >= self.addr_space_limit:
            user_data[2] = True
            # print("Hook: OutOfRange!")
            return False
        # if not filter_address(address, size, user_data[1]):
        #    #print('skip')
        #    return True
        value = sign2unsign(value, size * 8)
        if is_increase(address, size, user_data[1]):
            if access == uc_const.UC_MEM_READ:
                user_data[0][0] += 1
            elif access == uc_const.UC_MEM_WRITE:
                user_data[0][1] += 1
        if access == uc_const.UC_MEM_READ:
            # user_data[0][0] += 1
            self._mem_read(address, size, value, user_data[0][0])
        elif access == uc_const.UC_MEM_WRITE:
            # user_data[0][1] += 1
            self._mem_write(address, size, value, user_data[0][1])
        else:
            raise Exception('Unhandled access type in mem_hook!')
        return True

    def _test_mem(
        self,
        uc: Any,  # noqa: ARG002
        access: int,
        address: int,
        size: int,
        value: int,
        user_data: Any,
    ) -> bool:
        # print("addr:{}".format(hex(address)))
        # print('access:{}'.format(access))
        # print('size:{}'.format(size))
        # pdb.set_trace()
        mem_access, state = user_data
        value = sign2unsign(value, size * 8)
        if filter_address(address, size, state):
            mem_access[address] = (access, size, value)
        return True

    def identify_memops_jump(self, code: bytes) -> tuple[set[Register], Optional[Register]]:
        print('Identifying memops')
        jump_reg: Optional[Register] = None
        mem_set_set: set[tuple[Register, ...]] = set()
        mem_access: dict[int, tuple[int, int, Optional[int]]] = {}
        state: list[Optional[int]] = [None, None, None]
        test_mem_state = (mem_access, state)
        h = self.mu.hook_add(uc_const.UC_HOOK_MEM_READ | uc_const.UC_HOOK_MEM_WRITE, self._test_mem, test_mem_state)
        self.mu.hook_del(self._mem_rw_hook_handle)

        count = 0
        fail = 0
        while count < 100:
            mem_set = set()
            mem_access.clear()
            state[0] = None
            state[1] = None
            state[2] = None
            self.randomize_regs()
            try:
                sa, sb = self.execute(code)
            except unc.UcError as e:
                # print(e)
                # print(e.errno)
                fail += 1
                if fail < 10000:
                    continue
                raise Exception('Failed a total of 10000 times in identify memops') from e
            except OutOfRangeException:
                continue
            start_pc = sa[self.pc_reg]
            end_pc = sb[self.pc_reg]
            if start_pc is None or end_pc is None:
                raise Exception('PC is None')
            if start_pc != end_pc - len(code) and start_pc != end_pc:
                # print('{:064b} - {}'.format(start_pc,start_pc))
                # print('{:064b} - {}'.format(end_pc,end_pc))
                # print('len:{}'.format(len(code)))
                jump_reg = self.pc_reg

            count += 1

            # process mem_access to obtain number of memory access
            # we'll try to consolidate the memory accesses
            # each memory access is represented as a range

            # we'll check memory using filter_address instead of is_increase
            # the two methods should agree...

            # [0] - addr, [1] - size, [2] - value (not in use)
            temp_mem_addr_set = set()
            for addr in mem_access:
                temp_mem_addr_set.add((addr, addr + mem_access[addr][1]))

            # ensure that none of the range overlap
            # while doing that, merge consecutive filtered address...
            temp_mem_addr = list(temp_mem_addr_set)
            temp_mem_addr.sort(key=lambda x: x[0])

            for x_idx in range(len(temp_mem_addr[:-1])):
                if temp_mem_addr[x_idx][1] > temp_mem_addr[x_idx + 1][0]:
                    pdb.set_trace()
                    raise Exception
                if temp_mem_addr[x_idx][1] == temp_mem_addr[x_idx + 1][0]:
                    chunk1_addr = temp_mem_addr[x_idx][0]
                    chunk1_access = mem_access[chunk1_addr][0]
                    chunk1_size = temp_mem_addr[x_idx][1] - chunk1_addr
                    chunk2_addr = temp_mem_addr[x_idx + 1][0]
                    chunk2_access = mem_access[chunk2_addr][0]
                    chunk2_size = temp_mem_addr[x_idx + 1][1] - chunk2_addr

                    if chunk1_access != chunk2_access:
                        break

                    # consective, merge it
                    mem_access[chunk1_addr] = (chunk1_access, chunk1_size + chunk2_size, None)
                    assert chunk2_addr in mem_access
                    mem_access.pop(chunk2_addr)

            # at this point, we can create the memory operands.
            wc = 0
            rc = 0
            for _, (access, size, _) in mem_access.items():
                mem_reg = None
                if access == uc_const.UC_MEM_WRITE:
                    wc += 1
                    mem_reg, addr_reg = self.arch.name2mem('MEM_WRITE{}'.format(wc))
                elif access == uc_const.UC_MEM_READ:
                    rc += 1
                    mem_reg, addr_reg = self.arch.name2mem('MEM_READ{}'.format(rc))
                else:
                    raise Exception

                assert mem_reg
                assert addr_reg
                mem_reg.bits = size * 8
                mem_reg.structure.append(mem_reg.bits)
                mem_set.add(mem_reg)
                mem_set.add(addr_reg)

            mem_set_set.add(tuple(sorted(mem_set, key=lambda x: x.uc_const)))

        assert len(mem_set_set) == 1
        mem_registers = set(mem_set_set.pop())

        self.mu.hook_del(h)
        self._mem_rw_hook_handle = self.mu.hook_add(
            uc_const.UC_HOOK_MEM_WRITE | uc_const.UC_HOOK_MEM_READ,
            self._mem_hook,
            self.rw_struct,
        )
        print('Done identifying memops')

        return mem_registers, jump_reg

    def set_memregs(self, mem_regs: set[Register]) -> None:
        for mem_reg in mem_regs:
            if 'ADDR' in mem_reg.name:
                self.mem_addrs[mem_reg] = 0
            else:
                self.mem_regs[mem_reg] = 0

    def asm2bin(self, asm_string: str) -> str:
        encoding, _ = self.ks.asm(asm_string)
        if encoding is None:
            raise Exception('Keystone failed to assemble instruction: {}'.format(asm_string))
        return str(bytearray(encoding))

    def format_print(self, msg: str) -> None:
        print(('=' * 24 + '%-10s' + '=' * 24) % (msg))

    def write_reg(self, reg: Register, value: int) -> None:
        if reg in self.mem_regs:
            # store the memory stuff...
            self.mem_regs[reg] = value
        elif reg in self.cpu_regs:
            value_set = []
            for size in reg.structure:
                value_mask = (1 << size) - 1
                value_set.append(value & value_mask)
                value >>= size
            if len(value_set) == 1:
                self.mu.reg_write(reg.uc_const, value_set[0])
            else:
                self.mu.reg_write(reg.uc_const, tuple(value_set))
        elif reg in self.mem_addrs:
            self.mem_addrs[reg] = value
        else:
            pdb.set_trace()

    def write_regs(self, regs: Sequence[Register], values: Sequence[int] | int) -> None:
        seq_values: Sequence[int]
        if isinstance(values, int):
            seq_values = tuple([values for _ in regs])
        else:
            seq_values = values

        if len(regs) != len(seq_values):
            raise ValueError(f'Length mismatch: {len(regs)} registers but {len(seq_values)} values')
        max_length = len(regs)
        for count in range(max_length):
            self.write_reg(regs[count], seq_values[count])

    def read_reg(self, reg: Register) -> int:
        if reg in self.mem_regs:
            value = self.mem_regs[reg]
        elif reg in self.cpu_regs:
            value_set = self.mu.reg_read(reg.uc_const)
            value = 0
            if hasattr(value_set, '__iter__'):
                values_len = len(value_set)
                if values_len != len(reg.structure):
                    raise Exception('Register structure length mismatch!')
                for x in range(values_len):
                    value |= value_set[x] << sum(reg.structure[:x])
                value = int(value)
            else:
                value = value_set
        elif reg in self.mem_addrs:
            value = self.mem_addrs[reg]
        else:
            pdb.set_trace()
            raise Exception('Register not found!')

        return value

    def print_regs(self, reg_list: list[Register]) -> None:
        for reg in reg_list:
            fstr = '{{: <8}}: {{:0{}b}}'.format(reg.bits)
            print(fstr.format(reg.name, self.read_reg(reg)))

    def get_cpu_state(self) -> CpuRegisterMap:
        result = CpuRegisterMap()

        for reg in self.cpu_regs:
            result[reg] = self.read_reg(reg)
        for reg in self.mem_regs:
            result[reg] = self.read_reg(reg)
        for reg in self.mem_addrs:
            result[reg] = self.mem_addrs[reg]

        return result

    def set_cpu_state(self, cpu_state: CpuRegisterMap) -> None:
        for reg, value in cpu_state.items():
            self.write_reg(reg, value)

    def randomize_regs(self, reg_list: Optional[list[Register]] = None) -> None:
        if reg_list is None:
            reg_list = self.cpu_regs + list(self.mem_regs)

        # randomly initialize all cpu regs
        for reg in reg_list:
            random_number = random.getrandbits(reg.bits)
            self.write_reg(reg, random_number)

    def clear_page(self) -> None:
        for page_address in self.pages:
            self.mu.mem_unmap(page_address, 4096)
        self.pages.clear()

    def init_state(self) -> None:
        if isinstance(self.arch, AMD64) or isinstance(self.arch, X86):
            self.write_reg(x86_registers.X86_REG_FPSW(), 0)

        # TODO: have to figure out how to remove this state... :(
        self.rw_struct[0] = [0, 0]
        self.rw_struct[1] = [None, None, None]
        self.rw_struct[2] = False

    def execute(
        self,
        code: bytes,
    ) -> tuple[CpuRegisterMap, CpuRegisterMap]:
        """Execute code in Unicorn and return CPU state before and after execution."""
        self.init_state()
        self.clear_page()
        self.rep_cnt = 0
        self.write_reg(self.pc_reg, self.arch.code_addr)
        state_before = self.get_cpu_state()
        try:
            self.mu.mem_write(self.arch.code_addr, code)
            start_pc = self.read_reg(self.pc_reg)  # noqa: F841
            self.mu.emu_start(self.arch.code_addr, self.arch.code_addr + len(code))
        except unc.UcError as e:
            if e.errno != uc_const.UC_ERR_FETCH_UNMAPPED:
                raise e

        if self.rw_struct[2]:
            raise OutOfRangeException
        state_after = self.get_cpu_state()
        return (state_before, state_after)


def main() -> None:
    cpu = UnicornCPU('X86')
    # cpu.identify_memops('\x8b\x45\x08')
    # cpu.identify_memops('\xa4')
    # cpu.identify_memops('\x48\xa7')

    # mem_registers = cpu.identify_memops('\x48\x8b\x03')
    # cpu.randomize_regs()
    # cpu.execute('\x48\x8b\x03')

    # mem_registers = cpu.identify_memops('\x48\x89\x18')
    # cpu.randomize_regs()
    # cpu.execute('\x48\x89\x18')

    # mem_registers = cpu.identify_memops('\x89\x18')
    # cpu.randomize_regs()
    # cpu.execute('\x89\x18')

    # mem_registers = cpu.identify_memops('\x8b\x03')
    # cpu.set_memregs(mem_registers)
    # cpu.randomize_regs()
    # cpu.write_reg(isa.x86_registers.X86_REG_EBX(), 2**64-1)
    # cpu.write_reg(isa.x86_registers.X86_MEM_READ1(), 2**64-1)
    # cpu.print_regs(list(cpu.get_cpu_state()))
    # a,b = cpu.execute('\x8b\x03')
    # cpu.print_regs(list(cpu.get_cpu_state()))

    # mem_registers, is_jump = cpu.identify_memops_jump('\xc3')
    # mem_registers, is_jump = cpu.identify_memops_jump('\x8b\x03')
    mem_registers, is_jump = cpu.identify_memops_jump(b'\xf3\xab')
    cpu.set_memregs(mem_registers)
    print(mem_registers)
    print(is_jump)


if __name__ == '__main__':
    main()
