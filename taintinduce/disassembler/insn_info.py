#!/usr/bin/env python3


from taintinduce.disassembler.compat import SquirrelDisassemblerZydis
from taintinduce.disassembler.exceptions import (
    UnsupportedArchException,
    UnsupportedSizeException,
)
from taintinduce.isa import amd64, arm64, x86
from taintinduce.isa.register import Register
from taintinduce.rules import InsnInfo


class Disassembler(object):
    arch: x86.X86 | amd64.AMD64 | arm64.ARM64
    cs_reg_set: list[Register]
    insn_info: InsnInfo

    def __init__(self, arch_str: str, bytestring: str) -> None:
        """Initialize wrapper over Capstone CsInsn or Cs.

        arch_str (str)          - the architecture of the instruction (currently
                            supported: X86, AMD64)
        bytestring (str)        - the hex string corresponding to the instruction
                            bytes
        """
        self.archstring = arch_str
        if arch_str == 'X86':
            self.arch = x86.X86()
        elif arch_str == 'AMD64':
            self.arch = amd64.AMD64()
        elif arch_str == 'ARM64':
            self.arch = arm64.ARM64()
        else:
            raise UnsupportedArchException

        self.bytestring = bytestring
        dis = SquirrelDisassemblerZydis(arch_str)

        insn = dis.disassemble(bytestring)

        # capstone register set
        self.cs_reg_set = []

        for reg_i in insn.reg_reads():
            reg_name = dis.md.reg_name(reg_i).upper() if dis.md else str(reg_i)
            self.cs_reg_set.append(self.arch.create_full_reg(reg_name))

        for reg_i in insn.reg_writes():
            reg_name = dis.md.reg_name(reg_i).upper() if dis.md else str(reg_i)
            self.cs_reg_set.append(self.arch.create_full_reg(reg_name))

        # we don't fuck around with FPSW cause unicorn can't write stuff in it
        for reg in self.cs_reg_set:
            if reg.name == 'FPSW':
                self.cs_reg_set.remove(reg)

        reg_set = list(set(self.cs_reg_set))
        self.insn_info = InsnInfo(
            archstring=arch_str,
            bytestring=bytestring,
            state_format=reg_set,
            cond_reg=self.arch.cond_reg,
        )

    # Weird function to check out later
    # def _get_mem_bits(self, operand: Any, regs: Any) -> int:
    #     # for ARM32 and ARM64 capstone does not have a size
    #     # attribute for operands so we set it based on the other
    #     # operands size
    #     if hasattr(operand, 'size'):
    #         bits = operand.size * 8
    #     else:
    #         if operand.access == capstone.CS_AC_READ:
    #             reg0 = self.arch.name2reg(cs_insn_info.reg_name(regs[0]))
    #         elif operand.access == capstone.CS_AC_WRITE:
    #             reg0 = self.arch.name2reg(cs_insn_info.reg_name(regs[0]))
    #         bits = reg0.bits * 8
    #     return bits

    def _set_mem_reg_structure(self, reg_bytes: int) -> tuple[int, list[int]]:
        """Took this code from yanhao.
        THIS IS ONLY FOR IMPLICIT REGS DEFINED IN THE x86_insn_info_ct
            It sets the virtual registers for memory structure based on the
            register size.

            set args for a mem register
            92bits? doulble check
        """
        valid_size = [8, 16, 32, 64, 128, 256]

        bits = reg_bytes * 8
        if bits == 80:
            structure = [64, 16]
        elif bits in valid_size:
            structure = [reg_bytes * 8]
        else:
            raise UnsupportedSizeException

        return bits, structure
