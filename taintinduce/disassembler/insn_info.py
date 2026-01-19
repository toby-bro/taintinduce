from typing import Optional

from capstone import CsInsn
from capstone.arm64 import ARM64_OP_REG
from capstone.x86 import X86_OP_REG

from taintinduce.disassembler.compat import SquirrelDisassemblerZydis
from taintinduce.disassembler.exceptions import (
    UnsupportedArchException,
    UnsupportedSizeException,
)
from taintinduce.isa import amd64, arm64, jn, x86
from taintinduce.isa.isa import ISA
from taintinduce.isa.jn_isa import decode_hex_string as decode_jn_hex_string
from taintinduce.isa.jn_registers import JN_REG_NZVC, JN_REG_R1, JN_REG_R2
from taintinduce.isa.register import CondRegister, Register
from taintinduce.serialization import SerializableMixin


class InsnInfo(SerializableMixin):
    """Instruction information including state format and conditional register."""

    archstring: str
    bytestring: str
    state_format: list[Register]
    cond_reg: CondRegister

    def __init__(
        self,
        *,
        archstring: Optional[str] = None,
        bytestring: Optional[str] = None,
        state_format: Optional[list[Register]] = None,
        cond_reg: Optional[CondRegister] = None,
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


ARCH_DICT = {'X86': x86.X86(), 'AMD64': amd64.AMD64(), 'ARM64': arm64.ARM64(), 'JN': jn.JN()}


class Disassembler(object):
    arch: ISA
    cs_reg_set: list[Register]
    insn_info: InsnInfo

    def __init__(self, arch_str: str, bytestring: str) -> None:  # noqa: C901
        """Initialize wrapper over Capstone CsInsn or Cs.

        arch_str (str)          - the architecture of the instruction (currently
                            supported: X86, AMD64, ARM64, JN)
        bytestring (str)        - the hex string corresponding to the instruction
                            bytes
        """
        self.archstring = arch_str
        arch = ARCH_DICT.get(arch_str)
        if arch is None:
            raise UnsupportedArchException
        self.arch = arch

        self.bytestring = bytestring

        # JN doesn't use Capstone disassembler
        if arch_str == 'JN':
            # Decode the instruction to check if it has an immediate operand
            jn_insn = decode_jn_hex_string(bytestring)

            # For immediate instructions, exclude R2 from state (it's not used)
            # For register instructions, include R1, R2, and NZVC
            if jn_insn.has_immediate:
                reg_set = [JN_REG_R1(), JN_REG_NZVC()]
            else:
                reg_set = [JN_REG_R1(), JN_REG_R2(), JN_REG_NZVC()]

            # Pad bytestring with leading zero if it's only one character
            padded_bytestring = bytestring if len(bytestring) > 1 else bytestring + '0'

            self.insn_info = InsnInfo(
                archstring=arch_str,
                bytestring=padded_bytestring,
                state_format=reg_set,
                cond_reg=self.arch.cond_reg,
            )
            return

        dis = SquirrelDisassemblerZydis(arch_str)
        if not isinstance(dis, SquirrelDisassemblerZydis):
            raise Exception('Disassembler is not SquirrelDisassemblerZydis instance!')

        insn = dis.disassemble(bytestring)
        if not isinstance(insn, CsInsn):
            raise Exception('Disassembled object is not a CsInsn instance.')

        # capstone register set
        self.cs_reg_set = []

        # Add implicit register reads/writes
        for reg_i in insn.regs_read:
            reg_name = dis.md.reg_name(reg_i).upper()
            self.cs_reg_set.append(self.arch.create_full_reg(reg_name))

        for reg_i in insn.regs_write:
            reg_name = dis.md.reg_name(reg_i).upper()
            self.cs_reg_set.append(self.arch.create_full_reg(reg_name))

        # Add explicit register operands (fixed bug where EAX, EBX etc. weren't tracked)
        for operand in insn.operands:
            # Check if operand is a register (type varies by architecture)
            if hasattr(operand, 'type'):
                # Import the constants for register operand type check
                if arch_str in ('X86', 'AMD64'):

                    if operand.type == X86_OP_REG:
                        reg_name = dis.md.reg_name(operand.reg).upper()
                        self.cs_reg_set.append(self.arch.create_full_reg(reg_name))
                elif arch_str == 'ARM64':

                    if operand.type == ARM64_OP_REG:
                        reg_name = dis.md.reg_name(operand.reg).upper()
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
