from capstone import CS_ARCH_X86, CS_MODE_32
from keystone.keystone_const import KS_ARCH_X86, KS_MODE_32
from unicorn import UC_ARCH_X86, UC_MODE_32

from . import x86_registers
from .isa import ISA
from .register import Register


# x86 architecture
class X86(ISA):
    def __init__(self) -> None:
        self.cpu_regs = [
            x86_registers.X86_REG_EAX(),
            x86_registers.X86_REG_EBX(),
            x86_registers.X86_REG_ECX(),
            x86_registers.X86_REG_EDX(),
            x86_registers.X86_REG_EBP(),
            x86_registers.X86_REG_ESP(),
            x86_registers.X86_REG_EDI(),
            x86_registers.X86_REG_ESI(),
            x86_registers.X86_REG_EFLAGS(),
            x86_registers.X86_REG_EIP(),
            x86_registers.X86_REG_XMM0(),
            x86_registers.X86_REG_XMM1(),
            x86_registers.X86_REG_XMM2(),
            x86_registers.X86_REG_XMM3(),
            x86_registers.X86_REG_XMM4(),
            x86_registers.X86_REG_XMM5(),
            x86_registers.X86_REG_XMM6(),
            x86_registers.X86_REG_XMM7(),
            x86_registers.X86_REG_FP0(),
            x86_registers.X86_REG_FP1(),
            x86_registers.X86_REG_FP2(),
            x86_registers.X86_REG_FP3(),
            x86_registers.X86_REG_FP4(),
            x86_registers.X86_REG_FP5(),
            x86_registers.X86_REG_FP6(),
            x86_registers.X86_REG_FP7(),
            x86_registers.X86_REG_FPSW(),
        ]

        self.full_cpu_regs = [
            # Byte Registers
            x86_registers.X86_REG_AL(),
            x86_registers.X86_REG_AH(),
            x86_registers.X86_REG_BH(),
            x86_registers.X86_REG_BL(),
            x86_registers.X86_REG_CH(),
            x86_registers.X86_REG_CL(),
            x86_registers.X86_REG_DH(),
            x86_registers.X86_REG_DL(),
            x86_registers.X86_REG_DIL(),
            x86_registers.X86_REG_SIL(),
            # Word Registers
            x86_registers.X86_REG_AX(),
            x86_registers.X86_REG_BX(),
            x86_registers.X86_REG_CX(),
            x86_registers.X86_REG_DX(),
            x86_registers.X86_REG_DI(),
            x86_registers.X86_REG_SI(),
            x86_registers.X86_REG_BP(),
            x86_registers.X86_REG_SP(),
            x86_registers.X86_REG_IP(),
            x86_registers.X86_REG_BPL(),
            x86_registers.X86_REG_SPL(),
            # Doubleword Registers
            x86_registers.X86_REG_EAX(),
            x86_registers.X86_REG_EBP(),
            x86_registers.X86_REG_EBX(),
            x86_registers.X86_REG_ECX(),
            x86_registers.X86_REG_EDI(),
            x86_registers.X86_REG_EDX(),
            x86_registers.X86_REG_EFLAGS(),
            x86_registers.X86_REG_EIP(),
            x86_registers.X86_REG_ESI(),
            x86_registers.X86_REG_ESP(),
            # Multiword Registers
            x86_registers.X86_REG_XMM0(),
            x86_registers.X86_REG_XMM1(),
            x86_registers.X86_REG_XMM2(),
            x86_registers.X86_REG_XMM3(),
            x86_registers.X86_REG_XMM4(),
            x86_registers.X86_REG_XMM5(),
            x86_registers.X86_REG_XMM6(),
            x86_registers.X86_REG_XMM7(),
            x86_registers.X86_REG_FP7(),
            x86_registers.X86_REG_FP0(),
            x86_registers.X86_REG_FP1(),
            x86_registers.X86_REG_FP2(),
            x86_registers.X86_REG_FP3(),
            x86_registers.X86_REG_FP4(),
            x86_registers.X86_REG_FP5(),
            x86_registers.X86_REG_FP6(),
            x86_registers.X86_REG_FPSW(),
        ]

        # XXX: teo: can i remove these?
        self.cpu_read_emu_regs = [x86_registers.X86_MEM_READ2(), x86_registers.X86_MEM_READ1()]
        self.cpu_write_emu_regs = [x86_registers.X86_MEM_WRITE1()]

        # XXX: teo: do we need these ??
        self.pc_reg = x86_registers.X86_REG_EIP()
        self.flag_reg = [x86_registers.X86_REG_EFLAGS()]
        self.state_reg = [x86_registers.X86_REG_FPSW()]

        # Sub register
        self.register_map = {
            'EAX': ['AL', 'AH', 'AX'],
            'EBX': ['BL', 'BH', 'BX'],
            'ECX': ['CL', 'CH', 'CX'],
            'EDX': ['DL', 'DH', 'DX'],
            'ESI': ['SI', 'SIL'],
            'EDI': ['DI', 'DIL'],
            'EBP': ['BP', 'BPL'],
            'ESP': ['SP', 'SPL'],
            'EIP': ['IP'],
            'FP0': ['ST(0)', 'ST0', 'MM0', 'ST'],
            'FP1': ['ST(1)', 'ST1', 'MM1'],
            'FP2': ['ST(2)', 'ST2', 'MM2'],
            'FP3': ['ST(3)', 'ST3', 'MM3'],
            'FP4': ['ST(4)', 'ST4', 'MM4'],
            'FP5': ['ST(5)', 'ST5', 'MM5'],
            'FP6': ['ST(6)', 'ST6', 'MM6'],
            'FP7': ['ST(7)', 'ST7', 'MM7'],
        }

        self.register_alias = {}
        for reg_name in self.register_map:
            self.register_alias[reg_name] = reg_name
            for aliased_reg_name in self.register_map[reg_name]:
                self.register_alias[aliased_reg_name] = reg_name

        self.uc_arch = (UC_ARCH_X86, UC_MODE_32)
        self.ks_arch = (KS_ARCH_X86, KS_MODE_32)
        self.cs_arch = (CS_ARCH_X86, CS_MODE_32)
        self.code_mem = 4096
        self.code_addr = 0x6D1C000

        self.addr_space = 32

        self.cond_reg = x86_registers.X86_REG_EFLAGS()

    def name2mem(self, name: str) -> tuple[Register, Register]:
        name = name.upper()
        name = name.replace('(', '')
        name = name.replace(')', '')
        return (getattr(x86_registers, f'X86_{name}')(), getattr(x86_registers, f'X86_{name}_ADDR32')())

    def name2reg(self, name: str) -> Register:
        name = name.upper()
        name = name.replace('(', '')
        name = name.replace(')', '')

        return getattr(x86_registers, f'X86_REG_{name}')()

    def create_full_reg(self, name: str, bits: int = 0, structure: list[int] = []) -> Register:  # noqa: B006
        name = name.upper()
        name = name.replace('(', '')
        name = name.replace(')', '')
        if 'MEM' in name:
            reg = getattr(x86_registers, f'X86_{name}')()
            reg.bits, reg.structure = bits, structure
            return reg

        for full_reg_name, sub_regs_name in self.register_map.items():
            if name in sub_regs_name:
                return getattr(x86_registers, f'X86_REG_{full_reg_name}')()

        return getattr(x86_registers, f'X86_REG_{name}')()
