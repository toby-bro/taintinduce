from typing import Optional

from capstone import CS_ARCH_X86, CS_MODE_64
from keystone.keystone_const import KS_ARCH_X86, KS_MODE_64
from unicorn import UC_ARCH_X86, UC_MODE_64

from . import x86_registers
from .isa import ISA
from .register import Register


# x64 architecture
class AMD64(ISA):
    def __init__(self) -> None:
        self.cpu_regs = [
            # General Registers
            x86_registers.X86_REG_RAX(),
            x86_registers.X86_REG_RBX(),
            x86_registers.X86_REG_RCX(),
            x86_registers.X86_REG_RDX(),
            x86_registers.X86_REG_RBP(),
            x86_registers.X86_REG_RSP(),
            x86_registers.X86_REG_RDI(),
            x86_registers.X86_REG_RSI(),
            x86_registers.X86_REG_EFLAGS(),
            x86_registers.X86_REG_RIP(),
            x86_registers.X86_REG_R8(),
            x86_registers.X86_REG_R9(),
            x86_registers.X86_REG_R10(),
            x86_registers.X86_REG_R11(),
            x86_registers.X86_REG_R12(),
            x86_registers.X86_REG_R13(),
            x86_registers.X86_REG_R14(),
            x86_registers.X86_REG_R15(),
            # un-general
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
            x86_registers.X86_REG_AH(),
            x86_registers.X86_REG_AL(),
            x86_registers.X86_REG_AX(),
            x86_registers.X86_REG_BH(),
            x86_registers.X86_REG_BL(),
            x86_registers.X86_REG_BP(),
            x86_registers.X86_REG_BPL(),
            x86_registers.X86_REG_BX(),
            x86_registers.X86_REG_CH(),
            x86_registers.X86_REG_CL(),
            x86_registers.X86_REG_CX(),
            x86_registers.X86_REG_DH(),
            x86_registers.X86_REG_DI(),
            x86_registers.X86_REG_DIL(),
            x86_registers.X86_REG_DL(),
            x86_registers.X86_REG_DX(),
            x86_registers.X86_REG_IP(),
            x86_registers.X86_REG_SI(),
            x86_registers.X86_REG_SIL(),
            x86_registers.X86_REG_SP(),
            x86_registers.X86_REG_SPL(),
            # word registers
            x86_registers.X86_REG_EAX(),
            x86_registers.X86_REG_EBP(),
            x86_registers.X86_REG_EBX(),
            x86_registers.X86_REG_ECX(),
            x86_registers.X86_REG_ESI(),
            x86_registers.X86_REG_EDI(),
            x86_registers.X86_REG_EDX(),
            x86_registers.X86_REG_RFLAGS(),
            x86_registers.X86_REG_EIP(),
            x86_registers.X86_REG_ESP(),
            # double word registers
            x86_registers.X86_REG_RAX(),
            x86_registers.X86_REG_RBP(),
            x86_registers.X86_REG_RBX(),
            x86_registers.X86_REG_RCX(),
            x86_registers.X86_REG_RDI(),
            x86_registers.X86_REG_RDX(),
            x86_registers.X86_REG_RIP(),
            x86_registers.X86_REG_RSI(),
            x86_registers.X86_REG_RSP(),
            # New general register
            x86_registers.X86_REG_R8B(),
            x86_registers.X86_REG_R9B(),
            x86_registers.X86_REG_R10B(),
            x86_registers.X86_REG_R11B(),
            x86_registers.X86_REG_R12B(),
            x86_registers.X86_REG_R13B(),
            x86_registers.X86_REG_R14B(),
            x86_registers.X86_REG_R15B(),
            x86_registers.X86_REG_R8D(),
            x86_registers.X86_REG_R9D(),
            x86_registers.X86_REG_R10D(),
            x86_registers.X86_REG_R11D(),
            x86_registers.X86_REG_R12D(),
            x86_registers.X86_REG_R13D(),
            x86_registers.X86_REG_R14D(),
            x86_registers.X86_REG_R15D(),
            x86_registers.X86_REG_R8W(),
            x86_registers.X86_REG_R9W(),
            x86_registers.X86_REG_R10W(),
            x86_registers.X86_REG_R11W(),
            x86_registers.X86_REG_R12W(),
            x86_registers.X86_REG_R13W(),
            x86_registers.X86_REG_R14W(),
            x86_registers.X86_REG_R15W(),
            x86_registers.X86_REG_R8(),
            x86_registers.X86_REG_R9(),
            x86_registers.X86_REG_R10(),
            x86_registers.X86_REG_R11(),
            x86_registers.X86_REG_R12(),
            x86_registers.X86_REG_R13(),
            x86_registers.X86_REG_R14(),
            x86_registers.X86_REG_R15(),
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

        self.cpu_read_emu_regs = [x86_registers.X86_MEM_READ2(), x86_registers.X86_MEM_READ1()]
        self.cpu_write_emu_regs = [x86_registers.X86_MEM_WRITE1()]

        self.pc_reg = x86_registers.X86_REG_RIP()
        self.flag_reg = [x86_registers.X86_REG_EFLAGS()]
        self.state_reg = [x86_registers.X86_REG_FPSW()]

        self.register_map = {
            'RAX': ['AL', 'AH', 'AX', 'EAX'],
            'RBX': ['BL', 'BH', 'BX', 'EBX'],
            'RCX': ['CL', 'CH', 'CX', 'ECX'],
            'RDX': ['DL', 'DH', 'DX', 'EDX'],
            'RSI': ['SI', 'SIL', 'ESI'],
            'RDI': ['DI', 'DIL', 'EDI'],
            'RBP': ['BP', 'BPL', 'EBP'],
            'RSP': ['SP', 'SPL', 'ESP'],
            'RFLAGS': ['EFLAGS'],
            'R8': ['R8D', 'R8W', 'R8B'],
            'R9': ['R9D', 'R9W', 'R9B'],
            'R10': ['R10D', 'R10W', 'R10B'],
            'R11': ['R11D', 'R11W', 'R11B'],
            'R12': ['R12D', 'R12W', 'R12B'],
            'R13': ['R13D', 'R13W', 'R13B'],
            'R14': ['R14D', 'R14W', 'R14B'],
            'R15': ['R15D', 'R15W', 'R15B'],
            'RIP': ['IP', 'EIP'],
            #'YMM0'  : ['XMM0'],
            #'YMM1'  : ['XMM1'],
            #'YMM2'  : ['XMM2'],
            #'YMM3'  : ['XMM3'],
            #'YMM4'  : ['XMM4'],
            #'YMM5'  : ['XMM5'],
            #'YMM6'  : ['XMM6'],
            #'YMM7'  : ['XMM7'],
            #'YMM8'  : ['XMM8'],
            #'YMM9'  : ['XMM9'],
            #'YMM10' : ['XMM10'],
            #'YMM11' : ['XMM11'],
            #'YMM12' : ['XMM12'],
            #'YMM13' : ['XMM13'],
            #'YMM14' : ['XMM14'],
            #'YMM15' : ['XMM15'],
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

        self.uc_arch = (UC_ARCH_X86, UC_MODE_64)
        self.ks_arch = (KS_ARCH_X86, KS_MODE_64)
        self.cs_arch = (CS_ARCH_X86, CS_MODE_64)
        self.code_mem = 4096
        self.code_addr = 0x6D1C000000000  # 48-bit address (not 56-bit)

        self.addr_space = 64

        self.cond_reg = x86_registers.X86_REG_EFLAGS()

    def name2reg(self, name: str) -> Register:
        name = name.upper()
        name = name.replace('(', '')
        name = name.replace(')', '')
        return getattr(x86_registers, f'X86_REG_{name}')()

    def name2mem(self, name: str) -> tuple[Register, Register]:
        name = name.upper()
        name = name.replace('(', '')
        name = name.replace(')', '')
        return (getattr(x86_registers, f'X86_{name}')(), getattr(x86_registers, f'X86_{name}_ADDR64')())

    def create_full_reg(self, name: str, bits: int = 0, structure: Optional[list[int]] = None) -> Register:
        if structure is None:
            structure = []
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
