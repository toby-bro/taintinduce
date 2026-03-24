import re

from keystone import KS_ARCH_ARM64, KS_ARCH_X86, KS_MODE_32, KS_MODE_64, KS_MODE_LITTLE_ENDIAN, Ks
from unicorn import UC_ARCH_ARM64, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_MODE_ARM, Uc
from unicorn.arm64_const import UC_ARM64_REG_SP
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_RSP

from taintinduce.types import Architecture


def execute_asm_in_unicorn(  # noqa: C901
    asm_code: str,
    arch: Architecture,
    input_taint: dict[str, int],
    input_values: dict[str, int],
    target_vars: list[str],
) -> dict[str, int]:
    # Extract unique variables from asm_code
    var_pattern = r'[TV]_[A-Za-z0-9_]+'
    vars_found = set(re.findall(var_pattern, asm_code))
    for v in target_vars:
        vars_found.add(v)

    # Assign addresses
    base_data = 0x10000
    var_addr_map = {}
    for i, var in enumerate(sorted(vars_found)):
        var_addr_map[var] = base_data + (i * 8)

    # Replace variable names with addresses matching their strings
    patched_asm = asm_code
    for var, addr in var_addr_map.items():
        patched_asm = patched_asm.replace(var, hex(addr))

    # Compile
    if arch == Architecture.X86:
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        sp_reg = UC_X86_REG_ESP
    elif arch == Architecture.AMD64:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        sp_reg = UC_X86_REG_RSP
    elif arch == Architecture.ARM64:
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        sp_reg = UC_ARM64_REG_SP
    else:
        raise NotImplementedError(f'Unsupported arch {arch}')

    encoding, _count = ks.asm(patched_asm)
    if not encoding:
        raise RuntimeError('Failed to assemble the transpiled code')

    code_bytes = bytes(encoding)

    # Setup Unicorn
    base_code = 0x100000
    base_stack = 0x200000

    uc.mem_map(base_data, 0x10000)
    uc.mem_map(base_code, 0x10000)
    uc.mem_map(base_stack, 0x10000)

    # Write code
    uc.mem_write(base_code, code_bytes)

    # Write inputs
    for var, addr in var_addr_map.items():
        val = 0
        if var.startswith(('V_', 'T_')):
            parts = var.split('_')
            if len(parts) >= 2:
                reg_name = parts[1]
                source_dict = input_values if var.startswith('V_') else input_taint
                if reg_name in source_dict:
                    val = source_dict[reg_name]
                    if len(parts) >= 4:
                        try:
                            bit_max = int(parts[2])
                            bit_min = int(parts[3])
                            bit_len = bit_max - bit_min + 1
                            val = (val >> bit_min) & ((1 << bit_len) - 1)
                        except ValueError:
                            pass
        uc.mem_write(addr, val.to_bytes(8, byteorder='little'))

    # Setup stack pointer
    uc.reg_write(sp_reg, base_stack + 0x8000)

    # Run
    uc.emu_start(base_code, base_code + len(code_bytes))

    # Read back target variables
    results = {}
    for var in target_vars:
        addr = var_addr_map[var]
        res_bytes = uc.mem_read(addr, 8)
        results[var] = int.from_bytes(res_bytes, byteorder='little')

    return results
