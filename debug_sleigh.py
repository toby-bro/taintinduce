import argparse

from taintinduce.isa.amd64 import AMD64
from taintinduce.isa.arm64 import ARM64
from taintinduce.isa.register import Register
from taintinduce.isa.x86 import X86
from taintinduce.sleigh.engine import generate_static_rule
from taintinduce.sleigh.lifter import get_context


def get_state_format(arch: str) -> list[Register]:
    arch = arch.upper()
    if arch == 'X86':
        return X86().cpu_regs
    if arch == 'AMD64':
        return AMD64().cpu_regs
    if arch == 'ARM64':
        return ARM64().cpu_regs
    raise ValueError(f'Unsupported architecture: {arch}')


def main() -> None:
    parser = argparse.ArgumentParser(description='Debug Sleigh formulas for given instructions.')
    parser.add_argument(
        'arch',
        choices=['x86', 'X86', 'amd64', 'AMD64', 'arm64', 'ARM64'],
        help='Architecture (X86, AMD64, ARM64)',
    )
    parser.add_argument('hex_bytes', help="Hex string of the instruction (e.g., '0fafc3')")

    args = parser.parse_args()
    arch = args.arch.upper()

    try:
        bytestring = bytes.fromhex(args.hex_bytes)
    except ValueError as e:
        print(f'Invalid hex string: {e}')
        return

    ctx = get_context(arch)
    translation = ctx.translate(bytestring, 0x1000)

    print(f'--- Raw SLEIGH P-Code for {arch} {args.hex_bytes} ---')
    for op in translation.ops:
        print(f'  {op}')
    print('\n')

    regs = get_state_format(arch)

    rule = generate_static_rule(arch, bytestring, regs)

    print(f'--- Generated Formulas for {arch} {args.hex_bytes} ---')
    if not rule.assignments:
        print('No assignments generated.')

    for assignment in rule.assignments:
        t = assignment.target
        print(f'\nTarget: {t.name}[{t.bit_start}:{t.bit_end}]')
        print(f'Expression: {assignment.expression}')


if __name__ == '__main__':
    main()
