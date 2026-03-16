import csv
from pathlib import Path

from taintinduce.classifier.classifier import classify_instruction
from taintinduce.cpu.cpu import CPUFactory
from taintinduce.taintinduce import gen_insninfo, gen_obs
from taintinduce.types import Architecture

PROGRESSION_DIR = Path(__file__).parent
INPUT_CSV_PATH = PROGRESSION_DIR / 'input.csv'
OUTPUT_CSV_PATH = PROGRESSION_DIR / 'output.csv'


def init_input_csv():
    """Generates the initial input csv with common instructions if it doesn't exist."""
    if INPUT_CSV_PATH.exists():
        return

    # Format: ISA | Encoded | Decoded | Category
    # If encoded is empty, it will be derived from Decoded using keystone
    common_arm64 = [
        'ret',
        'brk #0',
        'autibsp',
        'eor x0, x1, x2',
        'sub x0, x1, x2',
        'cset x0, eq',
        'cmn x0, x1',
        'ldur x0, [x1, #-4]',
        'add x0, x1, x2, lsl #2',
        'csel x0, x1, x2, eq',
        'orr x0, x1, x2',
        'paciza x0',
        'ldr x0, [x1, x2]',
        'strb w0, [x1]',
        'ldp d0, d1, [x1]',
        'sxtw x0, w1',
        'and x0, x1, x2',
        'tbnz x0, #3, . + 8',
        'tbz x0, #3, . + 8',
        'stp x0, x1, [x2, #16]!',
        'add x0, x1, x2',
        'ldp x0, x1, [x2], #16',
        'stp d0, d1, [x1]',
        'retab',
        'pacibsp',
        'cbnz x0, . + 8',
        'cmp x0, x1',
        'ldrb w0, [x1]',
        'adrp x0, 0',
        'ldr x0, [sp]',
        'stp x0, x1, [sp]',
        'ldp x0, x1, [sp]',
        'adr x0, 0',
        'cbz x0, . + 8',
        'b . + 4',
        'str x0, [x1]',
        'b.eq . + 4',
        'mov x0, #1',
        'nop',
        'ldr x0, [x1]',
        'bl . + 8',
        'mov x0, x1',
    ]

    common_x86 = [
        'add eax, ebx',
        'sub eax, ebx',
        'imul eax, ebx',
        'xor eax, ebx',
        'mov eax, ebx',
        'lea eax, [ebx + ecx*8 + 5]',
        'and eax, ebx',
        'or eax, ebx',
        'shl eax, 2',
        'shr eax, 2',
        'sar eax, 2',
        'ror eax, 2',
        'rol eax, 2',
        'not eax',
        'neg eax',
        'inc eax',
        'dec eax',
        'push eax',
        'pop eax',
        'cmp eax, ebx',
        'test eax, ebx',
        'nop',
        'mov [eax], ebx',
        'mov eax, [ebx]',
        'cdq',
        'cwde',
        'movzx eax, bl',
        'movsx eax, bl',
        'xchg eax, ebx',
        'cmovz eax, ebx',
        'cmovnz eax, ebx',
        'setz al',
        'bt eax, ebx',
        'bswap eax',
        'std',
        'cld',
        'ret',
    ]

    common_amd64 = [
        'add rax, rbx',
        'sub rax, rbx',
        'imul rax, rbx',
        'xor rax, rbx',
        'mov rax, rbx',
        'lea rax, [rbx + rcx*8 + 5]',
        'and rax, rbx',
        'or rax, rbx',
        'shl rax, 2',
        'shr rax, 2',
        'sar rax, 2',
        'ror rax, 2',
        'rol rax, 2',
        'not rax',
        'neg rax',
        'inc rax',
        'dec rax',
        'push rax',
        'pop rax',
        'cmp rax, rbx',
        'test rax, rbx',
        'nop',
        'mov qword ptr [rax], rbx',
        'mov rsi, [rdi]',
        'cqo',
        'movzx rax, bl',
        'movzx rax, bx',
        'movsx rax, bl',
        'movsx rax, bx',
        'movsxd rax, ebx',
        'xchg rax, rbx',
        'cmovz rax, rbx',
        'cmovnz rax, rbx',
        'setz al',
        'bswap rax',
        'std',
        'cld',
        'ret',
        'syscall',
    ]

    with open(INPUT_CSV_PATH, 'w', newline='') as f:
        writer = csv.writer(f, delimiter='|')
        # We leave Encoded blank to force live encoding
        for i in common_arm64:
            writer.writerow(['ARM64', '', i, ''])
        for i in common_x86:
            writer.writerow(['X86', '', i, ''])
        for i in common_amd64:
            writer.writerow(['AMD64', '', i, ''])


def assemble_instruction(arch: Architecture, decoded: str) -> str:
    try:
        cpu = CPUFactory.create_cpu(arch)
        encoding, _count = cpu.ks.asm(decoded)
        if encoding:
            return bytes(encoding).hex()
    except Exception as e:
        print(f'Keystone assembly failed for {decoded} on {arch}: {e}')
    return ''


def test_categorize_progression():  # noqa: C901
    init_input_csv()

    rows = []
    with open(INPUT_CSV_PATH, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter='|')
        for row in reader:
            if len(row) < 3:
                continue
            rows.append(row)

    new_rows = []

    # Try reading output if exists, so we don't duplicate processing
    existing_output = {}
    if OUTPUT_CSV_PATH.exists():
        with open(OUTPUT_CSV_PATH, newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='|')
            for row in reader:
                if len(row) >= 4:
                    existing_output[f'{row[0]}_{row[2]}'] = row

    # rewrite output csv with existing output
    with open(OUTPUT_CSV_PATH, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter='|')
        for _k, v in existing_output.items():
            writer.writerow(v)

    for row in rows:
        while len(row) < 4:
            row.append('')

        isa_str, encoded_str, decoded_str, _category = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
        arch = (
            Architecture.ARM64
            if isa_str.upper() == 'ARM64'
            else (Architecture.AMD64 if isa_str.upper() == 'AMD64' else Architecture.X86)
        )

        lookup_key = f'{isa_str}_{decoded_str}'
        if lookup_key in existing_output:
            # We already have progress for this, reuse it
            ex_row = existing_output[lookup_key]
            if ex_row[3] and ex_row[3] not in ('Error', 'Unknown'):
                new_rows.append(ex_row)
                continue

        print(f'Testing {isa_str} -> {decoded_str}')

        if not encoded_str:
            encoded_str = assemble_instruction(arch, decoded_str)
            row[1] = encoded_str  # update list

        if not encoded_str:
            print(f'Failed to encode {decoded_str}')
            row[3] = 'Error'
            new_rows.append(row)
            continue

        try:
            insninfo = gen_insninfo(arch, encoded_str)
            obs_list, _ = gen_obs(arch, encoded_str, insninfo.state_format)

            if not obs_list:
                print(f'Failed to get observations for {decoded_str}')
                row[3] = 'Error'
            else:
                row[3] = str(classify_instruction(obs_list))
                print(f' -> {row[3]}')
        except Exception as e:
            print(f'Exception on {decoded_str}: {e}')
            row[3] = 'Error'

        new_rows.append(row)

        with open(OUTPUT_CSV_PATH, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter='|')
            writer.writerow(row)

        # Update input incrementally so we don't lose the keystone generated hex
        with open(INPUT_CSV_PATH, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter='|')
            # include the already generated new_rows + the rest of the file that hasn't been processed yet
            for nr in new_rows:
                writer.writerow([nr[0], nr[1], nr[2], ''])
            # append the rest
            for i in range(len(new_rows), len(rows)):
                unprocessed = rows[i]
                writer.writerow([unprocessed[0], unprocessed[1], unprocessed[2], ''])

    assert True
