import pypcode

_pypcode_contexts: dict[str, pypcode.Context] = {}


def get_context(arch: str) -> pypcode.Context:
    if arch not in _pypcode_contexts:
        # Map our architectures to pypcode architectures
        arch_map = {
            'X86': 'x86:LE:32:default',
            'AMD64': 'x86:LE:64:default',
        }

        if arch not in arch_map:
            raise ValueError(f'Unsupported architecture for lifting: {arch}')

        _pypcode_contexts[arch] = pypcode.Context(arch_map[arch])

    return _pypcode_contexts[arch]


def lift_instruction(arch: str, bytestring: bytes, address: int = 0x1000) -> pypcode.pypcode_native.Translation:
    ctx = get_context(arch)
    return ctx.translate(bytestring, address)
