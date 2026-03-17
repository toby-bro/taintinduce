bits := "64"

# Convert an assembly instruction to hex (defaults to 64-bit)
# Usage: just encode add rbx, rcx

# Usage: bits=32 just encode add eax, ebx
encode +args:
    @tt=$(mktemp); \
    echo ".intel_syntax noprefix" > $$tt.s; \
    echo ".global _start" >> $$tt.s; \
    echo "_start:" >> $$tt.s; \
    echo "  {{ args }}" >> $$tt.s; \
    if as --{{ bits }} $$tt.s -o $$tt.o 2>/dev/null; then \
        objdump -d -M intel $$tt.o | grep -E '^[[:space:]]+[0-9a-f]+:' | head -n 1 | cut -f2 -d: | cut -f1-7 -d' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; \
    else \
        echo "Error: Invalid instruction or operand count for '{{ args }}' in {{ bits }}-bit mode"; \
    fi; \
    rm -f $$tt $$tt.s $$tt.o

induce instruction arch="X86":
    uv run python -m taintinduce.taintinduce {{ instruction }} {{ arch }}

visualize instruction="21d8" arch="X86":
    uv run python taint_visualizer.py output/{{ instruction }}_{{ arch }}_instrumentation.json
