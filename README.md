# taintinduce++

> TaintInduce is a project which aims to automate the creation of taint propagation rules for unknown instruction sets.

The same applies to taintinduce++ which tries to do it more correctly and faster, whilst keeping many of the brilliant ideas introduced by taintinduce.

## References

One Engine To Serve 'em All: Inferring Taint Rules Without Architectural
Semantics

Zheng Leong Chua, Yanhao Wang, Teodora Băluță, Prateek Saxena, Zhenkai Liang,
Purui Su.

In the Network and Distributed System Security Symposium 2019, San Diego, CA,
US, Feb 2019.

## Disclaimer

### original disclaimer

> We are currently in the process of rewriting the prototype to better serve our
> goal of providing an online taint service for different architectures.
> For people who are interested in the implementation used in the paper, feel free
> to contact us.

### New disclaimer

This project has been a tiny bit reorganized to be able to run properly in 2025.

Problems encountered:

- Squirrelflowdb which does not exist on the PyPi -> Rewrote the serialization and deserialisation
- Initially released for Python 3.6 -> Migrated it to 3.12 with type checking and linting
- Fixed _bugs_ on ARM/AMD64/X86 and memory which was not implemented
- Migrated to use `uv` to run the project
- peekaboo did not compile so added a patch to make it run

## Requirements (aka uv)

For simplicity's sake this project uses [uv](https://docs.astral.sh/uv) for all the python wrangling, it looks after all the dependencies...

## Features

This taintinduce++ has the same features than the og taintinduce except that:

- the condition inference has been revamped to try and generate correct conditions on all dataflows, and do it fast.
- It fixes dead dependencies such as squirrel-framework...
- It adds a web based visualizer that can be run locally.
- It "fully"(kof kof) supports memory operations (wip)
- Fully supports X86, AMD64, ARM64 and ...
- It adds a very simple, tiny ISA called JN (just nibbles) that enabled debugging and fixing the inference with very simple operations and flags of 4 bits (aka nibbles)

## Basic usage

### To run taintinduce on a simple instruction

```sh
uv run python -m taintinduce.taintinduce 2303 X86
```

Instructions are written in hex. If you are not fluent in assembly here are two ressources

- [Felix Coutier's](https://www.felixcloutier.com/x86) x86 reference.
- a bash script adaptble to your needs: here it is used to write the crucial `bswap esi`

```sh
tt=$(mktemp) && cat > ${tt}.s << 'EOF'
.intel_syntax noprefix
.global _start
_start:
    bswap esi
EOF
as --32 ${tt}.s -o ${tt}.o && objdump -d -M intel ${tt}.o | grep bswap
rm ${tt}.s ${tt}.o ${tt}
```

### To visualize the rules and observations in CLI

```sh
uv run python read_taint_output.py output/0402_X86_rule.json
# for observations...
uv run python read_taint_output.py output/01C3_X86_obs.json --observations --limit 3
```

### GUI viewing of the rules

To view and play with the generated rules:

```sh
uv run python taint_visualizer.py output/0BC3_X86_rule.json
# then firefox localhost:5000
```

A simple flask webapp has been made to enable easier debugging or rules, it has a

- simulator: to put custom inputs and taints and see the propagation for a given instruction
- graph viewer: to see the relations between all bits
- condition viewer...
- another useless tab that I did not delete yet in case I use it again

## Using a tracer ?

I "fixed" this in the first iterations on the project (for backwards compatibility compared to the original project but did not test it since most of the big changes to the codebase have been made, all I can say is that there is a commit for which it worked...)

### If you want to run the tracer

You need to install [dynamorio](https://github.com/DynamoRIO/dynamorio)

Moreover to compile pypeekaboo in 2025 you need to apply a basic patch (all is described in the following instructions)

```sh
git submodule update --init --recursive  # clone peekaboo
./patch.sh                               # apply fix to be able to compile
cd peekaboo

DYNAMORIO_PATH=

# To compile the tracer
cd peekaboo_dr
mkdir build
cd build
DynamoRIO_DIR=($DYNAMORIO_PATH) cmake ..
make

# Then you can run the tracer with the wrapper trace.sh
# Examples:
./trace.sh --help
./trace.sh -- ls -la
./trace.sh -o trace_ls -- ls
./trace.sh -o trace_cat -- cat /etc/passwd
```

### To run it on a trace

- Adjust `-j` for the number of threads you want to use (default 1)
- the `PID` must be adjusted to the output you get from your command

```sh
uv run python -m taintinduce.train_trace trace_ls/ls-<PID>/<PID> -j 8
```

## Contributing

At the moment the checks which are enforced are

```sh
uv run ruff check .
uv run mypy .
uv run pytest
```

## JN

`JN` or "Just Nibbles" is a very simple ISA that was written to debug and test all the parts of the inference algorithm without being scared of running into obscure undocumented unicorn / capstone / keystone... or qemu bugs (on undocumented flags behaviour for instance).

It has two 4-bit registers `R1`, and `R2` and a nibble-sized flag register `NZCV` whose exact meaning is left to the reader. These were to be able to check that simple correlations between registers' bits can be established, as well as side effects that concern all the bits of the registers.

Our hope is that if that taintinduce++ manages to infer all the rules for this simple ISA correctly, then it will manage to do so for AMD64 (_kof kof_).

JN has 10 instructions organized as 5 operations with 2 addressing modes each:

### Arithmetic

| Opcode | Mnemonic       | Description            | Example             |
| ------ | -------------- | ---------------------- | ------------------- |
| 0x0    | `ADD R1, R2`   | R1 = R1 + R2 (mod 16)  | `0`                 |
| 0x1    | `ADD R1, #imm` | R1 = R1 + imm (mod 16) | `1A` (ADD R1, #0xA) |
| 0x8    | `SUB R1, R2`   | R1 = R1 - R2           | `8`                 |
| 0x9    | `SUB R1, #imm` | R1 = R1 - imm          | `95` (SUB R1, #0x5) |

### Logical Operations

| Opcode | Mnemonic       | Description    | Example             |
| ------ | -------------- | -------------- | ------------------- |
| 0x2    | `OR R1, R2`    | R1 = R1 \| R2  | `2`                 |
| 0x3    | `OR R1, #imm`  | R1 = R1 \| imm | `3F` (OR R1, #0xF)  |
| 0x4    | `AND R1, R2`   | R1 = R1 & R2   | `4`                 |
| 0x5    | `AND R1, #imm` | R1 = R1 & imm  | `58` (AND R1, #0x8) |
| 0x6    | `XOR R1, R2`   | R1 = R1 ^ R2   | `6`                 |
| 0x7    | `XOR R1, #imm` | R1 = R1 ^ imm  | `7C` (XOR R1, #0xC) |

Those can be tested very easily with taintinduce:

```sh
uv run python -m taintinduce.taintinduce 9A JN
uv run python -m taintinduce.taintinduce 4 JN
```
