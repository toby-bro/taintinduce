# taintinduce

TaintInduce is a project which aims to automate the creation of taint
propagation rules for unknown instruction sets.

## References

One Engine To Serve 'em All: Inferring Taint Rules Without Architectural
Semantics

Zheng Leong Chua, Yanhao Wang, Teodora Băluță, Prateek Saxena, Zhenkai Liang,
Purui Su.

In the Network and Distributed System Security Symposium 2019, San Diego, CA,
US, Feb 2019.

## Disclaimer

### Initial disclaimer

We are currently in the process of rewriting the prototype to better serve our
goal of providing an online taint service for different architectures.
For people who are interested in the implementation used in the paper, feel free
to contact us.

### New disclaimer

This project has been quite a bit reorganized to be able to run properly in 2025.

Problems encountered:

- Squirrelflowdb which does not exist on the PyPi -> Rewrote the serialization and deserialisation
- Initially released for Python 3.6 -> Migrated it to 3.12 with type checking and linting
- Fixed a bug on ARM and memory which was not implemented
- Migrated to use `uv` to run the project
- peekaboo did not compile so added a patch to make it run

## Requirements

### Python3.12

- capstone
- keystone
- unicorn
- tqdm

## Usage

### If you want to run the tracer

You need to install [dynamorio](https://github.com/DynamoRIO/dynamorio)

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

### To run taintinduce on a simple instruction

```sh
uv run python -m taintinduce.taintinduce 2303 X86
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
```
