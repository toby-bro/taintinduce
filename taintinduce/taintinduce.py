#!/usr/bin/env python3
import argparse
import binascii
import json
import logging
import os
import sys
from typing import Optional

import taintinduce.observation_engine.observation as observation_engine
from taintinduce.classifier.categories import InstructionCategory
from taintinduce.classifier.classifier import classify_instruction
from taintinduce.cpu.cpu import CPUFactory
from taintinduce.disassembler.insn_info import Disassembler, InsnInfo
from taintinduce.inference_engine import observation_processor
from taintinduce.inference_engine.inference import infer
from taintinduce.instrumentation.instrument import instrument_instruction
from taintinduce.isa.register import Register
from taintinduce.rules.rules import TaintRule

# Replaced squirrel imports with our own serialization
from taintinduce.serialization import TaintInduceDecoder, TaintInduceEncoder
from taintinduce.sleigh.engine import generate_static_rule
from taintinduce.state.state import Observation
from taintinduce.transpiler.transpiler import make_transpiler
from taintinduce.types import Architecture


def query_yes_no(question: str, default: Optional[str] = 'yes') -> bool:
    """Ask a yes/no question via raw_input() and return their answer.

    Args:
        question: string that is presented to the user.
        default: presumed answer if the user just hits <Enter>.
            It must be "yes" (the default), "no" or None (meaning an answer is required).
    Returns:
        Boolean answer
    """
    valid = {'yes': True, 'y': True, 'ye': True, 'no': False, 'n': False}
    if default is None:
        prompt = ' [y/n] '
    elif default == 'yes':
        prompt = ' [Y/n] '
    elif default == 'no':
        prompt = ' [y/N] '
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        if choice in valid:
            return valid[choice]
        sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")


def gen_insninfo(archstring: Architecture, bytestring: str, emu_verify: bool = True) -> InsnInfo:
    insninfo = Disassembler(archstring, bytestring).insn_info
    # JN doesn't use UnicornCPU emulation
    if emu_verify and archstring != 'JN':
        cpu = CPUFactory.create_cpu(archstring)
        bytecode = binascii.unhexlify(bytestring)
        mem_regs, jump_reg = cpu.identify_memops_jump(bytecode)
        if jump_reg and jump_reg not in insninfo.state_format:
            print('{} modifies the control flow but {} not in state_format!'.format(bytestring, jump_reg.name))
            insninfo.state_format.append(jump_reg)
        for mem_reg in mem_regs:
            if mem_reg not in insninfo.state_format:
                insninfo.state_format.append(mem_reg)
    return insninfo


def gen_obs(
    archstring: Architecture,
    bytestring: str,
    state_format: list[Register],
) -> tuple[list[Observation], observation_engine.ObservationEngine]:
    obs_engine = observation_engine.ObservationEngine(bytestring, archstring, state_format)
    return obs_engine.observe_insn(), obs_engine


def taintinduce_infer(archstring: Architecture, bytestring: str) -> tuple[InsnInfo, list[Observation], TaintRule]:
    insninfo = gen_insninfo(archstring, bytestring)
    obs_list, _obs_engine = gen_obs(archstring, bytestring, insninfo.state_format)
    rule = infer(obs_list, output_induction=False)
    taintrule = rule.convert2squirrel(archstring, bytestring)
    return insninfo, obs_list, taintrule


def _configure_logging(verbosity: int) -> None:
    """Configure logging based on verbosity level.

    Args:
        verbosity: 0=errors only, 1=warnings+errors, 2=info+warnings+errors, 3+=debug+info+warnings+errors
    """
    if verbosity == 0:
        log_level = logging.ERROR
    elif verbosity == 1:
        log_level = logging.WARNING
    elif verbosity == 2:
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG

    logging.basicConfig(
        format='%(levelname)s - %(message)s',
        level=log_level,
        force=True,
    )


def main() -> None:
    # we don't have ARM32, MIPS YET
    parser = argparse.ArgumentParser()
    parser.add_argument('bytestring', type=str, help='Instruction bytestring in ' + 'hex, e.g. use dac3 for \\xda\\xc3')
    parser.add_argument(
        'arch',
        type=str,
        choices=['X86', 'AMD64', 'ARM64', 'JN'],
        help='Select the architecture of the instruction.',
    )
    parser.add_argument('--output-dir', type=str, default='output', help='Output directory.')
    parser.add_argument('--force-gen', default=False, action='store_true', help='Force generation of observations')
    parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=0,
        help='Increase verbosity: -v for warnings, -vv for info, -vvv for debug',
    )
    parser.add_argument(
        '--no-sleigh',
        default=False,
        action='store_true',
        help='Use static SLEIGH lifting instead of dynamic emulation',
    )
    parser.add_argument(
        '--output-induction',
        default=False,
        action='store_true',
        help='Remove inputs when included in other output flows',
    )

    args = parser.parse_args()
    _configure_logging(args.verbose)

    if not args.no_sleigh:
        insn = gen_insninfo(args.arch, args.bytestring)
        sleigh_circuit = generate_static_rule(args.arch, bytes(bytearray.fromhex(args.bytestring)), insn.state_format)

        print('======== SLEIGH Generated Instrumentation ========')
        print(sleigh_circuit)

        instrument_path = os.path.join(args.output_dir, args.bytestring + '_' + args.arch + '_sleigh_instrumentation.json')
        if not os.path.exists(args.output_dir):
            os.makedirs(args.output_dir)
        with open(instrument_path, 'w') as f:
            json.dump(sleigh_circuit, f, cls=TaintInduceEncoder, indent=2)
        print(f'Writing SLEIGH instrumentation to {instrument_path}\n')

        try:
            transpiler = make_transpiler(args.arch)
            asm = transpiler.transpile(sleigh_circuit)
            print('======== SLEIGH Assembly Instrumentation ========')
            print(asm)
            print('=========================================')
        except Exception as e:
            print(f'Error transpiling SLEIGH: {e}')

        return

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    # if not isinstance(args.bytestring, (bytes, bytearray)):
    #    args.bytestring = bytearray.fromhex(args.bytestring)
    insn = gen_insninfo(args.arch, args.bytestring)
    output_obs_file = args.bytestring + '_' + args.arch + '_obs.json'
    output_rule_file = args.bytestring + '_' + args.arch + '_rule.json'
    obs_path = os.path.join(args.output_dir, output_obs_file)
    rule_path = os.path.join(args.output_dir, output_rule_file)

    obs_list: list[Observation] = []

    if not args.force_gen:
        try:
            assert args.output_dir
            with open(obs_path, 'r') as f:
                obs_list = json.load(f, cls=TaintInduceDecoder)
                if not isinstance(obs_list, list):
                    raise RuntimeError('Loaded observations is not a list!')
                assert all(isinstance(obs, Observation) for obs in obs_list)
            _obs_engine = None  # No refinement when loading from file
        except Exception as e:
            print(f'Failed to load observations from {obs_path}: {e}')
            print('Generating observations instead...')
    if len(obs_list) == 0:
        obs_list, _obs_engine = gen_obs(args.arch, insn.bytestring, insn.state_format)
        print('Writing observations to {}'.format(obs_path))
        # Verify serialization round-trip
        serialized = json.dumps(obs_list, cls=TaintInduceEncoder)
        deserialized = json.loads(serialized, cls=TaintInduceDecoder)
        if set(obs_list) != set(deserialized):
            print('Serialization round-trip failed!')
            return
        if obs_list != deserialized:
            print('Serialization round-trip failed!')
            return
        with open(obs_path, 'w') as f:
            json.dump(obs_list, f, cls=TaintInduceEncoder)

    _deps = observation_processor.extract_observation_dependencies(obs_list)
    category = classify_instruction(obs_list)
    print(f'Instruction CellIFT Category: {category.name}')

    if category is not InstructionCategory.UNKNOWN:
        circuit = instrument_instruction(obs_list, category)
        print('======== Generated Instrumentation ========')
        print(circuit)

        try:
            transpiler = make_transpiler(args.arch)
            asm = transpiler.transpile(circuit)
            print('======== Assembly Instrumentation ========')
            print(asm)
        except Exception as e:
            print(f'Error transpiling: {e}')

        print('=========================================')

        instrument_path = os.path.join(args.output_dir, args.bytestring + '_' + args.arch + '_instrumentation.json')
        with open(instrument_path, 'w') as f:
            json.dump(circuit, f, cls=TaintInduceEncoder, indent=2)
        print(f'Writing instrumentation to {instrument_path}\n')

    else:
        rule = infer(obs_list, output_induction=args.output_induction)
        taintrule = rule.convert2squirrel(args.arch, args.bytestring)
        if args.output_dir:
            with open(rule_path, 'w') as myfile:
                json.dump(taintrule, myfile, cls=TaintInduceEncoder, indent=2)

        # Verify serialization round-trip
        serialized = json.dumps(taintrule, cls=TaintInduceEncoder)
        deserialized = json.loads(serialized, cls=TaintInduceDecoder)
        if taintrule != deserialized:
            print('Serialization round-trip failed!')
            return
        print('Writing rule to {}'.format(rule_path))
        print('')


if __name__ == '__main__':
    main()
