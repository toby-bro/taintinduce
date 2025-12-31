#!/usr/bin/env python3

import argparse
import binascii
import json
import os
import sys
from typing import Optional

import taintinduce.disassembler.insn_info as insn_info
import taintinduce.inference_engine.inference as inference_engine
import taintinduce.observation_engine.observation as observation_engine
from taintinduce.isa.arm64_registers import ARM64_REG_NZCV
from taintinduce.isa.register import Register
from taintinduce.isa.x86_registers import X86_REG_EFLAGS
from taintinduce.rules import InsnInfo, Rule, TaintRule

# Replaced squirrel imports with our own serialization
from taintinduce.serialization import TaintInduceDecoder, TaintInduceEncoder
from taintinduce.state import Observation
from taintinduce.unicorn_cpu.unicorn_cpu import UnicornCPU


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


def gen_insninfo(archstring: str, bytestring: str, emu_verify: bool = True) -> InsnInfo:
    insninfo = insn_info.Disassembler(archstring, bytestring).insn_info
    if emu_verify:
        cpu = UnicornCPU(archstring)
        bytecode = binascii.unhexlify(bytestring)
        mem_regs, jump_reg = cpu.identify_memops_jump(bytecode)
        if jump_reg and jump_reg not in insninfo.state_format:
            print('{} modifies the control flow but {} not in state_format!'.format(bytestring, jump_reg.name))
            insninfo.state_format.append(jump_reg)
        for mem_reg in mem_regs:
            if mem_reg not in insninfo.state_format:
                insninfo.state_format.append(mem_reg)
    return insninfo


def gen_obs(archstring: str, bytestring: str, state_format: list[Register]) -> list[Observation]:
    obs_engine = observation_engine.ObservationEngine(bytestring, archstring, state_format)
    return obs_engine.observe_insn()


def infer(observations: list[Observation], cond_reg: Optional[X86_REG_EFLAGS | ARM64_REG_NZCV]) -> Rule:
    infer_engine = inference_engine.InferenceEngine()
    return infer_engine.infer(observations, cond_reg)


def taintinduce_infer(archstring: str, bytestring: str) -> tuple[InsnInfo, list[Observation], TaintRule]:
    insninfo = gen_insninfo(archstring, bytestring)
    obs_list = gen_obs(archstring, bytestring, insninfo.state_format)
    rule = infer(obs_list, insninfo.cond_reg)
    taintrule = rule.convert2squirrel(archstring)
    return insninfo, obs_list, taintrule


def main() -> None:
    # we don't have ARM32, MIPS YET
    parser = argparse.ArgumentParser()
    parser.add_argument('bytestring', type=str, help='Instruction bytestring in ' + 'hex, e.g. use dac3 for \\xda\\xc3')
    parser.add_argument(
        'arch',
        type=str,
        choices=['X86', 'AMD64', 'ARM64'],
        help='Select the architecture of the instruction.',
    )
    parser.add_argument('--output-dir', type=str, default='output', help='Output directory.')
    parser.add_argument('--skip-gen', default=False, action='store_true', help='Skip generation of observation')

    args = parser.parse_args()

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    # if not isinstance(args.bytestring, (bytes, bytearray)):
    #    args.bytestring = bytearray.fromhex(args.bytestring)
    insn = gen_insninfo(args.arch, args.bytestring)
    output_obs_file = args.bytestring + '_' + args.arch + '_obs.json'
    output_rule_file = args.bytestring + '_' + args.arch + '_rule.json'
    obs_path = os.path.join(args.output_dir, output_obs_file)
    rule_path = os.path.join(args.output_dir, output_rule_file)
    if insn.bytestring is None:
        print('Failed to disassemble instruction: {}'.format(args.bytestring))
        return

    if args.skip_gen:
        assert args.output_dir
        with open(obs_path, 'r') as f:
            obs_list = json.load(f, cls=TaintInduceDecoder)
            if not isinstance(obs_list, list):
                raise Exception('Loaded observations is not a list!')
            assert all(isinstance(obs, Observation) for obs in obs_list)
    else:
        obs_list = gen_obs(args.arch, insn.bytestring, insn.state_format)
        print('Writing observations to {}'.format(obs_path))
        with open(obs_path, 'w') as f:
            json.dump(obs_list, f, cls=TaintInduceEncoder)

    rule = infer(obs_list, insn.cond_reg)
    taintrule = rule.convert2squirrel(args.arch)
    if args.output_dir:
        with open(rule_path, 'w') as myfile:
            json.dump(taintrule, myfile, cls=TaintInduceEncoder, indent=2)

    # Verify serialization round-trip
    # serialized = json.dumps(taintrule, cls=TaintInduceEncoder)
    # deserialized = json.loads(serialized, cls=TaintInduceDecoder)
    # if taintrule != deserialized:
    #     print('Serialization round-trip failed!')
    #     return
    print('Writing rule to {}'.format(rule_path))
    print('')


if __name__ == '__main__':
    main()
