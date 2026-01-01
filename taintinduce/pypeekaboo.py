import os
import struct
from ctypes import Structure, c_uint8, c_uint16, c_uint32, c_uint64, sizeof
from typing import ClassVar


def read_struct(myfile, mystruct):
    x = mystruct()
    assert myfile.readinto(x) == sizeof(mystruct)
    return x


class GPR_AMD64(Structure):
    _fields_: ClassVar = [
        ('rdi', c_uint64),
        ('rsi', c_uint64),
        ('rsp', c_uint64),
        ('rbp', c_uint64),
        ('rbx', c_uint64),
        ('rdx', c_uint64),
        ('rcx', c_uint64),
        ('rax', c_uint64),
        ('r8', c_uint64),
        ('r9', c_uint64),
        ('r10', c_uint64),
        ('r11', c_uint64),
        ('r12', c_uint64),
        ('r13', c_uint64),
        ('r14', c_uint64),
        ('r15', c_uint64),
        ('rflags', c_uint64),
        ('rip', c_uint64),
    ]


class SIMD_AMD64(Structure):
    _fields_: ClassVar = [
        ('ymm0', c_uint64 * 4),
        ('ymm1', c_uint64 * 4),
        ('ymm2', c_uint64 * 4),
        ('ymm3', c_uint64 * 4),
        ('ymm4', c_uint64 * 4),
        ('ymm5', c_uint64 * 4),
        ('ymm6', c_uint64 * 4),
        ('ymm7', c_uint64 * 4),
        ('ymm8', c_uint64 * 4),
        ('ymm9', c_uint64 * 4),
        ('ymm10', c_uint64 * 4),
        ('ymm11', c_uint64 * 4),
        ('ymm12', c_uint64 * 4),
        ('ymm13', c_uint64 * 4),
        ('ymm14', c_uint64 * 4),
        ('ymm15', c_uint64 * 4),
    ]


class FXSAVE_AREA(Structure):
    _fields_: ClassVar = [
        ('fcw', c_uint16),
        ('fsw', c_uint16),
        ('ftw', c_uint8),
        ('reserved_1', c_uint8),
        ('fop', c_uint16),
        ('fpu_ip', c_uint32),
        ('fpu_cs', c_uint16),
        ('reserved_2', c_uint16),
        ('fpu_dp', c_uint32),
        ('fpu_ds', c_uint16),
        ('reserved_3', c_uint16),
        ('mxcsr', c_uint32),
        ('mxcsr_mask', c_uint32),
        ('st_mm', c_uint64 * 2 * 8),
        ('xmm', c_uint64 * 2 * 16),
        ('padding', c_uint8 * 96),
    ]


class RegFileAMD64(Structure):
    _fields_: ClassVar = [('gpr', GPR_AMD64), ('simd', SIMD_AMD64), ('fxsave', FXSAVE_AREA)]


class GPR_X86(Structure):
    _fields_: ClassVar = [
        ('edi', c_uint32),
        ('esi', c_uint32),
        ('esp', c_uint32),
        ('ebp', c_uint32),
        ('ebx', c_uint32),
        ('edx', c_uint32),
        ('ecx', c_uint32),
        ('eax', c_uint32),
        ('eflags', c_uint32),
        ('eip', c_uint32),
    ]


class SIMD_X86(Structure):
    _fields_: ClassVar = [
        ('xmm0', c_uint64 * 2),
        ('xmm1', c_uint64 * 2),
        ('xmm2', c_uint64 * 2),
        ('xmm3', c_uint64 * 2),
        ('xmm4', c_uint64 * 2),
        ('xmm5', c_uint64 * 2),
        ('xmm6', c_uint64 * 2),
        ('xmm7', c_uint64 * 2),
    ]


class RegFileX86(Structure):
    _fields_: ClassVar = [('gpr', GPR_X86), ('simd', SIMD_X86), ('fxsave', FXSAVE_AREA)]


class GPR_ARM(Structure):
    _fields_: ClassVar = [
        ('r0', c_uint32),
        ('r1', c_uint32),
        ('r2', c_uint32),
        ('r3', c_uint32),
        ('r4', c_uint32),
        ('r5', c_uint32),
        ('r6', c_uint32),
        ('r7', c_uint32),
        ('r8', c_uint32),
        ('r9', c_uint32),
        ('r10', c_uint32),
        ('r11', c_uint32),
        ('r12', c_uint32),
        ('sp', c_uint32),
        ('lr', c_uint32),
        ('pc', c_uint32),
        ('cpsr', c_uint32),
    ]


class SIMD_ARM(Structure):
    _fields_: ClassVar = [
        ('d0', c_uint64),
        ('d1', c_uint64),
        ('d2', c_uint64),
        ('d3', c_uint64),
        ('d4', c_uint64),
        ('d5', c_uint64),
        ('d6', c_uint64),
        ('d7', c_uint64),
        ('d8', c_uint64),
        ('d9', c_uint64),
        ('d10', c_uint64),
        ('d11', c_uint64),
        ('d12', c_uint64),
        ('d13', c_uint64),
        ('d14', c_uint64),
        ('d15', c_uint64),
        ('d16', c_uint64),
        ('d17', c_uint64),
        ('d18', c_uint64),
        ('d19', c_uint64),
        ('d20', c_uint64),
        ('d21', c_uint64),
        ('d22', c_uint64),
        ('d23', c_uint64),
        ('d24', c_uint64),
        ('d25', c_uint64),
        ('d26', c_uint64),
        ('d27', c_uint64),
        ('d28', c_uint64),
        ('d29', c_uint64),
        ('d30', c_uint64),
        ('d31', c_uint64),
        ('fpscr', c_uint32),
    ]


class RegFileARM(Structure):
    _fields_: ClassVar = [('gpr', GPR_ARM), ('simd', SIMD_ARM)]


class GPR_ARM64(Structure):
    _fields_: ClassVar = [
        ('x0', c_uint64),
        ('x1', c_uint64),
        ('x2', c_uint64),
        ('x3', c_uint64),
        ('x4', c_uint64),
        ('x5', c_uint64),
        ('x6', c_uint64),
        ('x7', c_uint64),
        ('x8', c_uint64),
        ('x9', c_uint64),
        ('x10', c_uint64),
        ('x11', c_uint64),
        ('x12', c_uint64),
        ('x13', c_uint64),
        ('x14', c_uint64),
        ('x15', c_uint64),
        ('x16', c_uint64),
        ('x17', c_uint64),
        ('x18', c_uint64),
        ('x19', c_uint64),
        ('x20', c_uint64),
        ('x21', c_uint64),
        ('x22', c_uint64),
        ('x23', c_uint64),
        ('x24', c_uint64),
        ('x25', c_uint64),
        ('x26', c_uint64),
        ('x27', c_uint64),
        ('x28', c_uint64),
        ('x29', c_uint64),
        ('x30', c_uint64),
        ('sp', c_uint64),
        ('pc', c_uint64),
        ('pstate', c_uint64),
    ]


class SIMD_ARM64(Structure):
    _fields_: ClassVar = [
        ('v0', c_uint64 * 2),
        ('v1', c_uint64 * 2),
        ('v2', c_uint64 * 2),
        ('v3', c_uint64 * 2),
        ('v4', c_uint64 * 2),
        ('v5', c_uint64 * 2),
        ('v6', c_uint64 * 2),
        ('v7', c_uint64 * 2),
        ('v8', c_uint64 * 2),
        ('v9', c_uint64 * 2),
        ('v10', c_uint64 * 2),
        ('v11', c_uint64 * 2),
        ('v12', c_uint64 * 2),
        ('v13', c_uint64 * 2),
        ('v14', c_uint64 * 2),
        ('v15', c_uint64 * 2),
        ('v16', c_uint64 * 2),
        ('v17', c_uint64 * 2),
        ('v18', c_uint64 * 2),
        ('v19', c_uint64 * 2),
        ('v20', c_uint64 * 2),
        ('v21', c_uint64 * 2),
        ('v22', c_uint64 * 2),
        ('v23', c_uint64 * 2),
        ('v24', c_uint64 * 2),
        ('v25', c_uint64 * 2),
        ('v26', c_uint64 * 2),
        ('v27', c_uint64 * 2),
        ('v28', c_uint64 * 2),
        ('v29', c_uint64 * 2),
        ('v30', c_uint64 * 2),
        ('v31', c_uint64 * 2),
        ('fpsr', c_uint32),
        ('fpcr', c_uint32),
    ]


class RegFileARM64(Structure):
    _fields_: ClassVar = [('gpr', GPR_ARM64), ('simd', SIMD_ARM64)]


ARCH_INFO = {
    0: (RegFileARM64, 'AARCH32'),  # ARCH_AARCH32
    1: (RegFileARM64, 'AARCH64'),  # ARCH_AARCH64 / ARM64
    2: (RegFileX86, 'X86'),        # ARCH_X86
    3: (RegFileAMD64, 'AMD64'),    # ARCH_AMD64
}


class Metadata(Structure):
    _fields_: ClassVar = [('arch', c_uint32), ('version', c_uint32)]


"""
typedef struct insn_ref {
	uint64_t pc;
} insn_ref_t;
"""


class InsnRef(Structure):
    _fields_: ClassVar = [('pc', c_uint64)]


"""
typedef struct bytes_map {
	uint64_t pc;
	uint32_t size;
	uint8_t rawbytes[16];
} bytes_map_t ;
"""


class BytesMap(Structure):
    _fields_: ClassVar = [('pc', c_uint64), ('size', c_uint32), ('rawbytes', c_uint8 * 16)]


"""
typedef struct {
	uint32_t length;	/* how many refs are there*/
} memref_t;
"""


class MemRef(Structure):
    _fields_: ClassVar = [('length', c_uint32)]


"""
typedef struct {
	uint64_t addr;		/* memory address */
	uint64_t value;		/* memory value */
	uint32_t size;		/* how many bits are vaild in value */
	uint32_t status; 	/* 0 for Read, 1 for write */
} memfile_t;
"""


class MemFile(Structure):
    _fields_: ClassVar = [('addr', c_uint64), ('value', c_uint64), ('size', c_uint32), ('status', c_uint32)]


class TraceInsn(object):
    def __init__(self):
        self.addr = None
        self.rawbytes = None
        self.num_mem = None
        self.mem = []
        self.regfile = None


class MemInfo(object):
    def __init__(self):
        pass


class PyPeekaboo(object):
    def __init__(self, trace_path):
        # ensure that path points to a directory...
        assert os.path.isdir(trace_path)
        # ensure that the basic structure is correct
        insn_trace_path = os.path.join(trace_path, 'insn.trace')

        # insn.bytemap can be in trace_path or parent directory (DynamoRIO version >=2)
        insn_bytemap_path = os.path.join(trace_path, 'insn.bytemap')
        if not os.path.isfile(insn_bytemap_path):
            insn_bytemap_path = os.path.join(os.path.dirname(trace_path), 'insn.bytemap')

        regfile_path = os.path.join(trace_path, 'regfile')
        memfile_path = os.path.join(trace_path, 'memfile')
        memrefs_path = os.path.join(trace_path, 'memrefs')
        metafile_path = os.path.join(trace_path, 'metafile')
        assert os.path.isfile(insn_trace_path)
        assert os.path.isfile(insn_bytemap_path)
        assert os.path.isfile(regfile_path)
        assert os.path.isfile(memfile_path)
        assert os.path.isfile(memrefs_path)
        assert os.path.isfile(metafile_path)

        # open up the files
        self.insn_trace = open(insn_trace_path, 'rb')
        self.insn_bytemap = open(insn_bytemap_path, 'rb')
        self.regfile = open(regfile_path, 'rb')
        self.memfile = open(memfile_path, 'rb')
        self.memrefs = open(memrefs_path, 'rb')
        self.metafile = open(metafile_path, 'rb')

        # parse metafile
        metadata = read_struct(self.metafile, Metadata)
        self.regfile_struct, self.arch_str = ARCH_INFO[metadata.arch]

        self.memrefs_offsets = self.load_memrefs_offsets(trace_path)
        self.num_insn = os.path.getsize(insn_trace_path) / sizeof(InsnRef)

        # parse the bytemaps
        self.bytesmap = {}
        bytesmap_entry = BytesMap()
        while self.insn_bytemap.readinto(bytesmap_entry) == sizeof(bytesmap_entry):
            self.bytesmap[bytesmap_entry.pc] = list(bytesmap_entry.rawbytes)[: bytesmap_entry.size]

    def load_memrefs_offsets(self, trace_path):
        memrefs_offsets_path = os.path.join(trace_path, 'memrefs_offsets')
        if not os.path.isfile(memrefs_offsets_path):
            # memfile offsets for each insn does not exist, create them
            # generate the memfile offsets
            print('{} does not contain the cached offsets to memfile, generating...'.format(trace_path))
            with open(memrefs_offsets_path, 'wb') as offset_file:
                cur_offset = 0
                memref_entry = MemRef()
                while self.memrefs.readinto(memref_entry) == sizeof(memref_entry):
                    if memref_entry.length:
                        offset_file.write(struct.pack('<Q', cur_offset))
                        cur_offset += sizeof(MemFile) * memref_entry.length
                    else:
                        # 63rd bit tell us if its valid or not, 0 is valid, 1 is not
                        offset_file.write(struct.pack('<Q', 2**63))
        return open(memrefs_offsets_path, 'rb')

    def get_insn(self, insn_id):

        # get the offset of the instruction into the different files.
        insn_trace_foffset = insn_id * sizeof(InsnRef)
        memrefs_foffset = insn_id * sizeof(MemRef)
        regfile_foffset = insn_id * sizeof(self.regfile_struct)
        memfile_index_foffset = insn_id * 8

        my_insn = TraceInsn()

        self.insn_trace.seek(insn_trace_foffset)
        my_insn.addr = read_struct(self.insn_trace, InsnRef).pc
        my_insn.rawbytes = self.bytesmap[my_insn.addr]

        self.memrefs.seek(memrefs_foffset)
        my_insn.num_mem = read_struct(self.memrefs, MemRef).length

        my_insn.mem = []
        if my_insn.num_mem:
            self.memrefs_offsets.seek(memfile_index_foffset)
            for _ in range(my_insn.num_mem):
                buf = self.memrefs_offsets.read(8)
                memref_offset = struct.unpack('<Q', buf)[0]
                self.memfile.seek(memref_offset)
                my_insn.mem.append(read_struct(self.memfile, MemFile))

        self.regfile.seek(regfile_foffset)
        my_insn.regfile = read_struct(self.regfile, self.regfile_struct)
        return my_insn

    def pp(self):
        insn_ref = InsnRef()
        while self.insn_trace.readinto(insn_ref) == sizeof(InsnRef):
            rawbytes = self.bytesmap[insn_ref.pc]
            print('{}\t: {}'.format(hex(insn_ref.pc), [hex(x) for x in rawbytes]))
