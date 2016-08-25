__author__ = 'holycall'

from capstone import *
from capstone.x86_const import *
import capstone.x86_const

import string
import traceback

import pickle

import numbers
import tempfile
import subprocess
import re

import pyvex
import archinfo

# ida helper class that resembles idaapi.BasicBlock
class my_ida_basic_block:
    def __init__(self, addr):
        self.startEA = addr
        self.endEA = -1
        self._preds = set()
        self._succs = set()
        self.addrs = list()

    def preds(self):
        return self._preds

    def succs(self):
        return self._succs

    def __str__(self):
        val = 'BasicBlock:[%08x,%08x] ' % (self.startEA, self.endEA)
        val += 'preds={'
        for bb in self._preds:
            val += '%08x,' % bb.startEA
        if val[-1] == ',':
            val = val[:-1]
        val += '}, succs={'
        for bb in self._succs:
            val += '%08x,' % bb.startEA
        if val[-1] == ',':
            val = val[:-1]
        val += '}'
        return val


class my_ida_fn:
    def __init__(self):
        pass


# time string to save logs
def get_time_str():
    import time
    import datetime
    ts =time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d%H%M')[2:]
    return st


# is hex string utility
def is_hex_str(s):
    """
    Is s is hex string.
    This string ends with 'h' or this string starts with '0x'
    :param s: string
    :return: hex string 'h' or '0x' striped if string is hex string. '' if this string is not hex string.
    """
    if s.endswith('h'):
        s = s[:-1]
    elif s.startswith('0x'):
        s = s[2:]
    if all(c in string.hexdigits for c in s):
        return s
    else:
        return ''

# gnu as wrapper
def as_code(asm, quiet=False, check_invalid_reg=False, cache=False):
    asm = ".intel_syntax noprefix\n" + asm + "\n"
    fname = tempfile.mktemp('.s')
    open(fname, 'w').write(asm)
    cmd = 'as -32 {file} -o {file}.o 2>&1 && objdump -d {file}.o && rm -f {file} {file}.o'.format(file=fname)
    out = subprocess.check_output(cmd, shell=True)
    out = out.decode('ascii').split('\n')
    is_success = False
    for i, line in enumerate(out):
        if "Disassembly of section .text:" in line:
            is_success = True
            out = out[i + 3:]
            break
    if not is_success:
        return None

    code = b''
    for line in out:
        if line.strip() == '':
            continue
        m = re.match(r'\s*[a-f0-9]+:\s+(([a-f0-9][a-f0-9]\s+)+)', line)
        if m is None:
            raise Exception("Can't parse objdump output: \"%s\"" % line)
        for b in re.split(r'\s+', m.groups()[0]):
            if b == '':
                continue
            code += bytearray.fromhex(b)
    return code


# FnCache utility
class FnCache:
    def __init__(self, addr):

        self.startAddr = addr
        self.bbMap = {}

        import idaapi
        fc = idaapi.FlowChart(addr, flags=idaapi.FC_PREDS)
        for bb in fc:
            self.bbMap[bb.startEA] = bb

    def get_bb(self, ea):
        if ea in self.bbMap:
            return self.bbMap[ea]
        return []

    def get_bb_map(self):
        return self.bbMap

    def get_bb_list(self):
        return self.bbMap.values()


# capstone wrapper

x86_const_names = dir(capstone.x86_const)

# flag registers do not  exist in Capstone so I appended after the end of capstone constants
# EFLAGS constants from OpenREIL
X86_REG_ZF = X86_REG_ENDING + 1
X86_REG_PF = X86_REG_ENDING + 2
X86_REG_CF = X86_REG_ENDING + 3
X86_REG_AF = X86_REG_ENDING + 4
X86_REG_SF = X86_REG_ENDING + 5
X86_REG_OF = X86_REG_ENDING + 6
X86_REG_DFLAG = X86_REG_ENDING + 7

# EFLAGS constants from pyvex
X86_REG_CC_OP = X86_REG_ENDING + 8
X86_REG_CC_DEP1 = X86_REG_ENDING + 9
X86_REG_CC_DEP2 = X86_REG_ENDING + 10

X86_REG_CC_NDEP = X86_REG_ENDING + 11

x86_ins_names = filter(lambda x: x.startswith('X86_INS'), x86_const_names)

# for openREIL
x86_const_names.extend(['X86_REG_ZF',
                        'X86_REG_PF',
                        'X86_REG_CF',
                        'X86_REG_AF',
                        'X86_REG_SF',
                        'X86_REG_OF',
                        'X86_REG_DFLAG'])

# for pyvex
x86_const_names.extend(['X86_REG_CC_OP',
                        'X86_REG_CC_DEP1',
                        'X86_REG_CC_DEP2',
                        'X86_REG_CC_NDEP'])

x86_reg_names = filter(lambda x: x.startswith('X86_REG'), x86_const_names)

current_module = __import__(__name__)

x86reg_num2reilstr = {getattr(current_module, reg): 'R' + reg[7:] for reg in x86_reg_names}  # n -> R_EAX, ...
x86reg_num2str = {getattr(current_module, reg): reg[8:].lower() for reg in x86_reg_names}  # 1 -> AH, ...
x86reg_str2num = {v: k for k, v in x86reg_num2str.iteritems()}
x86reg_reilstr2num = {v: k for k, v in x86reg_num2reilstr.iteritems()}

x86regs = [x86reg_num2str.keys()]
x86reg_flags = [x86reg_str2num[x] for x in ['zf', 'pf', 'cf', 'af', 'sf', 'of', \
                                            'cc_op', 'cc_dep1', 'cc_dep2', 'cc_ndep', \
                                            'dflag', 'eflags']]
memref_num2str = {1: 'byte ptr', 2: 'word ptr', 4: 'dword ptr', 8: 'qword ptr'}
memref_str2num = {v: k for k, v in memref_num2str.iteritems()}

memseg_num2str = {
    X86_PREFIX_CS: 'cs',
    X86_PREFIX_DS: 'ds',
    X86_PREFIX_ES: 'es',
    X86_PREFIX_FS: 'fs',
    X86_PREFIX_GS: 'gs',
    X86_PREFIX_SS: 'ss',
}
memseg_str2num = {v: k for k, v in memseg_num2str.iteritems()}


reg_family = {
    X86_REG_EAX: {1: X86_REG_AL,  2: X86_REG_AX, 4: X86_REG_EAX, 8: X86_REG_RAX},
    X86_REG_EBX: {1: X86_REG_BL,  2: X86_REG_BX, 4: X86_REG_EBX, 8: X86_REG_RBX},
    X86_REG_ECX: {1: X86_REG_CL,  2: X86_REG_CX, 4: X86_REG_ECX, 8: X86_REG_RCX},
    X86_REG_EDX: {1: X86_REG_DL,  2: X86_REG_DX, 4: X86_REG_EDX, 8: X86_REG_RDX},
    X86_REG_EBP: {1: X86_REG_BPL, 2: X86_REG_BP, 4: X86_REG_EBP, 8: X86_REG_RBP},
    X86_REG_ESI: {1: X86_REG_SIL, 2: X86_REG_SI, 4: X86_REG_ESI, 8: X86_REG_RSI},
    X86_REG_EDI: {1: X86_REG_DIL, 2: X86_REG_DI, 4: X86_REG_EDI, 8: X86_REG_RDI},
    X86_REG_ESP: {1: X86_REG_SPL, 2: X86_REG_SP, 4: X86_REG_ESP, 8: X86_REG_RSP},
    X86_REG_EIP: {2: X86_REG_IP, 4: X86_REG_EIP, 8: X86_REG_RIP}
}


# register containment utility
def get_representative_register(reg):
    if reg in [X86_REG_RAX, X86_REG_EAX, X86_REG_AX, X86_REG_AH, X86_REG_AL]:
        return X86_REG_EAX
    elif reg in [X86_REG_RBX, X86_REG_EBX, X86_REG_BX, X86_REG_BH, X86_REG_BL]:
        return X86_REG_EBX
    elif reg in [X86_REG_RCX, X86_REG_ECX, X86_REG_CX, X86_REG_CH, X86_REG_CL]:
        return X86_REG_ECX
    elif reg in [X86_REG_RDX, X86_REG_EDX, X86_REG_DX, X86_REG_DH, X86_REG_DL]:
        return X86_REG_EDX
    elif reg in [X86_REG_RBP, X86_REG_EBP, X86_REG_BP, X86_REG_BPL]:
        return X86_REG_EBP
    elif reg in [X86_REG_RSI, X86_REG_ESI, X86_REG_SI, X86_REG_SIL]:
        return X86_REG_ESI
    elif reg in [X86_REG_RDI, X86_REG_EDI, X86_REG_DI, X86_REG_DIL]:
        return X86_REG_EDI
    elif reg in [X86_REG_RSP, X86_REG_ESP, X86_REG_SP, X86_REG_SPL]:
        return X86_REG_ESP
    elif reg in [X86_REG_RIP, X86_REG_EIP, X86_REG_IP]:
        return X86_REG_EIP
    return X86_REG_INVALID


def set_reg_size(reg, size):
    """
    Set the value into size in bytes.
    :param reg: reg constant
    :param size: size in bytes
    :return: size set register
    """
    rep_reg = get_representative_register(reg)
    if rep_reg == X86_REG_INVALID:
        return X86_REG_INVALID

    m1 = reg_family[rep_reg]
    if size in m1:
        return m1[size]
    return X86_REG_INVALID


get_reg_size_helper = {
    X86_REG_AL :1, X86_REG_AX:2, X86_REG_EAX:4, X86_REG_RAX:8,
    X86_REG_BL :1, X86_REG_BX:2, X86_REG_EBX:4, X86_REG_RBX:8,
    X86_REG_CL :1, X86_REG_CX:2, X86_REG_ECX:4, X86_REG_RCX:8,
    X86_REG_DL :1, X86_REG_DX:2, X86_REG_EDX:4, X86_REG_RDX:8,
    X86_REG_BPL:1, X86_REG_BP:2, X86_REG_EBP:4, X86_REG_RBP:8,
    X86_REG_SIL:1, X86_REG_SI:2, X86_REG_ESI:4, X86_REG_RSI:8,
    X86_REG_DIL:1, X86_REG_DI:2, X86_REG_EDI:4, X86_REG_RDI:8,
    X86_REG_SPL:1, X86_REG_SP:2, X86_REG_ESP:4, X86_REG_RSP:8,
                   X86_REG_IP:2, X86_REG_EIP:4, X86_REG_RIP:8
}


def get_reg_size(reg):
    """
    Get register size in bytes.
    :param reg: reg constant
    :return: size of the register
    """
    return get_reg_size_helper.get(reg, X86_REG_INVALID)


def set_value_size(val, size):
    """
    Set the value into size in bytes.
    :param val: constant value
    :param size: size in bytes
    :return: size set value
    """
    if size == 1:
        return val & 0xFF
    elif size == 2:
        return val & 0xFFFF
    elif size == 4:
        return val & 0xFFFFFFFF
    elif size == 8:
        return val & 0xFFFFFFFFFFFFFFFF


def get_cs_insn_list_from_ida_by_count(ea, cnt):
    """
    Get capstone CsInsn type instruction list.
    :param ea: start address
    :param cnt: number of instructions
    :return: capstone disassembled object list
    """
    import idc
    i_list = get_ida_insn_addr_list_by_count(ea, cnt)
    CODE = ''
    for addr in i_list:
        size = idc.ItemSize(addr)
        CODE += idc.GetManyBytes(addr, size)

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    return list(md.disasm(CODE, ea))


def get_cs_insn_list_from_ida_by_range(start, end):
    """
    Get capstone CsInsn type instruction list.
    :param start: start addres
    :param end: end address
    :return: capstone disassembled object list
    """

    import idc
    CODE = ''

    addr = start
    while addr < end:
        size = idc.ItemSize(addr)
        CODE += idc.GetManyBytes(addr, size)
        addr += size

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    return list(md.disasm(CODE, start))


def get_ida_insn_addr_list_by_count(ea, cnt):
    """
    Get an instruction address from IDA Pro.
    :param ea: start address
    :param cnt: number of instructions
    :return: instruction address list
    """
    import idc
    import idaapi
    i_list = []
    cnt1 = 0
    while cnt1 < cnt:
        mnem = idc.GetMnem(ea)
        if mnem == '':
            break
        if mnem != 'jmp' and mnem.startswith('j'):
            break
        nextea = skip_nop_jmp(ea)
        if nextea != idaapi.BADADDR:
            ea = nextea
        i_list.append(ea)
        cnt1 += 1
        ea += idc.ItemSize(ea)
    return i_list


def get_ida_insn_addr_list_by_range(start_addr, end_addr):
    """
    Get an instruction address from IDA Pro.
    :param start_addr: start address
    :param end_addr: end address
    :return: instruction address list
    """
    import idc
    import idaapi
    i_list = []
    current_addr = start_addr
    while current_addr <= end_addr:
        mnem = idc.GetMnem(current_addr)
        if mnem == '':
            break
        if mnem != 'jmp' and mnem.startswith('j'):
            break
        next_addr = skip_nop_jmp(current_addr)
        if next_addr != idaapi.BADADDR:
            current_addr = next_addr
        i_list.append(current_addr)
        current_addr += idc.ItemSize(current_addr)
    return i_list


def skip_nop(ea):
    import idc
    while idc.GetMnem(ea) == 'nop':
        ea = idc.NextAddr(ea)
    return ea


def skip_nop_jmp(ea):
    import idautils
    import idaapi
    original_ea = ea
    while True:
        import idc
        mnem = idc.GetMnem(ea)
        if mnem == 'nop':
            ea += idc.ItemSize(ea)
            continue
        if mnem == 'jmp':
            # skip connected basic blocks
            crefs = list(idautils.CodeRefsFrom(ea, 1))
            # print 'crefs from ', hex(ea), ' ', map(hex, crefs)
            if not crefs:
                break
            nextea = crefs[0]
            crefs = list(idautils.CodeRefsTo(nextea, 1))
            # print 'crefs to ', hex(ea), ' ', map(hex, crefs)
            if len(crefs) > 1: break
            ea = nextea
            continue
        break
    if ea == original_ea: return idaapi.BADADDR
    return ea


class N2Oper(object):
    """
    x86 operand class
    """

    def __init__(self):
        self._type = X86_OP_INVALID
        self._size = 0
        self._reg = X86_REG_INVALID
        self._imm = 0
        self._segment = 0
        self._base = X86_REG_INVALID
        self._index = X86_REG_INVALID
        self._scale = 0
        self._disp = 0

    def __eq__(self, other):
        if self._type != other.type:
            return False
        if self._type == X86_OP_REG:
            return self._reg == other.reg
        elif self._type == X86_OP_IMM:
            return self._imm == other.imm
        elif self._type == X86_OP_MEM:
            if self._segment != other.segment:
                return False
            if self._base != other.base:
                return False
            if self._index != other.index:
                return False
            elif self._index != 0 and self._scale != other.scale:
                return False

            if self._disp != other.disp:
                return False
            return True

        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def make_by_capstone_operand(cls, csop):
        """
        Make an X86Operand object by a capstone object.
        @type csop: capstone.X86Op
        """
        x86op = cls()
        x86op._type = csop.type
        x86op._size = csop.size
        x86op._reg = csop.reg
        x86op._imm = csop.imm
        if x86op._type == X86_OP_MEM:
            x86op._segment = csop.mem.segment
            x86op._base = csop.mem.base
            x86op._index = csop.mem.index
            x86op._scale = csop.mem.scale
            x86op._disp = csop.mem.disp
        return x86op

    @classmethod
    def make_by_string(cls, op_str):
        """
        Make an X86Operand object by parsing the string
        :type op_str: string
        :param op_str: operand string
        :return: X86Operand instance
        """

        new_op = None
        op_str = op_str.lower().strip()
        if op_str in x86reg_str2num:  # register
            new_op = cls()
            new_op._type = X86_OP_REG
            new_op._reg = x86reg_str2num[op_str]
            new_op._size = get_reg_size(new_op._reg)

        elif is_hex_str(op_str):  # immediate value
            op_str = is_hex_str(op_str)
            new_op = cls()
            new_op._type = X86_OP_IMM
            new_op._imm = int(op_str, 16)
            if len(op_str) > 8:
                new_op._size = 8
            else:
                new_op._size = 4

        elif '[' in op_str and ']' in op_str:  # memory reference
            new_op = cls()
            new_op._type = X86_OP_MEM

            # memory reference size: dword ptr ...
            memrefkv = filter(lambda (s, v): op_str.startswith(s), memref_str2num.iteritems())
            if memrefkv:
                new_op._size = memrefkv[0][1]
                op_str = op_str[len(memrefkv[0][0]):].strip()
            else:
                new_op._size = 4  # default size = 4

            # memory segment: ds: ...
            if op_str.find(':') != -1:
                memsegkv = filter(lambda (s, v): op_str.startswith(s), memseg_str2num.iteritems())
                if memsegkv:
                    new_op._segment = memsegkv[0][1]
                    op_str = op_str[op_str.find(':') + 1:]

            # memory reference
            # string is split by '+'
            op_str = op_str[op_str.find('[') + 1:op_str.find(']')]
            oplst = op_str.split('+')
            # strip each string
            oplst = map(lambda x: x.strip(), oplst)

            found_base = False
            found_index = False
            # found_scale = False
            found_disp = False

            # process for each element
            for op_str in oplst:
                # check index register
                if 'si' in op_str or 'di' in op_str:
                    if found_index:
                        return None
                    found_index = True
                    op_str = op_str.split('*')
                    op_str = map(lambda x: x.strip(), op_str)
                    if len(op_str) == 1:
                        # omit scale
                        op_str = op_str[0]
                        new_op._scale = 1
                        if op_str in x86reg_str2num:
                            new_op._index = x86reg_str2num[op_str]
                    elif len(op_str) == 2:
                        # index * scale or scale * index
                        if op_str[0] in ['1', '2', '4', '8']:  # scale * index
                            op_str.reverse()
                        elif op_str[1] not in ['1', '2', '4', '8']:
                            return None  # not legal scale
                        # index reg * scale
                        if op_str[0] in x86reg_str2num:
                            new_op._index = x86reg_str2num[op_str[0]]
                        else:
                            return None  # illegal index register
                        new_op._scale = int(op_str[1])

                # check base register
                elif op_str in x86reg_str2num:
                    if found_base:
                        return None
                    found_base = True
                    new_op._base = x86reg_str2num[op_str]

                # check displacement
                elif is_hex_str(op_str):
                    if found_disp:
                        return None
                    found_disp = True
                    new_op._disp = int(is_hex_str(op_str), 16)

            # check whether memory reference is correct
            if not (found_base or found_disp):  # we need base register or displacement
                return None

        return new_op

    @property
    def type(self):
        return self._type

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, val):
        # assert (val in x86reg_num2str)
        if self.type == X86_OP_IMM:
            set_value_size(self._imm, val)
            self._size = val
        elif self.type == X86_OP_REG:
            self._reg = set_reg_size(self._reg, val)
            self._size = val
        else:
            self._size = val

    @property
    def reg(self):
        return self._reg

    @property
    def imm(self):
        return self._imm

    @imm.setter
    def imm(self, val):
        self._imm = val

    @property
    def segment(self):
        return self._segment

    @property
    def base(self):
        return self._base

    @base.setter
    def base(self, val):
        assert (val in x86reg_num2str)
        self._base = val

    @property
    def index(self):
        return self._index

    @index.setter
    def index(self, val):
        self._index = val

    @property
    def scale(self):
        return self._scale

    @scale.setter
    def scale(self, val):
        self._scale = val

    @property
    def disp(self):
        return self._disp

    @disp.setter
    def disp(self, val):
        if val < 0: # assume 32bit
            self._disp = val + 2**32
        else:
            self._disp = val
        self._disp &= 0xFFFFFFFF

    def log(self):
        print
        print 'type: %d' % self._type
        print 'size: %d' % self._size
        print 'reg: %d' % self._reg
        print 'imm: %x' % self._imm
        if self._type == X86_OP_MEM:
            print 'segment: %d' % self._segment
            print 'base: %d' % self._base
            print 'index: %d' % self._index
            print 'scale: %d' % self._scale
            print 'disp: %x' % self._disp

    @property
    def str(self):
        return str(self)

    def copy(self):
        obj = N2Oper()
        obj._type = self._type
        obj._size = self._size
        obj._reg = self._reg
        obj._imm = self._imm
        obj._segment = self._segment
        obj._base = self._base
        obj._index = self._index
        obj._scale = self._scale
        obj._disp = self._disp
        return obj

    def __str__(self):
        if self._type == X86_OP_REG:
            return x86reg_num2str[self._reg]
        elif self._type == X86_OP_IMM:
            # return '%xh' % self._imm
            if self._imm > 0:
                return '0x%x' % self._imm
            else:
                return '-0x%x' % (-self._imm)

        elif self._type == X86_OP_MEM:
            res = memref_num2str[self._size]
            if self._segment != 0:
                res += ' %s:' % memseg_num2str[self._segment]
            res += ' ['
            flag = False
            if self._base != 0:
                res += x86reg_num2str[self._base]
                flag = True
            if self._index != 0:
                if flag:
                    res += '+'
                res += '%s' % x86reg_num2str[self._index]
                flag = True
                if self._scale > 1:
                    res += '*%d' % self._scale
            if self._disp != 0:
                if flag:
                    if self._disp > 0:
                        res += '+'
                    else:
                        res += '-'
                # res += '%xh' % self._disp
                res += '0x%x' % abs(self._disp)

            return res + ']'
        return ''

    def get_regs(self):
        """
        Get all registers in this operand.

        :rtype: list[long]
        :return: All registers in this operand.
        """

        if self.type == X86_OP_IMM:
            return []
        elif self.type == X86_OP_REG:
            return [self.reg]
        elif self.type == X86_OP_MEM:
            rv = []
            if self._segment:
                rv.append(self._segment)
            if self._base:
                rv.append(self._base)
            if self._index:
                rv.append(self._index)
            return rv


class N2Inst(object):
    def __init__(self):
        """
        Make an empty N2Inst object.
        """
        self._id = 0
        self._groups = []
        self._address = 0
        self._size = 0
        self._bytes = []
        self._mnemonic = ''
        self._op_str = ''
        self._prefix = ''
        self._opcode = ''
        self._operands = []  # type: list[N2Oper]
        self._num_oper = 0
        self._ir = None # type: list[pyvex.stmt]
        self._reg_use = set()
        self._reg_def = set()

        # for optimization
        self.protect = False

    def assign(self, obj):
        """
        Assign this object with another object.
        :type obj: N2Inst
        :param obj: N2Inst Object
        :return:
        """
        self._id = obj.id
        self._groups = obj.groups
        self._address = obj.address
        self._size = obj.size
        self._bytes = obj.bytes
        self._mnemonic = obj.mnemonic
        self._op_str = obj.op_str
        self._prefix = obj.prefix
        self._opcode = obj.opcode
        self._operands = obj.op
        self._num_oper = obj.num_op
        self._ir = obj.ir.clone()
        self._reg_use = obj.reg_use
        self._reg_def = obj.reg_def

    def copy(self):
        """
        Return a clone.
        :type obj: N2Inst
        :param obj: N2Inst Object
        :return:
        """
        import copy
        return copy.deepcopy(self)

    def _compute_reg_use_def(self):
        """
        Compute use/def of an instruction
        :return:
        """
        reg_def = set()
        reg_use = set()
        for stmt in self._ir:
            if isinstance(stmt, pyvex.stmt.WrTmp):
                expr = stmt.data
                if isinstance(expr, pyvex.expr.Get):
                    reg = expr.arch.translate_register_name(expr.offset)

                    # so far we skip ldt, gdt
                    if reg in x86reg_str2num:
                        reg_use.add(x86reg_str2num[reg])

        for stmt in self._ir:
            if isinstance(stmt, pyvex.stmt.Put):
                reg = stmt.arch.translate_register_name(stmt.offset)
                reg_def.add(x86reg_str2num[reg])

                                # def _compute_use_def_openreil(self):
    #     reg_def = set()
    #     reg_use = set()
    #
    #     # not supporting instruction by openREIL
    #     # - rdtsc
    #     # - xchg
    #     # - shr/shl
    #     # implemented manually
    #
    #     if self.mnemonic == 'rdtsc':
    #         reg_def.add(x86reg_str2num['eax'])
    #         reg_def.add(x86reg_str2num['edx'])
    #
    #     # elif self.mnemonic in ['shr', 'shl']:
    #     #     op1 = self._operands[0]
    #     #     """:type : inst_util.X86Operand """
    #     #     op2 = self._operands[1]
    #     #     """:type : inst_util.X86Operand """
    #     #
    #     #     if op1.type == X86_OP_MEM:
    #     #         if op1.base != X86_REG_INVALID:
    #     #             reg_use.add(op1.base)
    #     #         if op1.index != X86_REG_INVALID:
    #     #             reg_use.add(op1.index)
    #     #     elif op1.type == X86_OP_REG:
    #     #         reg_use.add(x86reg_str2num[op1.str])
    #     #         reg_def.add(x86reg_str2num[op1.str])
    #     #         reg_def.add(x86reg_str2num['cf'])
    #     #         reg_def.add(x86reg_str2num['of'])
    #     #
    #     #     if op2.type == X86_OP_REG:
    #     #         reg_def.add(x86reg_str2num[op2.str])
    #
    #     elif 'xchg' in self.mnemonic:
    #         # xchg / cmpxchg
    #         op1 = self._operands[0]
    #         """:type : inst_util.X86Operand """
    #         op2 = self._operands[1]
    #         """:type : inst_util.X86Operand """
    #
    #         if op1.type == X86_OP_MEM:
    #             if op1.base != X86_REG_INVALID:
    #                 reg_use.add(op1.base)
    #             if op1.index != X86_REG_INVALID:
    #                 reg_use.add(op1.index)
    #
    #         if op2.type == X86_OP_MEM:
    #             if op2.base != X86_REG_INVALID:
    #                 reg_use.add(op2.base)
    #             if op2.index != X86_REG_INVALID:
    #                 reg_use.add(op2.index)
    #
    #         if op1.type == X86_OP_REG:
    #             reg_use.add(op1.reg)
    #             reg_def.add(op1.reg)
    #
    #         if op2.type == X86_OP_REG:
    #             reg_use.add(op2.reg)
    #             reg_def.add(op2.reg)
    #
    #     elif 'popf' in self.mnemonic:
    #         reg_use.add(X86_REG_ESP)
    #         reg_def.add(X86_REG_EFLAGS)
    #
    #     elif 'pushf' in self.mnemonic:
    #         reg_def.add(X86_REG_ESP)
    #         reg_use.add(X86_REG_EFLAGS)
    #
    #     else:
    #         # not supporting instruction by openREIL
    #         if not self._ir:
    #             self.translate_to_ir()
    #             return
    #
    #         # print self.str
    #         try:
    #             for reil_ins in self._ir:
    #                 src = reil_ins.src()
    #                 if src:
    #                     src = str(src[0])
    #                     if src.startswith('R_'):
    #                         src = src[2:src.find(':')].lower()
    #                         if src in x86reg_str2num:
    #                             if not (reil_ins.op_name() == 'AND'
    #                                     and reil_ins.b.type == pyopenreil.IR.A_CONST
    #                                     and ('%0x' % reil_ins.b.get_val())[:2] == 'ff'
    #                                     and ('%0x' % reil_ins.b.get_val())[-2:] == '00'):
    #                                 reg_use.add(x86reg_str2num[src])
    #                             #else:
    #                             #   print self, reil_ins
    #                         else:
    #                             # print self.str
    #                             # print self.reil_repr
    #                             # print 'What is %s?' % src
    #                             # refer to guest_x86_defs.h of vex implementation
    #                             # unimplemented:
    #                             # - shr
    #                             pass
    #
    #                 dst = reil_ins.dst()
    #                 if dst:
    #                     dst = str(dst[0])
    #                     if dst.startswith('R_'):
    #                         dst = dst[2:dst.find(':')].lower()
    #                         if dst in x86reg_str2num:
    #                             reg_def.add(x86reg_str2num[dst])
    #                         else:
    #                             # print self.str
    #                             # print self.reil_repr
    #                             # print 'What is %s?' % dst
    #                             # print 'def:',
    #                             # for d in reg_def:
    #                             #     print x86reg_num2str[d],',',
    #                             # print
    #                             pass
    #         except:
    #             # unimplemented:
    #             # - rdtsc
    #             print traceback.format_exc()
    #
    #     self._reg_def = reg_def
    #     self._reg_use = reg_use
    #     # print 'use:',
    #     # for s in reg_use:
    #     #     print x86reg_num2str[s],',',
    #     # print
    #     # print 'def:',
    #     # for d in reg_def:
    #     #     print x86reg_num2str[d],',',
    #     # print

    @classmethod
    def make_from_capstone_ins(cls, csins):
        """
        Make N2Inst object by capstone instruction object.
        The object also has semantics of the instruction by open REIL.

        :type csins: CsInsn
        :param cls: N2Inst class
        :param csins: CsInsn object
        :return: N2Inst instance.
        """
        obj = cls()
        obj._id = csins.id
        obj._groups = csins.groups
        obj._address = csins.address
        obj._size = csins.size
        obj._bytes = csins.bytes
        obj._mnemonic = csins.mnemonic
        obj._op_str = csins.op_str
        obj._prefix = csins.prefix
        obj._opcode = csins.opcode
        obj._operands = [N2Oper.make_by_capstone_operand(op) for op in csins.operands]
        obj._num_oper = len(obj._operands)

        # open REIL representation
        # try:
        #     # if csins.bytes[0] == 0x87:
        #     #     raise Exception
        #     storage = pyopenreil.REIL.CodeStorageMem(pyopenreil.REIL.ARCH_X86)
        #     reader = pyopenreil.REIL.ReaderRaw(pyopenreil.REIL.ARCH_X86,
        #                                        ''.join(map(chr, csins.bytes)),
        #                                        addr=csins.address)
        #     tr = pyopenreil.REIL.CodeStorageTranslator(reader, storage)
        #     obj._ir = tr.get_insn(csins.address)
        # except:
        #     print 'cannot translate to reil: %x %s %s' % (csins.address, csins.mnemonic, csins.op_str)
        #     for b in csins.bytes:
        #         print '\\x%x' % b,
        #     print
        #     # print traceback.format_exc()
        #     obj._ir = []

        # print '%08X' % csins.address,
        # for byt in csins.bytes:
        #     print '%02X' % byt,
        # print

        obj._ir = filter(lambda x: not isinstance(x, pyvex.stmt.NoOp),
                         pyvex.IRSB(str(csins.bytes), csins.address, archinfo.ArchX86()).statements)

        obj._compute_reg_use_def()

        return obj

    @classmethod
    def make_from_assembly_string(cls, ea, asmstr):
        """
        Make N2Inst object by assembly string.
        @type asmstr: string
        @type ea: long

        :param cls: N2Inst class
        :param ea: Address
        :param asmstr: Assembly string.
        :return: ObjN2Inst instance.
        """

        addrfix = False

        if asmstr.startswith('movsd'):
            asmstr = 'movsd'
        if asmstr[0] == 'j':
            pos = asmstr.find(' ')
            targetaddr = asmstr[pos + 1:]
            if is_hex_str(targetaddr):
                addrfix = True
                targetaddr = int(targetaddr, 16)
                targetaddr -= ea
                if targetaddr >= 0:
                    asmstr = asmstr[:pos + 1] + '0x%x' % targetaddr
                else:
                    asmstr = asmstr[:pos + 1] + '-0x%x' % (-targetaddr)

        try:
            # print asmstr
            # code = pycca.asm.util.as_code(asmstr, quiet=True)
            code = as_code(asmstr)
            if addrfix:
                pos = asmstr.find(' ')
                targetaddr = int(asmstr[pos + 1:], 16)
                targetaddr += 4 - len(code)
                if targetaddr >= 0:
                    asmstr = asmstr[:pos + 1] + '0x%x' % targetaddr
                else:
                    asmstr = asmstr[:pos + 1] + '-0x%x' % (-targetaddr)
                # code = pycca.asm.util.as_code(asmstr, quiet=True)
            code = as_code(asmstr)

            code = ''.join(map(chr, code))
            # TODO: change OpenREIL to pyVex which only installed on x64.
            # TODO: Migrate to x64

        except Exception as e:
            print e, '@%08X %s' % (ea, asmstr)
            return None

        # using IDA assembler --> fail
        # ok, code = idautils.Assemble(ea, str(asmstr))
        # if not ok:
        #     return None

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        csins = md.disasm(code, ea).next()
        return cls.make_from_capstone_ins(csins)

    @classmethod
    def make_from_binary_string(cls, ea, binstr):
        """
        Make N2Inst object by assembled binary string.
        @type binstr: string
        @type ea: long

        :param cls: N2Inst class
        :param ea: Address
        :param binstr: Instruction bytes
        :return: N2Inst instance.
        """

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        csins = md.disasm(binstr, ea).next()
        return cls.make_from_capstone_ins(csins)

    def __str__(self):
        """
        Return a string representation of this instruction without address.
        """
        binstr = ''.join(['%02X' % val for val in self.bytes])
        if self._op_str == '':
            return '%s # %s' % (self._mnemonic, binstr)
        else:
            return '%s %s # %s' % (self._mnemonic, self._op_str, binstr)

    @property
    def str(self):
        """
        Return a string representation of this instruction.
        """
        return str(self)

    @property
    def str_without_bytes(self):
        """
        Return a string representation of this instruction.
        """
        if self._op_str == '':
            return self._mnemonic
        else:
            return '%s %s' % (self._mnemonic, self._op_str)

    @property
    def str_with_address(self):
        """
        Return a string representation of this instruction with address.
        """
        if self._op_str == '':
            return '%08X %s # %s' % (self._address, self._mnemonic, ''.join(['%02X' % val for val in self.bytes]))
        else:
            return '%08X %s %s # %s' % (
            self._address, self._mnemonic, self._op_str, ''.join(['%02X' % val for val in self.bytes]))

    @property
    def str_w_address_wo_bytes(self):
        """
        Return a string representation of this instruction with address.
        """
        if self._op_str == '':
            return '%08X %s' % (self._address, self._mnemonic)
        else:
            return '%08X %s %s' % (self._address, self._mnemonic, self._op_str)

    @property
    def strdetail(self):
        """
        Return a string representation of this instruction with address.
        """
        res = self.str
        if self._ir:
            res += '\n'
            for ir_inst in self._ir:
                res += ir_inst.to_str(show_asm=True) + '\n'
        return res

    @property
    def id(self):
        return self._id

    @property
    def groups(self):
        return self._groups

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, val):
        self._address = val

    @property
    def size(self):
        return self._size

    @property
    def bytes(self):
        return self._bytes

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def op_str(self):
        return self._op_str

    @property
    def prefix(self):
        return self._prefix

    @property
    def opcode(self):
        return self._opcode

    @property
    def op(self):
        return self._operands

    @property
    def num_op(self):
        return self._num_oper

    @property
    def ir(self):
        return self._ir

    @property
    def reg_use(self):
        return self._reg_use

    @property
    def reg_def(self):
        return self._reg_def

    @property
    def reg_use_str(self):
        res = str([x86reg_num2str[s] for s in self._reg_use]).replace("'", "")
        return res

    @property
    def reg_def_str(self):
        res = str([x86reg_num2str[s] for s in self._reg_def]).replace("'", "")
        return res

    def to_symbolic(self):
        if not self._ir:
            self.translate_to_ir()
        if self._ir:
            return self._ir.to_symbolic()

    def translate_to_ir(self):
        """
        Transate this instruction into IR
        :return: None
        """
        try:
            storage = pyopenreil.REIL.CodeStorageMem(pyopenreil.REIL.ARCH_X86)
            reader = pyopenreil.REIL.ReaderRaw(pyopenreil.REIL.ARCH_X86,
                                               ''.join(map(chr, self._bytes)),
                                               addr=self._address)
            tr = pyopenreil.REIL.CodeStorageTranslator(reader, storage)
            self._ir = tr.get_insn(self.address)
        except:
            print 'cannot translate to reil: %x %s %s' % (self._address, self._mnemonic, self._op_str)
            for b in self._bytes:
                print '\\x%x' % b,
            print
            self._ir = []

    @classmethod
    def modify_stack_pointer(cls, obj, diff):
        """
        Modify stack pointer by diff. diff is added to the displacement of the instruction operand.
        :param obj:
        :param diff:
        :return: True, obj if modified. False, None if the instruction doesn't have stack base memory operand.
        """
        if not isinstance(obj, N2Inst):
            return False, None
        is_modified = False
        for i in xrange(obj._num_oper):
            if obj._operands[i].type == X86_OP_MEM:
                if obj._operands[i].base == X86_REG_ESP:
                    is_modified = True
                    obj._operands[i].disp += diff
        if not is_modified:
            return False, None
        asm_line = obj.mnemonic + ' '
        asm_line += reduce(lambda x, y: str(x) + ', ' + str(y), obj.op)

        return True, N2Inst.make_from_assembly_string(obj.address, asm_line)


def print_ins_list(ins_list, start=0, count=-1, defuse=False, semantics=False):
    """
    print instruction list
    :type ins_list: list[N2Inst] | N2InstList
    :param ins_list:
    :param start: start index
    :param count: number of elements to print
    """

    if count == -1:
        end = len(ins_list)
    else:
        end = min(start + count, len(ins_list))
    for i in xrange(start, end):
        if semantics:
            print ins_list[i].strdetail,
        else:
            print ins_list[i].str_with_address,
        if defuse:
            print '\t# use:' + ins_list[i].reg_use_str + ' def:' + ins_list[i].reg_def_str,
        print


class N2InstList(object):
    """
    X86 Instruction List.
    It is a basic unit to optimize.
    It spans over basic blocks connected by absolute jumps.
    """

    @classmethod
    def make_from_ida_by_addr_cnt(cls, ea, cnt):
        """
        Make InstructionList instance by start address and number of instructions.
        :param ea: start address.
        :param cnt: number of instructions.
        :return: InstructionList instance.
        """
        obj = cls()
        obj.set_with_list([N2Inst.make_from_capstone_ins(ins)
                           for ins in get_cs_insn_list_from_ida_by_count(ea, cnt)])
        return obj

    @classmethod
    def make_from_ida_by_range(cls, start, end):
        """
        Make InstructionList instance by start address and number of instructions.
        :rtype : N2InstList
        :param start: start address.
        :param end: end address
        :return: InstructionList instance.
        """
        obj = cls()
        obj.set_with_list([N2Inst.make_from_capstone_ins(ins)
                           for ins in get_cs_insn_list_from_ida_by_range(start, end)])
        return obj

    @classmethod
    def make_from_bytes(cls, start, bytes):
        """
        Make InstructionList instance by start address and number of instructions.
        :rtype : N2InstList
        :param start: start address.
        :param bytes: bytes string
        :return: InstructionList instance.
        """
        obj = cls()
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        obj.set_with_list([N2Inst.make_from_capstone_ins(ins)
                           for ins in md.disasm(bytes, start)])
        return obj

    def __init__(self):
        self._ins_list = []
        """:type : list[inst_util.N2Inst]"""

        self._ins_dict = dict()
        """:type : dict[long, N2Inst]"""

    def __str__(self):
        return '\n'.join(self.str_list)

    def __delitem__(self, idx):
        if isinstance(idx, slice):
            start, stop, step = idx.indices(len(self))
            for i in range(start, stop, step):
                del self._ins_dict[self._ins_list[i].address]
            del self._ins_list[idx]

        elif isinstance(idx, numbers.Number):
            ea = self._ins_list[idx].address
            del self._ins_list[idx]
            del self._ins_dict[ea]
        else:
            raise TypeError("Index must be int or slice")

    def __getitem__(self, idx):
        return self._ins_list[idx]

    def __setitem__(self, idx, val):
        if isinstance(idx, slice):
            start, stop, step = idx.indices(len(self))
            for i in range(start, stop, step):
                del self._ins_dict[self._ins_list[i].address]
            for ins in val:
                self._ins_dict[ins.address] = ins
            self._ins_list[idx] = val

        elif isinstance(idx, numbers.Number):
            ea = self._ins_list[idx].address
            if ea in self._ins_dict:
                del self._ins_dict[ea]
            self._ins_list[idx] = val
            self._ins_dict[val.address] = val

        else:
            raise TypeError("Index must be int or slice")

    def __len__(self):
        return len(self._ins_list)

    def get_ins(self, addr):
        """
        Get an instruction at address ea
        :param ea:
        :return: N2Inst object
        :rtype: N2Inst
        """
        if addr in self._ins_dict:
            return self._ins_dict[addr]
        else:
            return None

    @property
    def len(self):
        return len(self._ins_list)

    @property
    def ins_list(self):
        """
        Return instruction list.
        :rtype list[N2Inst]
        """
        return self._ins_list

    @property
    def str_list(self):
        """
        Construct a list of instruction string representation.

        :return a list of instruction in string format.
        """
        return [str(ins) for ins in self._ins_list]

    @property
    def str(self):
        """
        Return a string representation of this instruction list with addresses.

        :return a string representation of this instruction list with addresses.
        """
        return '\n'.join(ins.str_with_address for ins in self._ins_list) + '\n'

    def remove_ins(self, ea):
        """
        Remove an instruction at ea
        :param ea: instruction address
        :return: True if removed.
        """
        for idx, ins in enumerate(self._ins_list):
            if ea == ins.address:
                del self._ins_list[idx]
                del self._ins_dict[ins.address]
                return True
        return False

    def remove_tail(self):
        """
        Remove from tail.
        :return: pop result
        """
        ins = self._ins_list.pop()
        del self._ins_dict[ins.address]
        return ins

    def patch_ida_nop(self):
        """
        Patch instructions with NOP in IDA Pro
        :return:
        """
        for ins in self._ins_list:
            ins.patch_ida_nop()

    def set_with_list(self, lst):
        """
        Initialize with list[N2Inst]
        :type lst: list[N2Inst]
        :param lst: N2Inst object list
        :return:
        """
        self._ins_list = lst
        self._ins_dict = dict()
        for ins in lst:
            self._ins_dict[ins.address] = ins

    def extend(self, other):
        """
        Extend this instruction list with another instruction list.
        :type other: N2InstList | list[N2Inst]
        """
        for ins in other:
            if ins.address in self._ins_dict:
                break
            self._ins_dict[ins.address] = ins
            self.append(ins)

    def append(self, ins):
        """
        Append this instruction list with an instruction
        :type ins: N2Inst
        :param ins: instruction.
        """
        self._ins_list.append(ins)
        self._ins_dict[ins.address] = ins


class N2BB(object):
    """
    A basic block constructed from IDA Pro basic block.
    """

    def __init__(self):
        self._start_addr = 0
        self._end_addr = 0
        self._ins_list = N2InstList()
        self._in_edge = []
        """:type list[long]"""
        self._out_edge = []
        """:type list[long]"""
        self._IN = set()
        self._OUT = set()

    @property
    def start_addr(self):
        return self._start_addr

    @property
    def end_addr(self):
        return self._end_addr

    @property
    def in_edge(self):
        return self._in_edge

    @in_edge.setter
    def in_edge(self, val):
        self._in_edge = val

    @property
    def out_edge(self):
        return self._out_edge

    @out_edge.setter
    def out_edge(self, val):
        self._out_edge = val

    @property
    def IN(self):
        return self._IN

    @IN.setter
    def IN(self, val):
        self._IN = val

    @property
    def OUT(self):
        return self._OUT

    @OUT.setter
    def OUT(self, val):
        self._OUT = val

    @property
    def ins_list(self):
        """
        :rtype inst_util.InstructionList
        """
        return self._ins_list

    @property
    def len(self):
        return self._ins_list.len

    def __str__(self):
        """
        Basic block information with instruction list
        :return:
        """
        info = self.str_brief
        ins_list = self.ins_list.str
        return info + '\n' + ins_list

    @property
    def str(self):
        return self.__str__()

    @property
    def str_brief(self):
        in_edges = filter(lambda c: c not in "'L", str(map(lambda x: '%08x' % x, self._in_edge)))
        out_edges = filter(lambda c: c not in "'L", str(map(lambda x: '%08x' % x, self._out_edge)))
        info = 'Basic Block:[%08x, %08x], in_edge:%s, out_edge:%s' % \
               (self._start_addr, self._end_addr, in_edges, out_edges)
        return info

    @classmethod
    def make_from_ida_basic_block(cls, bb):
        """
        Initialize BasicBlock object with IDA Pro idaapi.BasicBlock object

        :rtype : N2BB
        :type bb: idaapi.BasicBlock
        :param bb: BasicBlock object of IDA Pro
        :return: N2BB instance
        """

        obj = cls()
        obj._start_addr = bb.startEA
        obj._end_addr = bb.endEA
        obj._ins_list = N2InstList.make_from_ida_by_range(obj._start_addr, obj._end_addr)
        obj._in_edge = [pred.startEA for pred in bb.preds()]
        obj._out_edge = [succ.startEA for succ in bb.succs()]
        return obj

    @classmethod
    def make_from_bytes(cls, start_addr, bytes, preds, succs):
        """
        Initialize BasicBlock object with bytes and

        :rtype : N2BB
        :type start_addr: long
        :type bytes: str
        :type preds: list[string]
        :type succs: list[string]
        :param start_addr: start address
        :param size: number of bytes
        :param bytes: bytes as string
        :param preds: predecessors
        :param succs: successors
        :return: N2BB instance
        """

        obj = cls()
        obj._start_addr = start_addr
        obj._end_addr = start_addr + len(bytes)
        obj._ins_list = N2InstList.make_from_bytes(start_addr, bytes)
        obj._in_edge = preds
        obj._out_edge = succs
        return obj

    @classmethod
    def make_from_str(cls, lines):
        """
        Make N2BB instance by assembly string.
        Format is as follows.

        Basic Block:[00405902, 0040596b], in_edge:[00405882], out_edge:[40596b]
        00405902 add ebx, 0
        00405908 xor ebx, 0xe1
        0040590E mov ecx, 0
        ....
        00405969 mov dword ptr [ecx], esi

        :rtype : N2BB
        :type lines: [string]
        :param lines: File name.
        :return: N2Fn instance.
        """

        bb = cls()

        temp_inst_list = []

        for line in lines:
            if line.startswith('Basic Block:'):
                # print line
                line = line[12:]
                bb_range = line[1:line.find(']')]
                addrs = map(lambda x: int(x.strip(), 16), bb_range.split(','))
                bb._start_addr = addrs[0]
                bb._end_addr = addrs[1]

                line = line[line.find('in_edge:'):]
                in_edges = line[9:line.find(']')]
                if in_edges:
                    in_addrs = map(lambda x: int(x.strip(), 16), in_edges.split(','))
                    bb._in_edge = in_addrs

                line = line[line.find('out_edge:'):]
                out_edges = line[10:line.find(']')]
                if out_edges:
                    out_addrs = map(lambda x: int(x.strip(), 16), out_edges.split(','))
                    bb._out_edge = out_addrs

            elif len(line) > 8 and is_hex_str(line[0:8]):
                addr = int(line[0:8], 16)
                code = line[9:].strip()
                temp_inst_list.append((addr, code))
        ins_list = cls.compile_basic_block(temp_inst_list)
        bb._ins_list.set_with_list(ins_list)
        return bb

    @classmethod
    def compile_basic_block(cls, asm_list):
        """
        Make N2Inst object by assembly string.
        @type asm_list: list[(long, string)]

        :param cls: N2Inst class
        :param asm_list: List of (address, asm_str) tuple
        :return: List of N2Inst objects
        """

        ins_list = []
        addrfix = False
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True

        bin_str = ''
        for idx, (addr, asm_str) in enumerate(asm_list):
            # print '%08X %s' % (addr, asm_str)

            pos = asm_str.find('#')
            if pos != -1:
                for i in xrange(pos + 2, len(asm_str), 2):
                    bin_str += chr(int(asm_str[i:i + 2], 16))

            if asm_str.startswith('movsd'):
                asm_list[idx] = (addr, 'movsd')
            elif asm_str.startswith('pushal'):
                asm_list[idx] = (addr, 'pusha')
            elif asm_str.startswith('popal'):
                asm_list[idx] = (addr, 'popa')
                # elif asm_str.startswith('call'):
                #     pos = asm_str.find(' ')
                #     target_addr = int(asm_str[pos + 1:], 16)
                #     if is_hex_str(target_addr):
                #         reladdr = target_addr - addr

        last_addr, last_asm_str = asm_list[-1]
        if last_asm_str[0] == 'j':
            pos = last_asm_str.find(' ')
            target_addr = last_asm_str[pos + 1:]
            if is_hex_str(target_addr):
                addrfix = True
                asm_list.pop()

        if bin_str:
            addr = asm_list[0][0]
            for cs_ins in md.disasm(bin_str, addr):
                if cs_ins.mnemonic == 'nop':
                    continue
                ins_list.append(N2Inst.make_from_capstone_ins(cs_ins))
            return ins_list

        asm_str = ''
        for addr, line in asm_list:
            asm_str += line + '\n'

        if asm_str:
            try:
                # print '%08X %s' % (addr, asm_str)
                code = as_code(asm_str)
            except Exception as e:
                print e
                for addr, asm_str in asm_list:
                    print '%08X %s' % (addr, asm_str)
                return None

            code = ''.join(map(chr, code))
            addr = asm_list[0][0]

            for cs_ins in md.disasm(code, addr):
                if cs_ins.mnemonic == 'nop':
                    continue
                ins_list.append(N2Inst.make_from_capstone_ins(cs_ins))

        if addrfix:
            pos = last_asm_str.find(' ')
            target_addr = last_asm_str[pos + 1:]
            target_addr = int(target_addr, 16)
            reladdr = target_addr - last_addr
            if reladdr >= 0:
                last_asm_str = last_asm_str[:pos + 1] + '0x%x' % reladdr
            else:
                last_asm_str = last_asm_str[:pos + 1] + '-0x%x' % (-reladdr)

            try:
                # print '%08X %s' % (last_addr, last_asm_str)
                last_code = as_code(last_asm_str)
            except Exception as e:
                print e
                print '%08X %s' % (last_addr, asm_str)
                return None

            reladdr -= len(last_code)
            # print last_asm_str, 'len=', len(last_code)
            # for x in last_code:
            #     print '%02X' % x,
            # print
            if reladdr >= 0:
                last_asm_str = last_asm_str[:pos + 1] + '0x%x' % reladdr
            else:
                last_asm_str = last_asm_str[:pos + 1] + '-0x%x' % (-reladdr)

            try:
                # print '%08X %s' % (last_addr, last_asm_str)
                last_code = as_code(last_asm_str)
            except Exception as e:
                print e
                print '%08X %s' % (last_addr, last_asm_str)
                return None

            last_code = ''.join(map(chr, last_code))
            cs_ins = md.disasm(last_code, last_addr).next()
            ins_list.append(N2Inst.make_from_capstone_ins(cs_ins))

        return ins_list

    def get_ins(self, ea):
        """
        Get an instruction at address ea
        :param ea:
        :return: N2Inst object
        :rtype: N2Inst
        """
        return self._ins_list.get_ins(ea)

    def remove_inst(self, ea):
        """
        Remove an instruction at address ea
        :param ea: instruction address
        :return True if removed.
        """
        return self._ins_list.remove_ins(ea)

    def remove_tail(self):
        """
        Remove an N2Inst object from the list.
        :rtype : N2Inst
        :return the removed instruction.
        """
        if len(self._ins_list) > 0:
            return self._ins_list.remove_tail()
        return None

    def extend(self, other):
        """
        Extend this basic block with instructions of the other basic block.
        The basic block itself need to be removed after.
        :type other: N2BB
        :param other: other basic block instance
        """
        self._ins_list.extend(other._ins_list)

    def _compute_use_def(self):
        """
        Compute use/def of this basic block
        :return:
        """
        self.reg_use = set()
        self.reg_def = set()
        use_tmp = set()
        def_tmp = set()
        for ins in self.ins_list:
            # def(B) : the set of variables defined in B prior to any use of that variable in B
            # use(B) : the set of variables whose values may be used in B prior to any definition of the variable
            for ru in ins.reg_use:
                if ru not in def_tmp:
                    self.reg_use.add(ru)
            for rd in ins.reg_def:
                if rd not in use_tmp:
                    self.reg_def.add(rd)
            use_tmp.update(ins.reg_use)
            def_tmp.update(ins.reg_def)

    def _compute_gen(self):
        """
        Compute use/def of this basic block
        gen[B] : definitions generated: Gen[B] = union(def(s)) where s in B
        # consider registers without flags. ignore side effects
        :return:
        """
        self.reg_gen = set()    # register gen set
        self.reg2defs = dict()  # register to definition location

        for ins in self.ins_list:
            loc = (self.start_addr, ins.address)
            # definition is a tuple (basic block address, instruction address)

            for reg in ins.reg_def:
                if reg in x86reg_flags:
                    continue
                if reg in self.reg2defs:
                    # remove the previous definition from reg2defs
                    prev_loc = self.reg2defs[reg]
                    prev_ins = self.get_ins(prev_loc[1])
                    if not prev_ins:
                        print 'no prev ins in ', ins
                        print 'prev_loc : (%08X, %08X)' % (prev_loc[0], prev_loc[1])
                    removed_reg_defs = prev_ins.reg_def - {reg}
                    removed_reg_defs -= set(x86reg_flags)
                    if prev_loc in self.reg_gen and len(removed_reg_defs) == 0:
                        self.reg_gen.remove(prev_loc)
                self.reg_gen.add(loc)
                self.reg2defs[reg] = loc

    def _compute_kill(self, all_defs):
        """
        Compute use/def of this basic block
        kill[B] : set of all other defs to x in the rest of program e
        This is a conservative definition which will not affect the result of reaching definitions.
        consider registers without flags. ignore side effects
        :param all_defs: dictionary from register to definition locations
        :type all_defs: dict
        :return:
        """
        # self.reg_kill = all_defs - self.reg_gen

        # collect all definitions related to register definition of this block other than this basic block
        self.reg_kill = set()
        for gen_loc in self.reg_gen:
            ins_addr = gen_loc[1]
            # definition is a tuple (basic block address, instruction address)
            gen_ins = self.get_ins(ins_addr)
            if gen_ins:
                for reg in gen_ins.reg_def:
                    self.reg_kill |= all_defs[reg]
                    self.reg_kill.remove(gen_loc)
            else:
                print 'no gen_ins %08X, %08X' % (gen_loc[0], gen_loc[1])
                print self
                print


class N2Fn(object):
    """
    A function class with a start address and basic blocks.
    """

    def __init__(self):
        """
        Initialize a block N2Fn Object.
        :return:
        """
        self._start_addr = 0
        """:type : long"""

        self._basic_block_dict = {}
        """:type : dict[long, N2BB]"""

        # for reaching definition
        self.all_reg_defs = {}  # register -> (basic block address, instruction address)
        """:type : dict[long, (long, long)]"""

    def generate_cfg(self, file_path):
        """
        Get function graph using graphviz.
        :param file_path file path
        :return:
        """

        import graphviz as gv

        # dot = gv.Digraph(format='svg')
        dot = gv.Digraph(format='pdf')

        for bb in self._basic_block_dict.values():

            label_str = "{%08X|" % bb.start_addr
            for ins in bb.ins_list:
                label_str += ins.str_w_address_wo_bytes + '\\l'
            label_str += "}"
            # print label_str
            dot.node('%08X' % bb.start_addr, label_str, shape='record')

            for edge in bb.out_edge:
                dot.edge('%08X' % bb.start_addr, '%08X' % edge)

        styles = {
            'graph': {
                'label': 'Function %08X' % self.start_addr,
                # 'rankdir': 'BT',
                'fontsize': '16',
                'fontcolor': 'white',
                'bgcolor': '#333333',

            },
            'nodes': {
                # 'fontname': 'DejaVu Sans Mono',
                'fontname': 'Consolas',
                'shape': 'hexagon',
                'fontsize': '10',
                'fontcolor': 'white',
                'color': 'white',
                'style': 'filled',
                'fillcolor': '#006699',
            },
            'edges': {
                'style': 'dashed',
                'color': 'white',
                'arrowhead': 'open',
                'fontname': 'Courier',
                'fontsize': '10',
                'fontcolor': 'white',
            }
        }

        def apply_styles(graph, styles):
            graph.graph_attr.update(
                ('graph' in styles and styles['graph']) or {}
            )
            graph.node_attr.update(
                ('nodes' in styles and styles['nodes']) or {}
            )
            graph.edge_attr.update(
                ('edges' in styles and styles['edges']) or {}
            )
            return graph

        dot = apply_styles(dot, styles)

        dot.render(file_path)

    def live_variable_analysis(self):
        """
        Live variable analysis on this function.
        :return:
        """
        for bb in self._basic_block_dict.values():
            bb._compute_use_def()
            bb.IN = set()
            bb.OUT = set()

        is_change = True
        while is_change:
            is_change = False
            for bb in self._basic_block_dict.values():
                # OUT[B] = union(IN[S] where S is successor of B)
                # IN[B] = use(B) union (OUT[B] - def(B))
                bb_out_len = len(bb.OUT)
                bb_in_len = len(bb.IN)
                for succ_addr in bb.out_edge:
                    succ = self.get_basic_block(succ_addr)
                    if succ:
                        bb.OUT |= succ.IN
                    else:
                        print 'no succ'
                        print bb
                        print

                bb.IN = bb.reg_use | (bb.OUT - bb.reg_def)

                if bb_out_len != len(bb.OUT):
                    is_change = True
                if bb_in_len != len(bb.IN):
                    is_change = True

    def reaching_definition(self):
        """
        Compute reaching definition on this function.
        :return:
        """
        for bb in self._basic_block_dict.values():
            bb.IN = set()
            bb.OUT = set()

        self.all_reg_defs = dict()
        for bb in self._basic_block_dict.values():
            bb._compute_gen()
            for gen_loc in bb.reg_gen:
                ins_addr = gen_loc[1]
                gen_ins = bb.get_ins(ins_addr)
                if gen_ins:
                    for reg in gen_ins.reg_def:
                        if reg in self.all_reg_defs:
                            self.all_reg_defs[reg].add(gen_loc)
                        else:
                            self.all_reg_defs[reg] = {gen_loc}
                else:
                    print 'no gen_ins'
                    print '%08X' % ins_addr
                    print bb
                    print


        for bb in self._basic_block_dict.values():
            bb._compute_kill(self.all_reg_defs)

        is_change = True
        while is_change:
            is_change = False
            for bb in self._basic_block_dict.values():
                # IN[B] = union(OUT[P] where P is a predecessor of B)
                # OUT[B] = gen(B) union (IN[B] - kill(B))
                bb_out_len = len(bb.OUT)
                bb_in_len = len(bb.IN)
                for pred_addr in bb.in_edge:
                    pred = self.get_basic_block(pred_addr)
                    if pred:
                        bb.IN |= pred.OUT
                    else:
                        print 'no pred'
                        print bb
                        print
                bb.OUT = bb.reg_gen | (bb.IN - bb.reg_kill)

                if bb_out_len != len(bb.OUT):
                    is_change = True
                if bb_in_len != len(bb.IN):
                    is_change = True


    def add_bb(self, bb):
        """
        add a basic block to this function

        :type bb: N2BB
        :param bb: basic block
        """
        self._basic_block_dict[bb._start_addr] = bb


    @classmethod
    def make_from_ida_function(cls, ea):
        """
        Get a IDA function address and return a basic block graph.

        :type ea: long
        :param ea: function address
        """
        from idaapi import get_func
        obj = cls()
        obj._start_addr = ea
        fn = get_func(ea)
        if not fn:
            raise Exception('No function at %08X.' % ea)

        fc = FnCache(fn)

        # populate basic block objects map
        for bb in fc.get_bb_list():
            bb_obj = N2BB.make_from_ida_basic_block(bb)
            obj._basic_block_dict[bb._start_addr] = bb_obj

        return obj

    @classmethod
    def make_function_from_ida(cls, ea):
        """
        Get a handler code from starting address 'ea'.
        IDA Pro cannot identify a handler as a function.
        So an N2Fn is a collection of connected basic blocks.

        :type ea: long
        :param ea: function address
        """

        from idc import MakeUnkn, MakeCode, DOUNK_EXPAND, ItemSize, GetFlags, Message
        from idautils import XrefsFrom
        from idaapi import fl_JF, fl_JN, fl_F, isCode
        fn_obj = cls()
        fn_obj._start_addr = ea

        current_basic_block_set = set()
        """type: set[my_ida_basic_block]"""

        next_basic_block_set = set()
        """type: set[my_ida_basic_block]"""

        handler_basic_block_dict = dict()
        """type: dict[long, my_ida_basic_block]"""

        handler_addr_to_basic_block_dict = dict()
        """type: dict[long, my_ida_basic_block]"""

        bb_obj = my_ida_basic_block(ea)
        handler_addr_to_basic_block_dict[ea] = bb_obj
        handler_basic_block_dict[ea] = bb_obj

        Message(hex(ea) + '\n')
        next_basic_block_set.add(bb_obj)

        while next_basic_block_set:

            # tmp = ''
            # for hdl_addr in handler_basic_block_dict:
            #     tmp += str(handler_basic_block_dict[hdl_addr]) + '\n'
            # Message(tmp + '\n')

            current_basic_block_set = list(next_basic_block_set)
            next_basic_block_set.clear()

            # while current_basic_block_set:
            for bb in current_basic_block_set:
                if bb.endEA != -1:
                    continue

                MakeUnkn(bb.startEA, DOUNK_EXPAND)

                ea = bb.startEA

                # get a basic block at ea
                last_crefs = []
                while True:
                    MakeCode(ea)
                    if not isCode(GetFlags(ea)):
                        break

                    crefs = filter(lambda x: x.type in [fl_JF, fl_JN, fl_F], list(XrefsFrom(ea, 0)))
                    handler_addr_to_basic_block_dict[ea] = bb
                    bb.addrs.append(ea)

                    ea += ItemSize(ea)

                    # end of a basic block when there is no flow
                    if len(crefs) == 0:
                        break

                    # end of a basic block when there is jcc or jmp instruction
                    if len(crefs) == 1 and crefs[0].type in [fl_JF, fl_JN] or len(crefs) >= 2:
                        last_crefs = crefs
                        break

                    # end of a basic block when the next instruction is contained in another basic block
                    if ea in handler_addr_to_basic_block_dict:
                        last_crefs = crefs
                        break


                bb.endEA = ea

                for cref in last_crefs:
                    to_addr = cref.to
                    if to_addr in handler_addr_to_basic_block_dict:

                        # existing basic block
                        if to_addr in handler_basic_block_dict:
                            # branch into the starting address of a basic block
                            to_bb = handler_basic_block_dict[to_addr]
                            to_bb._preds.add(bb)
                            bb._succs.add(to_bb)

                        else:
                            # branch into the middle of a basic block
                            # we need to split the basic block into two basic blocks
                            bb1 = handler_addr_to_basic_block_dict[to_addr]
                            bb2 = my_ida_basic_block(to_addr)

                            bb2.endEA = bb1.endEA
                            bb2._preds = {bb1, bb}
                            bb2._succs = {x for x in bb1._succs}
                            idx = bb1.addrs.index(to_addr)
                            bb2.addrs = bb1.addrs[idx:]

                            for bb2succ in bb2._succs:
                                bb2succ._preds.remove(bb1)
                                bb2succ._preds.add(bb2)

                            bb1.endEA = to_addr
                            bb1._succs = {bb2}
                            bb1.addrs = bb1.addrs[:idx]

                            bb._succs.add(bb2)

                            handler_basic_block_dict[bb2.startEA] = bb2
                            handler_addr_to_basic_block_dict[to_addr] = bb2

                            for addr in bb1.addrs:
                                handler_addr_to_basic_block_dict[addr] = bb1
                            for addr in bb2.addrs:
                                handler_addr_to_basic_block_dict[addr] = bb2

                    else:
                        # new basic block
                        new_bb = my_ida_basic_block(to_addr)
                        new_bb._preds.add(bb)
                        bb._succs.add(new_bb)

                        handler_addr_to_basic_block_dict[to_addr] = new_bb
                        handler_basic_block_dict[to_addr] = new_bb

                        next_basic_block_set.add(new_bb)

                # end of 'for cref in last_crefs:'
            # end of 'for bb in current_basic_block_set:'
            # end of 'while current_basic_block_set:'
        # end of 'while next_basic_block_set:'

        if not handler_basic_block_dict:
            raise Exception('No function at %08X.' % ea)

        tmp = ''
        for hdl_addr in handler_basic_block_dict:
            tmp += str(handler_basic_block_dict[hdl_addr]) + '\n'
        Message(tmp + '\n')

        # populate basic block objects map
        for bb_addr in handler_basic_block_dict:
            bb = handler_basic_block_dict[bb_addr]
            bb_obj = N2BB.make_from_ida_basic_block(bb)
            fn_obj._basic_block_dict[bb.startEA] = bb_obj

        return fn_obj

    @classmethod
    def make_from_dump(cls, file_name='FunctionTmp.p'):
        """
        Make InstructionList instance by start address and number of instructions.
        :rtype : N2Fn
        :type file_name: string
        :param file_name: File name.
        :return: N2Fn instance.
        """
        obj = pickle.load(file(file_name, 'rb'))
        return obj

    @classmethod
    def make_from_str(cls, lines):
        """
        Make InstructionList instance by assembly text file.
        Text file format is as follows.

        Function:00405902
        Basic Block:[00405902, 0040596b], in_edge:[00405882], out_edge:[40596b]
        00405902 add ebx, 0
        00405908 xor ebx, 0xe1
        0040590E mov ecx, 0
        ....
        00405969 mov dword ptr [ecx], esi

        Basic Block:[00405868, 00405882], in_edge:[004056b3], out_edge:[00405882]
        00405868 or esi, 0xc4
        0040586E and esi, 0x91
        00405874 add dword ptr [edi], 4
        0040587A mov esi, edx
        0040587C or esi, 0xc8

        :rtype : N2Fn
        :type file_name: string
        :param file_name: File name.
        :return: N2Fn instance.
        """

        fn = cls()
        bb_code = []

        for line in lines:
            if line.startswith('Function:'):
                fn._start_addr = int(line[9:17].strip(), 16)
            elif line.startswith('Basic Block:'):
                bb_code = [line]
            elif len(line) > 8 and is_hex_str(line[0:8]):
                bb_code.append(line)
            elif bb_code:
                bb = N2BB.make_from_str(bb_code)
                fn._basic_block_dict[bb.start_addr] = bb
                bb_code = []
        if bb_code:
            bb = N2BB.make_from_str(bb_code)
            fn._basic_block_dict[bb.start_addr] = bb

        return fn

    @classmethod
    def make_from_text_file(cls, file_name='FunctionTmp.txt', fn_addr=0):
        """
        Make InstructionList instance by assembly text file.
        Text file format is as follows.

        Function:00405902
        Basic Block:[00405902, 0040596b], in_edge:[00405882], out_edge:[40596b]
        00405902 add ebx, 0
        00405908 xor ebx, 0xe1
        0040590E mov ecx, 0
        ....
        00405969 mov dword ptr [ecx], esi

        Basic Block:[00405868, 00405882], in_edge:[004056b3], out_edge:[00405882]
        00405868 or esi, 0xc4
        0040586E and esi, 0x91
        00405874 add dword ptr [edi], 4
        0040587A mov esi, edx
        0040587C or esi, 0xc8

        :rtype : N2Fn
        :type file_name: string
        :type fn_addr: int
        :param file_name: File name.
        :param fn_Addr: function address
        :return: N2Fn instance.
        """
        return N2Fn.make_from_str(open(file_name, 'r').readlines())

    def __str__(self):
        """
        Return the string representation of this function.
        This includes the function start address and each basic blocks.
        :return: string representation of this function.
        """
        # val = 'Function:%08x\n' % self.start_addr
        val = self.info + '\n'
        for bb in self.basic_blocks:
            val += str(bb) + '\n'
        return val

    @property
    def info(self):
        val = 'Function:%08x ' % self.start_addr
        val += 'Basic Blocks=' + str(map(lambda x: '%08X' % x, self.basic_block_addresses)).replace("'", "")
        val += ' Entry Blocks=' + str(map(lambda x: '%08X' % x,
                                          filter(lambda x: len(self.get_basic_block(x).in_edge) == 0,
                                                 self.basic_block_addresses))).replace("'", "")
        val += ' Exit Blocks=' + str(map(lambda x: '%08X' % x,
                                         filter(lambda x: len(self.get_basic_block(x).in_edge) == 0,
                                                self.basic_block_addresses))).replace("'", "")

        return val

    def save_dump(self, file_name='FunctionTmp.p'):
        """
        Save a dump file
        :param file_name: dump file name
        """
        pickle.dump(self, file(file_name, 'wb'))

    def save_text(self, file_name='FunctionTmp.txt'):
        """
        Save a dump file
        :param file_name: dump file name
        """
        import os.path
        tmppath = os.path.abspath(os.path.join(file_name, os.pardir))
        tmppath = os.path.abspath(os.path.join(tmppath, os.pardir))
        tmppath += '\\Handler\\'
        file_name = os.path.basename(file_name)
        fp = file(tmppath + file_name, 'w')
        fp.write(str(self))
        fp.close()

    @property
    def start_addr(self):
        return self._start_addr

    @property
    def basic_blocks(self):
        """
        Get basic block addresses in the function.
        :return: list of basic blocks of the function
        """
        return self._basic_block_dict.values()

    @property
    def basic_block_addresses(self):
        """
        Get basic block addresses in the function.
        :return: list of basic block address of the function
        """
        return self._basic_block_dict.keys()

    def get_basic_block(self, ea):
        """
        Get a basic block by a basic block address.
        :rtype : ir.N2BB
        :param ea: basic block address
        :return: -1 if not exists. BasicBlock object if exists.
        """
        if ea in self._basic_block_dict:
            return self._basic_block_dict[ea]
        return None

    def remove_basic_block(self, ea):
        """
        Remove a basic block from this function.
        :rtype : bool
        :type ea: long
        :param ea: Basic block address
        :return: True if removed
        """
        if ea not in self._basic_block_dict:
            return False
        del self._basic_block_dict[ea]
        return True

class N2Pgm:
    """
    A program class is a set of functions
    """

    def __init__(self):
        self._name = ''
        """:type: str"""

        self._bb_dict = dict()
        """:type : dict[long, N2BB]"""

        self._fn_dict = dict()
        """:type : dict[long, N2Fn]"""

        self._inst_dict = dict()
        """:type : dict[long, N2Inst]"""

        self._imports = dict()
        """:type : dict[long, str]"""

        self._strings = dict()
        """:type : dict[long, unicode]"""

    def get_bb(self, ea):
        """
        Get a basic block from this program
        :param ea: address
        :return: basic block at ea
        """
        return self._bb_dict[ea]

    def get_fn(self, ea):
        """
        Get a function from this program
        :param ea: address
        :return: function at ea
        """
        return self._fn_dict[ea]

    def get_inst(self, ea):
        """
        Get an instruction from this program
        :param ea: address
        :return: instruction at ea
        """
        return self._inst_dict[ea]

    @classmethod
    def make_from_exe_and_fninfo(cls, exe_file, fninfo_file):
        """
        Load an executable file and a function information.
        :param exe_file: an executabe file path
        :param fninfo_file: a file information file path
        :return: new object
        """
        obj = cls()
        obj._name = exe_file

        import pefile
        pe = pefile.PE(exe_file)
        base = pe.OPTIONAL_HEADER.ImageBase

        import json
        with open(fninfo_file, 'r') as f:
            fninfo = json.load(f)

        # load functions
        for fn in fninfo['functions']:
            n2fn = N2Fn()
            n2fn._start_addr = fn['addr'] + base
            obj._fn_dict[n2fn._start_addr] = n2fn

            for bb in fn['basic_blocks']:
                bb_addr = bb['addr']
                bb_size = bb['size']
                bb_bytes = pe.get_data(bb_addr, bb_size)
                bb_peds = map(lambda x: x+base, bb['preds'])
                bb_succs = map(lambda x: x+base, bb['succs'])
                n2bb = N2BB.make_from_bytes(base + bb_addr, bb_bytes, bb_preds, bb_succs)
                n2fn.add_bb(n2bb)
                obj._bb_dict[bb_addr] = n2bb
                for ins in n2bb.ins_list:
                    obj._inst_dict[ins.address] = ins
        # load imports
        for item in fninfo['imports']:
            addr = item['addr']
            lib = item['lib']
            if 'name' in item:
                name = item['name']
                obj._imports[addr] = '%s.%s' % (lib, name)
            else:
                ord = item['ord']
                obj._imports[addr] = '%s.#%d' % (lib, ord)

        # load strings
        for item in fninfo['strings']:
            obj._strings[item['addr']] = item['str']

        return obj

    def __str__(self):
        """
        Return the string representation of this program.
        :return: string representation of this program.
        """
        val = self._name + '\n'
        for fn in self._fn_dict.itervalues():
            val += str(fn) + '\n'

        for ea, name in self._imports.iteritems():
            val += '%08X %s\n' % (ea, name)

        for ea, name in self._strings.iteritems():
            val += '%08X %s\n' % (ea, name)
        return val

# test
if __name__ == '__main__':
    pgm = N2Pgm.make_from_exe_and_fninfo('C:/vex/Binary/Test.exe',
                                   'C:/vex/Binary/Test.exe_fninfo.json')
    print '%s' % pgm
