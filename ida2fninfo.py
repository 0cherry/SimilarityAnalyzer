# coding=utf-8
from idaapi import *
from idc import *
from idautils import *
import json
import os.path
import datetime

start_time = datetime.datetime.now()
base = get_imagebase()


class FnCache:
    def __init__(self, addr):
        self.startAddr = addr
        self.bbMap = {}
        self.graph = idaapi.FlowChart(addr, flags=idaapi.FC_PREDS)
        for bb in self.graph:
            self.bbMap[bb.startEA] = bb

    def get_graph(self):
        return self.graph

    def get_bb(self, ea):
        if ea in self.bbMap:
            return self.bbMap[ea]
        return []

    def get_bb_map(self):
        return self.bbMap

    def get_bb_list(self):
        return self.bbMap.values()


def getBlockInfo(bb):
    basic_block = dict()
    basic_block['number'] = bb.id
    basic_block['addr'] = bb.startEA - base
    basic_block['size'] = bb.endEA - bb.startEA
    predcessor_list = list()
    basic_block['preds'] = predcessor_list
    succs = list()
    basic_block['succs'] = succs
    mnemonics = getMnemonics(bb)
    basic_block['mnemonics'] = mnemonics
    for pred in bb.preds():
        # fp.write('Pred %08X\n' % pred.startEA)
        predcessor_list.append(pred.startEA - base)
        # edgeCount = edgeCount + 1
    for succ in bb.succs():
        # fp.write('Succ %08X\n' % succ.startEA)
        succs.append(succ.startEA - base)
    return basic_block


def getMnemonics(bb):
    mnemonics = []
    for i in range(bb.startEA, bb.endEA):
        mnemonic = GetMnem(i)
        if mnemonic is not '':
            mnemonics.append(mnemonic)
    return mnemonics


def getBlockList(func):
    # save basic block information
    basic_blocks = list()
    for bb in func.get_bb_list():
        # fp.write('BasicBlock %08X %08X\n' % (bb.startEA, bb.endEA))

        # skip disassemble failure
        if bb.endEA == bb.startEA:
            continue

        basic_block = getBlockInfo(bb)
        basic_blocks.append(basic_block)
    return basic_blocks


def getFunctionInfo(fn_ea, func):
    fc = FnCache(func)

    # function informations
    call_count = 0
    cmp_count = 0
    disasm_addr = list(FuncItems(fn_ea))
    mnemonics = []
    for curr_addr in disasm_addr:
        mnemonic = GetMnem(curr_addr)
        mnemonics.append(mnemonic)
        # print type(GetDisasm(curr_addr))
        if mnemonic == "call":
            #print call address
            #print GetOperandValue(curr_addr, 0) - base
            call_count += 1
        elif mnemonic == "cmp":
            cmp_count += 1

    function = dict()  # for json output
    # fp.write('Function %08X\n' % fn_ea)
    function['addr'] = fn_ea - base
    function['mnemonics'] = mnemonics
    function['basic_blocks'] = getBlockList(fc)
    function['name'] = GetFunctionName(fn_ea)
    function['blocks'] = len(function['basic_blocks'])
    edge_count = 0
    for block in function['basic_blocks']:
        edge_count += len(block['preds'])
    function['edges'] = edge_count
    function['calls'] = call_count
    function['cmps'] = cmp_count
    return function


def getFunctionList():
    # save function
    functions = list()
    for seg_ea in Segments():
        for fn_ea in Functions(SegStart(seg_ea), SegEnd(seg_ea)):
            asm_count = len(list(FuncItems(fn_ea)))
            func = get_func(fn_ea)    # idaapi function
            basic_block_count = (FlowChart(func, flags=FC_NOEXT)).size

            if asm_count < 2 or basic_block_count < 2:
                # print "number of instructions : " + str(len(dism_addr))
                continue

            # skip library functions
            if func.flags & FUNC_LIB:
                continue

            function = getFunctionInfo(fn_ea, func)
            functions.append(function)

    return functions


def get_operand(ea):
    # op_t.type
    #                  Description                          Data field
    # o_void = 0  # No Operand                           ----------
    # o_reg = 1  # General Register (al,ax,es,ds...)    reg
    # o_mem = 2  # Direct Memory Reference  (DATA)      addr
    # o_phrase = 3  # Memory Ref [Base Reg + Index Reg]    phrase
    # o_displ = 4  # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    # o_imm = 5  # Immediate Value                      value
    # o_far = 6  # Immediate Far Address  (CODE)        addr
    # o_near = 7  # Immediate Near Address (CODE)        addr
    op_types = [GetOpType(ea, 0), GetOpType(ea, 1)]
    operands = []
    for idx, op_type in enumerate(op_types):
        if op_type == o_void:
            break
        elif op_type == o_reg:
            operands.append('reg')
        elif op_type == o_mem:
            operands.append('mem')
        elif op_type == o_phrase:
            operands.append('mem')
        elif op_type == o_displ:
            operands.append('mem')
        elif op_type == o_imm:
            operand_value = GetOperandValue(ea, idx)
            if operand_value > 0:
                operands.append('+')
            elif operand_value < 0:
                operands.append('-')
            else:
                operands.append('0')
        elif op_type == o_far:
            operands.append('code')
        elif op_type == o_near:
            operands.append('code')
        else:
            continue
    return operands


def save_to_json():
    # save function information in a text file
    exe_fname = get_input_file_path()
    # print exe_fname

    # construct program dictionary for json output
    pgm = dict()
    pgm['filepath'] = exe_fname
    pgm['functions'] = getFunctionList()

    # save as exe_fname_fninfo.json in D:\SimilarityAnalysis\fninfo directory
    with open('D:\\SimilarityAnalyzer\\fninfo\\' + os.path.basename(exe_fname) + '_fninfo.json', 'w') as f:
        json.dump(pgm, f)


def save_to_csv():
    file_name = get_input_file_path()

    with open('D:\\SimilarityAnalyzer\\fninfo\\' + 'openssl_export_function.csv', 'a') as f:
        for seg_ea in Segments():
            for fn_ea in Functions(SegStart(seg_ea), SegEnd(seg_ea)):
                rva = fn_ea
                offset = rva - base
                function_name = GetFunctionName(rva)
                function_code = ''
                assembly_code = ''
                function_code_size = 0
                call = 0
                cmp = 0
                disassemble_address_list = list(FuncItems(rva))
                # block = len(disassemble_address_list)
                version = os.path.basename(file_name)

                import re
                unknown_function = re.compile('sub_'+'[A-Z0-9]{8}')
                indirect_function = re.compile('^_'+'.*')
                if not(unknown_function.match(function_name) or indirect_function.match(function_name)):
                    f.write('{},{},{},{},'.format(version, function_name, rva, offset))

                    func = get_func(rva)
                    # cfg = FlowChart(func, flags=FC_NOEXT)
                    function = getFunctionInfo(rva, func)

                    for current_address in disassemble_address_list:
                        code_piece = GetManyBytes(current_address, get_item_size(current_address)).encode('hex')
                        function_code += code_piece
                        function_code_size += len(str(code_piece))/2

                        # f.write(code_piece)
                        mnemonic = GetMnem(current_address)
                        operands = get_operand(current_address)
                        number_of_operands = len(operands)

                        instruction = ''
                        if number_of_operands == 0:
                            instruction = '{}/'.format(mnemonic)
                        elif number_of_operands == 1:
                            instruction = '{} {}/'.format(mnemonic, operands[0])
                        else:
                            instruction = '{} {} {}/'.format(mnemonic, operands[0], operands[1])
                        assembly_code += instruction

                        # function_code += code_piece
                        if mnemonic == 'call':
                            call += 1
                        elif mnemonic == 'cmp':
                            cmp += 1
                        else:
                            continue

                    f.write('{},'.format(function_code))
                    f.write('{},'.format(assembly_code[:-1]))
                    # function_code_size = len(function_code)/2
                    f.write('{},'.format(function_code_size))
                    f.write('{},{},{},{}\n'.format(function['blocks'], function['edges'], call, cmp))


def main():
    autoWait()
    save_to_csv()
    print('time cost : {}'.format(datetime.datetime.now() - start_time))
    Exit(0)

if __name__ == '__main__':
    main()
