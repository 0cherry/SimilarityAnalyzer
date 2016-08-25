# coding=utf-8
from idaapi import *
from idc import *
from idautils import *
import json
import os.path

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

base = get_imagebase()
def getBlockInfo(bb):
    basic_block = dict()
    basic_block['number'] = bb.id
    basic_block['addr'] = bb.startEA - base
    basic_block['size'] = bb.endEA - bb.startEA
    preds = list()
    basic_block['preds'] = preds
    succs = list()
    basic_block['succs'] = succs
    #mnemonics = getMnemonics(bb)
    #basic_block['mnemonics'] = mnemonics
    for pred in bb.preds():
        # fp.write('Pred %08X\n' % pred.startEA)
        preds.append(pred.startEA - base)
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
    callCount = 0
    cmpCount = 0
    dism_addr = list(FuncItems(fn_ea))
    mnemonics = []
    for curr_addr in dism_addr:
        mnemonic = GetMnem(curr_addr)
        mnemonics.append(mnemonic)
        # print type(GetDisasm(curr_addr))
        if mnemonic == "call":
            #print call address
            #print GetOperandValue(curr_addr, 0) - base
            callCount = callCount + 1
        elif mnemonic == "cmp":
            cmpCount = cmpCount + 1

    function = dict()  # for json output
    # fp.write('Function %08X\n' % fn_ea)
    function['addr'] = fn_ea - base
    function['mnemonics'] = mnemonics
    function['basic_blocks'] = getBlockList(fc)
    function['name'] = GetFunctionName(fn_ea)
    function['blocks'] = len(function['basic_blocks'])
    edgeCount = 0
    for block in function['basic_blocks']:
        edgeCount += len(block['preds'])
    function['edges'] = edgeCount
    function['calls'] = callCount
    function['cmps'] = cmpCount
    return function

def getFunctionList():
    # save function
    functions = list()
    for seg_ea in Segments():
        for fn_ea in Functions(SegStart(seg_ea), SegEnd(seg_ea)):
            asmCount = len(list(FuncItems(fn_ea)))
            func = get_func(fn_ea)    # idaapi function
            BBCount = (FlowChart(func, flags=FC_NOEXT)).size

            if asmCount < 2 or BBCount < 2:
                # print "number of instructions : " + str(len(dism_addr))
                continue

            # skip library functions
            if func.flags & FUNC_LIB:
                continue

            function = getFunctionInfo(fn_ea, func)
            functions.append(function)

    return functions

# save function information in a text file
exe_fname = get_input_file_path()
print exe_fname

# construct program dictionary for json output
pgm = dict()
pgm['filepath'] = exe_fname
pgm['functions'] = getFunctionList()

#save as exe_fname_fninfo.json in D:\SimilarityAnalysis\fninfo directory
with open('D:\\SimilarityAnalyzer\\fninfo\\' + os.path.basename(exe_fname) + '_fninfo.json', 'w') as f:
    json.dump(pgm, f)
