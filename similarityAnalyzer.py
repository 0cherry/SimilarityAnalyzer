import json
import csv
import math
import os.path
import multiprocessing as mp
# import itertools
from graph import *
from editdistance import *
from ngram import *

def readFile(filePath):
    f = open(filePath, 'r')
    contents = json.loads(f.read())
    f.close()
    return contents


def writeAnalysis(file1, file2):
    cmp1 = readFile(file1)
    cmp2 = readFile(file2)

    fninfo1 = cmp1['functions']
    fninfo2 = cmp2['functions']

    #print number of functions
    print file1 + ' functions : ' + str(len(fninfo1))
    print file2 + ' functions : ' + str(len(fninfo2))

    result_filename = 'D:\\SimilarityAnalyzer\\test\\' + os.path.basename(file1) + '+' + os.path.basename(file2) + 'analysis300'
    processOfNumber = 10
    processOfArray = []

    # generate processes
    for i in range(processOfNumber):
        end = len(fninfo1)
        section_start = end*i/processOfNumber
        section_end = end*(i+1)/processOfNumber
        distributed_funcion_list = fninfo1[section_start:section_end]
        if i==processOfNumber:
            section_end = end
        processOfArray.append(mp.Process(target=writeinfo, args=(distributed_funcion_list, fninfo2, result_filename+str(i))))

    # start, join processes
    for process in processOfArray:
        process.start()
    for process in processOfArray:
        process.join()


def writeinfo(fninfo1, fninfo2, result_filename):
    import time
    start = time.time()
    with open(result_filename, 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['targetAddr', 'targetName', 'blocks1', 'edges1', 'calls1', 'cmps1', 'sourceAddr', 'sourceName', 'blocks2', 'edges2', 'calls2', 'cmps2', 'cosine', 'graph distance', 'ngram distance'])

        for f1 in fninfo1:
            for f2 in fninfo2:
                info = calculateSimilarity(f1, f2)
                if info is not None:
                    writer.writerow(info)
    from os import rename
    rename(result_filename, result_filename+'.csv')
    print 'analysis time : %.02f' % (time.time() - start)

def calculateSimilarity(f1, f2):
    info, name1, name2 = getCosineSimilarity(f1, f2)

    if name1 == name2 and name1.find("sub") < 0:
        ngram_distance = getNgramDistance(f1, f2, 8)
        info.append(None)
        info.append(ngram_distance)
        return info

    return None


def getCosineSimilarity(f1, f2):
    name1, blocks1, edges1, calls1, cmps1, addr1 = f1['name'], f1['blocks'], f1['edges'], f1['calls'], f1['cmps'], f1[
        'addr']
    name2, blocks2, edges2, calls2, cmps2, addr2 = f2['name'], f2['blocks'], f2['edges'], f2['calls'], f2['cmps'], f2[
        'addr']
    a = cmps1 * cmps2 + blocks1 * blocks2 + calls1 * calls2 + edges1 * edges2
    b = math.sqrt(cmps1 * cmps1 + blocks1 * blocks1 + calls1 * calls1 + edges1 * edges1)
    c = math.sqrt(cmps2 * cmps2 + blocks2 * blocks2 + calls2 * calls2 + edges2 * edges2)
    # cosine similarity + vector size
    consine_simiarity = a / (b * c) * (min(b, c) / max(b, c))
    info = [addr1, name1, blocks1, edges1, calls1, cmps1, addr2, name2, blocks2, edges2, calls2, cmps2,
            consine_simiarity]
    return info, name1, name2


def getGraphDistance(f1, f2):
    g1 = graph(f1['basic_blocks'])
    g2 = graph(f2['basic_blocks'])
    distance = float(graph_edit_distance(g1, g2))
    similarity = 1-(distance/(g1.getGraphBlocks()+g1.getGraphEdges()+g1.getGraphSize()+g2.getGraphBlocks()+g2.getGraphEdges()+g2.getGraphSize()))
    print 'g1 blocks ', g1.getGraphBlocks()
    print 'g2 blocks ', g2.getGraphBlocks()
    print 'g1 edges ', g1.getGraphEdges()
    print 'g2 edges ', g2.getGraphEdges()
    print 'graph similarity ', similarity
    return similarity


def getNgramDistance(f1, f2, n):
    mnemonics1, mnemonics2 = f1['mnemonics'], f2['mnemonics']
    length = min(len(mnemonics1), len(mnemonics2))
    # if a function is large size,
    if length > 300: length = 300
    mnemonics1, mnemonics2 = f1['mnemonics'][:length], f2['mnemonics'][:length]
    if length < n:
        n = length
    ngram1 = ngram(mnemonics1, n)
    ngram2 = ngram(mnemonics2, n)
    ngram_distance = ngramset_edit_distance(ngram1.ngramSet, ngram2.ngramSet)
    return ngram_distance

def run():
    import time
    start = time.time()
    #writeAnalysis('fninfo\A.json', 'fninfo\B.json')
    if len(sys.argv) != 3:
        writeAnalysis('fninfo\Test.exe_fninfo.json', 'fninfo\Test2.exe_fninfo.json')
    else:
        writeAnalysis(sys.argv[1], sys.argv[2])
    print 'execution time : %.02f' % (time.time() - start)

if __name__ == "__main__":
    run()