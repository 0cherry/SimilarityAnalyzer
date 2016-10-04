import json
import csv
import math
import os
import multiprocessing as mp
import time
# import itertools
from graph import *
from editdistance import *
from ngram import *

def readFile(filePath):
    f = open(filePath, 'r')
    contents = json.loads(f.read())
    f.close()
    return contents

queue = mp.Queue()
def initQueue(fninfo1, fninfo2):
    pass

def writeAnalysis(file1, file2):
    cmp1 = readFile(file1)
    cmp2 = readFile(file2)

    fninfo1 = cmp1['functions']
    fninfo2 = cmp2['functions']

    #print number of functions
    print file1 + ' functions : ' + str(len(fninfo1))
    print file2 + ' functions : ' + str(len(fninfo2))

    result_filename = 'D:\\SimilarityAnalyzer\\test\\' + os.path.basename(file1) + '+' + os.path.basename(file2) + 'analysis'
    processOfNumber = 10
    processOfArray = []

    # generate processes
    initQueue(fninfo1, fninfo2)
    # for f1 in fninfo1:
    #     for f2 in fninfo2:
    #         queue.put([f1, f2])

    for i in range(processOfNumber):
        processOfArray.append(mp.Process(target=writeinfo, args=(queue, result_filename+str(i))))

    # start, join processes
    for process in processOfArray:
        process.start()
    for process in processOfArray:
        process.join()


def writeinfo(queue, result_filename):
    with open(result_filename, 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        #tuples = ['srcName', 'srcMumOfMne', 'dstName', 'dstNumOfMne', 'cosine', 'cosineTime', 'graph', 'graphTime', 'ngram', 'ngramTime']
        if( result_filename[-1] == '0' ):
            tuples = ['srcName', 'srcMumOfMne', 'dstName', 'dstNumOfMne', 'cosine', 'cosineTime', 'ngram', 'ngram_var', 'ngramTime']
            writer.writerow(tuples)

        while queue.qsize() > 0:
            f = queue.get(timeout=1)
            f1, f2 = f[0], f[1]
            info = calculateSimilarity(f1, f2)
            if info is not None:
                writer.writerow(info)
    os.rename(result_filename, result_filename+'.csv')


def calculateSimilarity(f1, f2):
    info = [f1['name'], len(f1['mnemonics']), f2['name'], len(f2['mnemonics'])]
    cosineSimilarity, cosineTime = getCosineSimilarity(f1, f2)
    # if f1['name'] == f2['name'] and f1['name'].find("sub") < 0:
    if cosineSimilarity > 0.9:
        # graph_distance, graphTime = getGraphDistance(f1, f2)
        ngram_distance, ngram_var, ngramTime = getNgramDistance(f1, f2, 8)
        info.append(cosineSimilarity)
        info.append(cosineTime)
        # info.append(graph_distance)
        # info.append(graphTime)
        info.append(ngram_distance)
        info.append(ngram_var)
        info.append(ngramTime)
        return info
    else:
        return None


def getCosineSimilarity(f1, f2):
    start = time.time()
    name1, blocks1, edges1, calls1, cmps1, addr1 = f1['name'], f1['blocks'], f1['edges'], f1['calls'], f1['cmps'], f1[
        'addr']
    name2, blocks2, edges2, calls2, cmps2, addr2 = f2['name'], f2['blocks'], f2['edges'], f2['calls'], f2['cmps'], f2[
        'addr']
    a = cmps1 * cmps2 + blocks1 * blocks2 + calls1 * calls2 + edges1 * edges2
    b = math.sqrt(cmps1 * cmps1 + blocks1 * blocks1 + calls1 * calls1 + edges1 * edges1)
    c = math.sqrt(cmps2 * cmps2 + blocks2 * blocks2 + calls2 * calls2 + edges2 * edges2)
    # cosine similarity + vector size
    cosine_simiarity = a / (b * c) * (min(b, c) / max(b, c))
    return cosine_simiarity, time.time()-start

    # info = [addr1, name1, blocks1, edges1, calls1, cmps1, addr2, name2, blocks2, edges2, calls2, cmps2, consine_simiarity]
    # info = [name1, len(f1['mnemonics']), name2, len(f2['mnemonics'])]
    #return info


def getGraphDistance(f1, f2):
    start = time.time()
    g1 = graph(f1['basic_blocks'])
    g2 = graph(f2['basic_blocks'])
    distance = float(graph_edit_distance(g1, g2))
    graph_similarity = 1-(distance/(g1.getGraphBlocks()+g1.getGraphEdges()+g1.getGraphSize()+g2.getGraphBlocks()+g2.getGraphEdges()+g2.getGraphSize()))
    return graph_similarity, time.time()-start


def getNgramDistance(f1, f2, n):
    start = time.time()
    mnemonics1, mnemonics2 = f1['mnemonics'], f2['mnemonics']
    length = min(len(mnemonics1), len(mnemonics2))
    if length > 150: length = 150
    mnemonics1, mnemonics2 = f1['mnemonics'][:length], f2['mnemonics'][:length]
    if length < n:
        n = length
    ngram1 = ngram(mnemonics1, n)
    ngram2 = ngram(mnemonics2, n)
    ngram_distance, ngram_var = ngramset_edit_distance(ngram1.ngramSet, ngram2.ngramSet)
    return ngram_distance, ngram_var, time.time()-start


def deleteTemporaryFiles(path1, path2):
    name1, name2 = os.path.basename(path1), os.path.basename(path2)
    rmCommand = 'del D:\\SimilarityAnalyzer\\test\\{}+{}analysis*'.format(name1, name2)
    print rmCommand
    os.system(rmCommand)


def unionOutputCSVfiles(path1, path2):
    name1, name2 = os.path.basename(path1), os.path.basename(path2)
    unionCommand = 'type D:\\SimilarityAnalyzer\\test\\{}+{}analysis* > D:\\SimilarityAnalyzer\\test\\{}+{}_report.csv'.format(name1, name2, name1, name2)
    print unionCommand
    os.system(unionCommand)


def run():
    start = time.time()
    #writeAnalysis('fninfo\A.json', 'fninfo\B.json')
    if len(sys.argv) != 3:
        print "needed 2 argments"
        exit()
    writeAnalysis(sys.argv[1], sys.argv[2])
    unionOutputCSVfiles(sys.argv[1], sys.argv[2])
    deleteTemporaryFiles(sys.argv[1], sys.argv[2])
    print 'execution time : %.02f' % (time.time() - start)
    queue.close()
    queue.join_thread()

def test():
    writeAnalysis('fninfo\\A.json', 'fninfo\\B.json')
    unionOutputCSVfiles('fninfo\\A.json', 'fninfo\\B.json')
    deleteTemporaryFiles('fninfo\\A.json', 'fninfo\\B.json')
    print 'queue size ', queue.qsize()
    queue.close()
    queue.join_thread()

if __name__ == "__main__":
    run()