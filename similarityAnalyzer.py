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
    print "#Queue is setting..."
    print "Flitering function..."
    start = time.time()
    for f1 in fninfo1:
        for f2 in fninfo2:
            if isCandidate(f1, f2):
                print f1['name'], f2['name']
                # queue.put([f1, f2])
    print "Filtering time", str(time.time() - start)
    print "#Complete. queue size is", queue.qsize()

def filtering(queue, result_filename):
    print "Flitering function..."
    start = time.time()
    while queue.qsize() > 0:
        f = queue.get()
        f1, f2 = f[0], f[1]
        if isCandidate(f1, f2):
            print f1['name'], f2['name']
            # queue.put([f1, f2])
    print "Filtering time", str(time.time() - start)

def isCandidate(f1, f2):
    def filterByFunctionName(f1, f2):
        if f1['name'] == f2['name'] and f1['name'].find("sub") < 0:
            return True
        return False

    def filterByCosine(f1, f2):
        cosine_similarity = getCosineSimilarity(f1, f2)
        if cosine_similarity > 0.7:
            return True
        return False

    def filterByMnemonicLCS(f1, f2):
        mnemonics1, mnemonics2 = f1['mnemonics'], f2['mnemonics']
        n = 300
        maxlen = max(len(mnemonics1), len(mnemonics2))
        if maxlen > n:
            maxlen = n
        if len(mnemonics1) > n:
            mnemonics1 = mnemonics1[0:n]
        if len(mnemonics2) > n:
            mnemonics2 = mnemonics2[0:n]
        common_mnemonics = lcs(mnemonics1, mnemonics2)
        # LCS/min * min/max
        bytelcs_similairty = float(len(common_mnemonics))/maxlen
        if bytelcs_similairty > 0.7:
            return True
        return False

    #not impilemented
    def filterByGraph(f1, f2):
        pass

    #function body
    start = time.time()
    selected = filterByFunctionName(f1, f2) or (filterByCosine(f1, f2) and filterByMnemonicLCS(f1, f2))
    return selected

def analyze(filepath1, filepath2):
    def createProcess(numberOfProcess, func):
        result_filename = 'D:\\SimilarityAnalyzer\\test\\' + os.path.basename(filepath1) + '+' + os.path.basename(filepath2) + 'analysis'
        processOfArray = []
        # generate processes
        for i in range(numberOfProcess):
            processOfArray.append(mp.Process(target=func, args=(queue, result_filename + str(i))))
        return processOfArray

    def startProcess(processOfArray):
        # start, join processes
        for process in processOfArray:
            process.start()
        for process in processOfArray:
            process.join()

    #function body
    fninfo1 = readFile(filepath1)['functions']
    fninfo2 = readFile(filepath2)['functions']

    #print number of functions
    print filepath1 + ' functions : ' + str(len(fninfo1))
    print filepath2 + ' functions : ' + str(len(fninfo2))

    initQueue(fninfo1, fninfo2)
    processOfArray = []
    if sys.argv[3] == "1":
        print "#cosine, ngram calculating..."
        processOfArray = createProcess(8, writeinfo)
    elif sys.argv[3] == "2":
        print "#filtering functions..."
        processOfArray = createProcess(8, filtering)
    else:
        print "wrong input argv[3]"
        exit()
    startProcess(processOfArray)

def writeinfo(queue, result_filename):
    with open(result_filename, 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        #tuples = ['srcName', 'srcMumOfMne', 'dstName', 'dstNumOfMne', 'cosine', 'cosineTime', 'graph', 'graphTime', 'ngram', 'ngramTime']
        if( result_filename[-1] == '0' ):
            tuples = ['srcName', 'srcMumOfMne', 'dstName', 'dstNumOfMne', 'cosine', 'cosineTime', 'ngram', 'ngram_var', 'ngramTime']
            writer.writerow(tuples)

        while queue.qsize() > 0:
            f = queue.get()
            f1, f2 = f[0], f[1]
            info = calculateSimilarity(f1, f2)
            if info is not None:
                writer.writerow(info)
    os.rename(result_filename, result_filename+'.csv')

def calculateSimilarity(f1, f2):
    info = [f1['name'], len(f1['mnemonics']), f2['name'], len(f2['mnemonics'])]
    cosineSimilarity, cosineTime = getCosineSimilarity(f1, f2)
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

def getCosineSimilarity(f1, f2):
    start = time.time()
    name1, blocks1, edges1, calls1, cmps1 = f1['name'], f1['blocks'], f1['edges'], f1['calls'], f1['cmps']
    name2, blocks2, edges2, calls2, cmps2 = f2['name'], f2['blocks'], f2['edges'], f2['calls'], f2['cmps']
    a = cmps1 * cmps2 + blocks1 * blocks2 + calls1 * calls2 + edges1 * edges2
    b = math.sqrt(cmps1 * cmps1 + blocks1 * blocks1 + calls1 * calls1 + edges1 * edges1)
    c = math.sqrt(cmps2 * cmps2 + blocks2 * blocks2 + calls2 * calls2 + edges2 * edges2)
    # cosine similarity + vector size
    cosine_simiarity = a / (b * c) * (min(b, c) / max(b, c))
    return cosine_simiarity, time.time()-start

def getGraphDistance(f1, f2):
    start = time.time()
    g1, g2 = graph(f1['basic_blocks']), graph(f2['basic_blocks'])
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
    analyze(sys.argv[1], sys.argv[2])
    unionOutputCSVfiles(sys.argv[1], sys.argv[2])
    deleteTemporaryFiles(sys.argv[1], sys.argv[2])
    print 'execution time : %.02f' % (time.time() - start)
    queue.close()
    queue.join_thread()

def test():
    analyze('fninfo\\A.json', 'fninfo\\B.json')
    unionOutputCSVfiles('fninfo\\A.json', 'fninfo\\B.json')
    deleteTemporaryFiles('fninfo\\A.json', 'fninfo\\B.json')
    print 'queue size ', queue.qsize()
    queue.close()
    queue.join_thread()

if __name__ == "__main__":
    run()