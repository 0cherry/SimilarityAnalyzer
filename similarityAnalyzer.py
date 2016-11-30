import json
import csv
import math
import os
import multiprocessing as mp
import time
import re
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
def initQueue(filepath1, filepath2):
    fninfo1 = readFile(filepath1)['functions']
    fninfo2 = readFile(filepath2)['functions']

    # print number of functions
    print filepath1 + ' functions : ' + str(len(fninfo1))
    print filepath2 + ' functions : ' + str(len(fninfo2))
    print "#Queue is setting..."
    start = time.clock()
    for f1 in fninfo1:
        for f2 in fninfo2:
            if isCandidate(f1, f2):
                queue.put([f1, f2])
    print "Filtering time :", (time.clock()-start)
    print "#Complete. queue size is", queue.qsize()

def getCountFunctionHasName(fninfo1, fninfo2):
    pattern = re.compile('sub_[A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9]')
    num1, num2 = 0, 0
    for f1 in fninfo1:
        if pattern.match(f1['name']) or len(f1['mnemonics']) < 51:
            continue
        num1 = num1 + 1
    for f2 in fninfo2:
        if pattern.match(f2['name']) or len(f2['mnemonics']) < 51:
            continue
        num2 = num2 + 1
    print num1, num2

def isCandidate(f1, f2):
    def filterByFunctionSize(f1, f2):
        f1size, f2size = len(f1['mnemonics']), len(f2['mnemonics'])
        if 10 < f1size < 150 and 10 < f2size < 150:
            return True
        return False

    def filterByExistedFuncionName(f1, f2):
        pattern = re.compile('sub_[A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9]')
        if pattern.match(f1['name']) or pattern.match(f2['name']):
            return False
        return True

    def filterByFunctionName(f1, f2):
        if f1['name'] == f2['name']:
            return True
        return False

    def filterByCosine(f1, f2):
        cosine_similarity = getCosineSimilarity(f1, f2)[0]
        if cosine_similarity >= 0.7:
            return True
        return False

    #Unused
    def filterByMnemonicLCS(f1, f2):
        mnemonics1, mnemonics2 = f1['mnemonics'], f2['mnemonics']
        maxlen = max(len(mnemonics1), len(mnemonics2))
        n = maxlen
        if maxlen > n:
            maxlen = n
        if len(mnemonics1) > n:
            mnemonics1 = mnemonics1[0:n]
        if len(mnemonics2) > n:
            mnemonics2 = mnemonics2[0:n]
        # LCS/min * min/max
        bytelcs_similairty = float(lcs(mnemonics1, mnemonics2))/maxlen
        if bytelcs_similairty > 0.7:
            return True
        return False

    #not impilemented
    def filterByGraph(f1, f2):
        pass

    #function body
    return filterByExistedFuncionName(f1, f2) and filterByFunctionName(f1, f2) and filterByFunctionSize(f1, f2)

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
    initQueue(filepath1, filepath2)
    startProcess(processOfArray)

def writeinfo(queue, result_filename):
    with open(result_filename, 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        #tuples = ['srcName', 'srcMumOfMne', 'dstName', 'dstNumOfMne', 'cosine', 'cosineTime', 'graph', 'graphTime', 'ngram', 'ngramTime']
        if( result_filename[-1] == '0' ):
            tuples = ['srcName', 'srcMumOfMne', 'dstName', 'dstNumOfMne', 'cosine', 'cosineTime', 'ngram', 'ngram_var', 'sim2', 'sim3', 'ngramTime']
            writer.writerow(tuples)

        while queue.qsize() > 0:
            f = queue.get(timeout=1.5)
            f1, f2 = f[0], f[1]
            info = calculateSimilarity(f1, f2)
            if info is not None:
                writer.writerow(info)
    os.rename(result_filename, result_filename+'.csv')

def filtering(queue, result_filename):
    start = time.clock()
    with open(result_filename, 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        #tuples = ['srcName', 'srcMumOfMne', 'dstName', 'dstNumOfMne', 'cosine', 'cosineTime', 'graph', 'graphTime', 'ngram', 'ngramTime']
        if( result_filename[-1] == '0' ):
            tuples = ['srcName', 'srcAddr', 'srcNumOfMne', 'dstName', 'dstAddr', 'dstNumOfMne', 'cosine', 'cosineTime', 'mLCS', 'mLCSTime']
            writer.writerow(tuples)

        while queue.qsize() > 0:
            f = queue.get(timeout=1.5)
            f1, f2 = f[0], f[1]
            cosine_similarity = getCosineSimilarity(f1, f2)
            cosine, cosineTime = cosine_similarity[0], cosine_similarity[1]
            lcs = getMnemonicLCS(f1, f2)
            mLCS, mLCSTime = lcs[0], lcs[1]
            info = [f1['name'], f1['addr'], len(f1['mnemonics']), f2['name'], f2['addr'], len(f2['mnemonics']), cosine, cosineTime, mLCS, mLCSTime]
            writer.writerow(info)
    print result_filename, "analysis time :", str(time.clock()-start)
    os.rename(result_filename, result_filename+'.csv')

def calculateSimilarity(f1, f2):
    info = [f1['name'], len(f1['mnemonics']), f2['name'], len(f2['mnemonics'])]
    cosineSimilarity, cosineTime = getCosineSimilarity(f1, f2)
    # graph_distance, graphTime = getGraphDistance(f1, f2)
    ngram_distance, ngram_var, sim2, sim3, ngram_time, indexes = getNgramDistance(f1, f2, 8)
    info.append(cosineSimilarity)
    info.append(cosineTime)
    # info.append(graph_distance)
    # info.append(graphTime)
    info.append(ngram_distance)
    info.append(ngram_var)
    info.append(sim2)
    info.append(sim3)
    info.append(ngram_time)
    info.append(indexes)
    return info

def getCosineSimilarity(f1, f2):
    start = time.clock()
    name1, blocks1, edges1, calls1, cmps1 = f1['name'], f1['blocks'], f1['edges'], f1['calls'], f1['cmps']
    name2, blocks2, edges2, calls2, cmps2 = f2['name'], f2['blocks'], f2['edges'], f2['calls'], f2['cmps']
    a = cmps1 * cmps2 + blocks1 * blocks2 + calls1 * calls2 + edges1 * edges2
    b = math.sqrt(cmps1 * cmps1 + blocks1 * blocks1 + calls1 * calls1 + edges1 * edges1)
    c = math.sqrt(cmps2 * cmps2 + blocks2 * blocks2 + calls2 * calls2 + edges2 * edges2)
    # cosine similarity + vector size
    cosine_simiarity = a / (b * c) * (min(b, c) / max(b, c))
    return cosine_simiarity, time.clock()-start

def getMnemonicLCS(f1, f2):
    start = time.clock()
    mnemonics1, mnemonics2 = f1['mnemonics'], f2['mnemonics']
    maxlen = max(len(mnemonics1), len(mnemonics2))
    # n = maxlen
    # if maxlen > n:
    #     maxlen = n
    # if len(mnemonics1) > n:
    #     mnemonics1 = mnemonics1[0:n]
    # if len(mnemonics2) > n:
    #     mnemonics2 = mnemonics2[0:n]
    # LCS/min * min/max
    bytelcs_similairty = float(lcs(mnemonics1, mnemonics2)) / maxlen
    return bytelcs_similairty, time.clock() - start

def getGraphDistance(f1, f2):
    start = time.clock()
    g1, g2 = graph(f1['basic_blocks']), graph(f2['basic_blocks'])
    distance = float(graph_edit_distance(g1, g2))
    graph_similarity = 1-(distance/(g1.getGraphBlocks()+g1.getGraphEdges()+g1.getGraphSize()+g2.getGraphBlocks()+g2.getGraphEdges()+g2.getGraphSize()))
    return graph_similarity, time.clock()-start

def getNgramDistance(f1, f2, n):
    start = time.clock()
    mnemonics1, mnemonics2 = f1['mnemonics'], f2['mnemonics']
    length = min(len(mnemonics1), len(mnemonics2))
    #if length > 150: length = 150
    mnemonics1, mnemonics2 = f1['mnemonics'][:length], f2['mnemonics'][:length]
    if length < n:
        n = length
    ngram1 = ngram(mnemonics1, n)
    ngram2 = ngram(mnemonics2, n)
    ngram_distance, ngram_var, sim2, sim3, indexes = ngramset_edit_distance(ngram1.ngramSet, ngram2.ngramSet)
    return ngram_distance, ngram_var, sim2, sim3, indexes, time.clock()-start

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
    start = time.clock()
    #writeAnalysis('fninfo\A.json', 'fninfo\B.json')
    if len(sys.argv) != 4:
        print "needed 3 argments"
        exit()
    analyze(sys.argv[1], sys.argv[2])
    unionOutputCSVfiles(sys.argv[1], sys.argv[2])
    deleteTemporaryFiles(sys.argv[1], sys.argv[2])
    print 'execution time :', (time.clock() - start)
    queue.close()
    queue.join_thread()

def test():
    start = time.clock()
    for i in range(30000): print i
    print "execution time :", time.clock()-start

if __name__ == "__main__":
    run()