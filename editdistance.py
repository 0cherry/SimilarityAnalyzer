#import numpy as np
from munkres import Munkres, print_matrix, make_cost_matrix
from ngram import *
import sys
import numpy

def _build_cost_matrix(graph1, graph2):
    costMatrix = []
    for graph1_block in graph1.block_list:
        unitMatrix = []
        for graph2_block in graph2.block_list:
            unitMatrix.append(graph1_block.getMatchingCost(graph2_block) + 1)
        costMatrix.append(unitMatrix)
    #costMatrix = np.array(costMatrix) + 10

    row = len(graph1.block_list)
    column = len(graph2.block_list)
    matrix = []
    if row > column:
        for block in graph1.block_list:
            n = 0
            for i in range(column, row):
                costMatrix[i][n] = block.getDeleteCost()+1
                n = n + 1
    elif row < column:
        for block in graph2.block_list:
            matrix.append(block.getDeleteCost()+1)
        for i in range(0, column-row):
            costMatrix.append(matrix)

    return costMatrix


def _build_size_matrix(graph1, graph2):
    costMatrix = []
    for graph1_block in graph1.block_list:
        unitMatrix = []
        for graph2_block in graph2.block_list:
            unitMatrix.append(graph1_block.getBlockSize() + 1)
        costMatrix.append(unitMatrix)
    #costMatrix = np.array(costMatrix) + 10

    row = len(graph1.block_list)
    column = len(graph2.block_list)
    matrix = []
    if row > column:
        for block in graph1.block_list:
            n = 0
            for i in range(column, row):
                costMatrix[i][n] = block.getDeleteCost()+1
                n = n + 1
    elif row < column:
        for block in graph2.block_list:
            matrix.append(block.getDeleteCost()+1)
        for i in range(0, column-row):
            costMatrix.append(matrix)

    return costMatrix


def graph_edit_distance(graph1, graph2):
    costMatrix = []
    if(graph1.getGraphBlocks() > 5 and graph2.getGraphBlocks() > 5):
        costMatrix = _build_cost_matrix(graph1, graph2)
    else:
        costMatrix = _build_size_matrix(graph1, graph2)

    #costMatrix = _build_cost_matrix(graph1, graph2)
    m = Munkres()
    indexes = m.compute(costMatrix)
    editDistance = 0
    for row, column in indexes:
        value = costMatrix[row][column]-1
        editDistance += value
        #print '({}, {}) -> {}'.format(row, column, value)
    return editDistance


def _ngram_matrix(set1, set2):
    matrix = []
    for ngram1 in set1:
        unitMatrix = []
        for ngram2 in set2:
            ngram_similarity = float(len(lcs(ngram1, ngram2)))/len(ngram1)
            if ngram_similarity < 0.7: ngram_similarity=0
            unitMatrix.append(100*ngram_similarity)
        matrix.append(unitMatrix)
    return matrix


def ngramset_edit_distance(set1, set2):
    matrix = _ngram_matrix(set1, set2)

    cost_matrix = make_cost_matrix(matrix, lambda cost: sys.maxint - cost)
    m = Munkres()
    indexes = m.compute(cost_matrix)
    # total = 0.0
    max_matrix = []
    for row, column in indexes:
        value = matrix[row][column]
        max_matrix.append(value)
        # total += value
    edit_distance = numpy.mean(max_matrix)
    variance = numpy.var(max_matrix)
    # print 'ngram distance ', edit_distance
    # print 'variance ', variance
    # print 'total ', total
    # edit_distance = total/len(indexes)
    return edit_distance, variance