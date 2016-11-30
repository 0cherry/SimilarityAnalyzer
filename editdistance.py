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
    cost_matrix = []
    if(graph1.getGraphBlocks() > 5 and graph2.getGraphBlocks() > 5):
        cost_matrix = _build_cost_matrix(graph1, graph2)
    else:
        cost_matrix = _build_size_matrix(graph1, graph2)

    #cost_matrix = _build_cost_matrix(graph1, graph2)
    m = Munkres()
    indexes = m.compute(cost_matrix)
    edit_distance = 0
    for row, column in indexes:
        value = cost_matrix[row][column]-1
        edit_distance += value
        #print '({}, {}) -> {}'.format(row, column, value)
    return edit_distance


def _ngram_matrix(set1, set2):
    matrix = []
    for ngram1 in set1:
        unitMatrix = []
        for ngram2 in set2:
            ngram_similarity = float(lcs(ngram1, ngram2))/len(ngram1)
            if ngram_similarity < 0.7: ngram_similarity=0
            unitMatrix.append(100*ngram_similarity)
        matrix.append(unitMatrix)
    return matrix


def ngramset_edit_distance(set1, set2):
    def get_yxgraph_distance(x, y):
        import math
        if(x == y):
            return 0
        elif(x > y):
            return math.sqrt(math.pow((x-y), 2))
        else:
            return -math.sqrt(math.pow((y-x), 2))
    matrix = _ngram_matrix(set1, set2)

    cost_matrix = make_cost_matrix(matrix, lambda cost: sys.maxint - cost)
    m = Munkres()
    indexes = m.compute(cost_matrix)
    # total = 0.0
    max_matrix = []
    xygraph_distance_list = []
    for row, column in indexes:
        value = matrix[row][column]
        max_matrix.append(value)
        xygraph_distance_list.append(get_yxgraph_distance(row, column))
        # total += value
    edit_distance = numpy.mean(max_matrix)/100
    variance = numpy.var(max_matrix)
    sim2 = _similarity(xygraph_distance_list, 2)
    sim3 = _similarity(xygraph_distance_list, 3)

    return edit_distance, variance, sim2, sim3, xygraph_distance_list


def _similarity(xygraph_distance_list, n):
    count = 0
    length = len(xygraph_distance_list)
    for i in range(length-n+1):
        n_indexes = xygraph_distance_list[i:i+n]
        sub_count = 0
        for j in range(0, n-1):
            if n_indexes[j] == n_indexes[j+1]:
                sub_count += 1
        count += sub_count / (n-1)
    similarity = float(count) / (len(xygraph_distance_list)-n+1)
    return similarity
