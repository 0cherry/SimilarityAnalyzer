#import numpy as np
from munkres import Munkres, print_matrix, make_cost_matrix
from ngram import *
import sys
import numpy

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
    # with open("matrix", 'wb') as file:
    #     file.write(str(matrix))

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

    # if edit_distance > 0.7:
    #     sim2 = _similarity(xygraph_distance_list, 2)
    #     sim3 = _similarity(xygraph_distance_list, 3)
    #     return edit_distance, variance, sim2, sim3, xygraph_distance_list

    return edit_distance, variance, None, None, xygraph_distance_list


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
