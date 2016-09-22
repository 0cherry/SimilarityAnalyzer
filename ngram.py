def compare(P, Q, threshold):
    count = 0.0
    for ngram1 in P:
        for ngram2 in Q:
            if(_match(ngram1, ngram2, threshold)):
                count += 1
                break
    similarity = (count*2)/(len(P)+len(Q))
    print 'similarity ', similarity
    return similarity


def _match(ngram1, ngram2, threshold):
    common = lcs(ngram1, ngram2)
    common_len = float(len(common))
    match_score = (common_len*2/(len(ngram1)+len(ngram2)))
    if( match_score > threshold ):
        return True
    else:
        return False


def lcs(ngram1, ngram2):
    lengths = [[0 for j in range(len(ngram2) + 1)] for i in range(len(ngram1) + 1)]
    # row 0 and column 0 are initialized to 0 already
    for i, x in enumerate(ngram1):
        for j, y in enumerate(ngram2):
            if x == y:
                lengths[i+1][j+1] = lengths[i][j] + 1
            else:
                lengths[i+1][j+1] = max(lengths[i+1][j], lengths[i][j+1])
    # read the substring out from the matrix
    result = []
    x, y = len(ngram1), len(ngram2)
    while x != 0 and y != 0:
        if lengths[x][y] == lengths[x-1][y]:
            x -= 1
        elif lengths[x][y] == lengths[x][y-1]:
            y -= 1
        else:
            assert ngram1[x - 1] == ngram2[y - 1]
            result.insert(0, ngram1[x - 1])
            x -= 1
            y -= 1
    return result

#Unused
def lcs_recursion(ngram1, ngram2):
    if not ngram1 or not ngram2:
        return ""
    x, xs, y, ys = ngram1[0], ngram1[1:], ngram2[0], ngram2[1:]
    if x == y:
        return x + lcs_recursion(xs, ys)
    else:
        return max(lcs_recursion(ngram1, ys), lcs_recursion(xs, ngram2), key=len)


class ngram(object):
    def __init__(self, mnemonics, n):
        self.n = n
        self.ngramSet = []
        for i in range(len(mnemonics)):
            mnemonic = mnemonics[i:i+n]
            if len(mnemonic) != n:
                continue
            # delete duplicate n-gram
            # if self.ngramSet.__contains__(mnemonic):
            #     continue
            self.ngramSet.append(mnemonic)