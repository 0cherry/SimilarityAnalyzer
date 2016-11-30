import pandas
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.pyplot as plot
import numpy
import csv

def readFile(filepath):
    # data [srcName, srcAddr, srcNumOfMne, dstName, dstAddr, cosine, cosineTime, mLCS, mLCSTime]
    data = pandas.read_csv(filepath)
    return data

def classifyData(data, cosine, lcs):
    # noFiltered_data = data
    total = float(data.srcName.count())
    FilteredData = data[(data.cosine >= cosine) & (data.mLCS >= lcs)]
    NotFilteredData = data[((data.cosine < cosine) | (data.mLCS < lcs))]

    true_positive = FilteredData[(FilteredData.srcName == FilteredData.dstName)]
    numOfTP = true_positive.srcName.count()
    perOfTP = numOfTP/total*100
    true_negative = NotFilteredData[(NotFilteredData.srcName != NotFilteredData.dstName)]
    numOfTN = true_negative.srcName.count()
    perOfTN = numOfTN/total*100
    false_negative = NotFilteredData[(NotFilteredData.srcName == NotFilteredData.dstName)]
    numOfFN = false_negative.srcName.count()
    perOfFN = numOfFN/total*100
    false_positive = FilteredData[(FilteredData.srcName != FilteredData.dstName)]
    numOfFP = false_positive.srcName.count()
    perOfFP = numOfFP/total*100
    # true_positive.to_csv('test\\performance\\true_positive cosine' + str(cosine) + ' lcs ' + str(lcs) + '.csv')
    # true_negative.to_csv('true_negative cosine' + str(cosine) + ' lcs ' + str(lcs) + '.csv')
    # false_negative.to_csv('test\\performance\\false_negative cosine' + str(cosine) + ' lcs ' + str(lcs) + '.csv')
    # false_positive.to_csv('test\\performance\\false_positive cosine' + str(cosine) + ' lcs ' + str(lcs) + '.csv')
    return [numOfTP, perOfTP, numOfTN, perOfTN, numOfFN, perOfFN, numOfFP, perOfFP, numOfFN+numOfFP, perOfFN + perOfFP, float(numOfTP)/(numOfTP+numOfFP), float(numOfTP)/(numOfTP+numOfFN)]
    # result = [true_positive, true_negative, false_negative, false_positive]
    # return result

def getPercentageFalseFromClassifyData(classifiedData):
    total = classifiedData[0].srcName.count() + classifiedData[1].srcName.count() + classifiedData[2].srcName.count() + classifiedData[3].srcName.count()
    false_negative, false_positive = classifiedData[2],classifiedData[3]
    percentageFN = false_negative.srcName.count()/float(total)*100
    percentageFP = false_positive.srcName.count()/float(total)*100
    return percentageFP, percentageFN

def getPointData(data):
    percentageFall = []
    percentageFP = []
    percentageF = [percentageFall, percentageFP]
    cosine_list = []
    lcs_list = []

    for i in range(12, 21, 1):
        cosine = float(i)/20
        for j in range(14, 21, 1):
            lcs = float(j)/20
            classifiedData = classifyData(data, cosine, lcs)
            percentage = getPercentageFalseFromClassifyData(classifiedData)

            cosine_list.append(cosine)
            lcs_list.append(lcs)
            percentageFall.append(percentage[0] + percentage[1])
            percentageFP.append(percentage[0])
    return cosine_list, lcs_list, percentageF

def writeAnalyzedData(data):
    with open('test\\performance\\performance.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        columns = ['cosine', 'lcs', 'numOfTP', 'perOfTP', 'numOfTN', 'perOfTN', 'numOfFN', 'perOfFN', 'numOfFP', 'perOfFP', 'numOfF', 'perOfF', 'precision', 'recall']
        writer.writerow(columns)

        for i in range(14, 21, 1):
            cosine = float(i)/20
            for j in range(14, 21, 1):
                lcs = float(j)/20
                cData = classifyData(data, cosine, lcs)
                writer.writerow([cosine, lcs, cData[0], cData[1], cData[2], cData[3], cData[4], cData[5], cData[6], cData[7], cData[8], cData[9], cData[10], cData[11]])

def makeGraph(points):
    x, y = points[0], points[1]
    z1, z2 = points[2][0], points[2][1]

    print z1
    print z2
    print 'minimum false {} cosine {} lcs {}'.format(min(z1), x[z1.index(min(z1))], y[z1.index(min(z1))])
    print 'minimum false positive {} cosine {} lcs {}'.format(min(z2), x[z2.index(min(z2))], y[z2.index(min(z2))])

    figure = plot.figure()
    ax = figure.add_subplot(111, projection='3d')
    ax.scatter(x, y, z2, c='r', marker='o')
    ax.set_xlabel('cosine')
    ax.set_ylabel('lcs')
    ax.set_zlabel('false positive percentage')

# not used
def makeLinearGraph(x_data, fp, fn):
    N = len(x_data)
    index = numpy.arange(N)
    width = 0.35

    plot.ylabel('False Percentage')
    y1 = plot.bar(index, fp, width, color='r')
    y2 = plot.bar(index, fn, width, color='y', bottom=fp)
    plot.xticks(index+width/2., x_data)
    plot.legend((y1[0], y2[0]), ('False Positive', 'False Negative'))

# not used
def makeGraphByClassifiedData(classifiedData, cosine, lcs):
    true_positive = classifiedData[0].srcName.count()
    true_negative = classifiedData[1].srcName.count()
    false_negative = classifiedData[2].srcName.count()
    false_positive= classifiedData[3].srcName.count()
    total = float(true_positive + true_negative + false_positive + false_negative)

    title = 'cosine {} lcs {}'.format(cosine, lcs)
    labels = ['true positive', 'true negative', 'false negative', 'false positive']
    ratio = [true_positive/total*100, true_negative/total*100, false_positive/total*100, false_negative/total*100]
    explode = (0.3, 0.3, 0.3, 0.3)
    #plot.pie(ratio, explode=explode, labels=labels, autopct='%.3f%%', labeldistance=1.2, startangle=90)
    plot.title(title)
    plot.ylabel('Percentage')
    plot.bar([0, 1, 2, 3], ratio, color='r')
    plot.xticks([0, 1, 2, 3], labels)

def showGraph():
    plot.show()

def run():
    filepath = 'test\\FunctionHavedName.csv'
    data = readFile(filepath)

    cosine, lcs = 0.7, 0.9
    classifiedData = classifyData(data, cosine, lcs)
    makeGraphByClassifiedData(classifiedData, cosine, lcs)
    showGraph()

def test():
    filepath = 'test\\1.0.1f+1.0.2h_report proc8 871sec size50.csv'
    data = readFile(filepath)
    # classifyData(data, 1.0, 1.0)
    writeAnalyzedData(data)

def data_analyze():
    filepath = 'test\\zlib123.dll_fninfo.json+zlib128.dll_fninfo.json_report.csv'
    data = readFile(filepath)

    for i in range(data.srcName.count()):
        function_size = len(data['xygraph_distance'][i])
        n = 3 # can be modified
        for j in range(function_size-1):
            print

if __name__ == '__main__':
    data_analyze()