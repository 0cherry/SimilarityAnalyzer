import pandas
import matplotlib.pyplot as plot

def readFile(filepath):
    # data [srcName, srcAddr, srcNumOfMne, dstName, dstAddr, cosine, cosineTime, mLCS, mLCSTime]
    data = pandas.read_csv(filepath)
    return data

def classifyData(data, cosine, lcs):
    # noFiltered_data = data
    FilteredData = data[(data.cosine >= cosine) & (data.mLCS >= lcs)]
    NotFilteredData = data[((data.cosine < cosine) | (data.mLCS < lcs))]

    true_positive = FilteredData[(FilteredData.srcName == FilteredData.dstName)]
    false_positive = FilteredData[(FilteredData.srcName != FilteredData.dstName)]
    false_negative = NotFilteredData[(NotFilteredData.srcName == NotFilteredData.dstName)]
    true_negative = NotFilteredData[(NotFilteredData.srcName != NotFilteredData.dstName)]
    result = [true_positive, true_negative, false_negative, false_positive]
    return result

def getPercentageFalseFromClassifyData(classifiedData):
    total = classifiedData[0].srcName.count() + classifiedData[1].srcName.count() + classifiedData[2].srcName.count() + classifiedData[3].srcName.count()
    false_negative, false_positive = classifiedData[2],classifiedData[3]
    percentageFN = false_negative.srcName.count()/float(total)*100
    percentageFP = false_positive.srcName.count()/float(total)*100
    return [percentageFP, percentageFN]

def getFalseData(data):
    percentageFP = []
    percentageFN = []
    cosine_list = [float(i)/20 for i in range(12, 21, 1)]
    lcs_list = [float(i)/20 for i in range(14, 21, 1)]

    for cosine in cosine_list:
        for j in range(14, 21, 1):
            lcs = float(j)/20
            classifiedData = classifyData(data, cosine, lcs)
            percentage = getPercentageFalseFromClassifyData(classifiedData)
            percentageFP.append(percentage[0])
            percentageFN.append(percentage[1])
    return cosineLcsPair, percentageFP, percentageFN

def makeLinearGraph(x_data, fp, fn):
    import numpy
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
    filepath = 'test\\FunctionHavedName.csv'
    data = readFile(filepath)
    falsePercentage = getFalseData(data)
    makeLinearGraph(falsePercentage[0], falsePercentage[1], falsePercentage[2])
    showGraph()

if __name__ == '__main__':
    test()
# filtered_data.cosine.hist()
# filtered_data.plot.pie()

# notfiltered_data.to_csv('test\\notfiltered data.csv', index=False)
# filtered_data.to_csv('test\\filtered data.csv', index=False)
# sameNameFunction_data.to_csv('test\\same name function data.csv', index=False)
# sameFunction_data.to_csv('test\\same function data.csv', index=False)