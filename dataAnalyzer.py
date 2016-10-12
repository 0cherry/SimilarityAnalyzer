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

    print FilteredData.srcName.count(), NotFilteredData.srcName.count()
    true_positive = FilteredData[(FilteredData.srcName == FilteredData.dstName)]
    false_positive = FilteredData[(FilteredData.srcName != FilteredData.dstName)]
    false_negative = NotFilteredData[(NotFilteredData.srcName == NotFilteredData.dstName)]
    true_negative = NotFilteredData[(NotFilteredData.srcName != NotFilteredData.dstName)]
    result = [true_positive, true_negative, false_negative, false_positive]
    return result

def makeGraphByClassifiedData(classifiedData, cosine, lcs):
    true_positive = classifiedData[0].srcName.count()
    true_negative = classifiedData[1].srcName.count()
    false_negative = classifiedData[2].srcName.count()
    false_positive= classifiedData[3].srcName.count()

    print true_positive, true_negative, false_negative, false_positive
    title = 'cosine {} lcs {}'.format(cosine, lcs)
    labels = ['true positive', 'true negative', 'false negative', 'false positive']
    ratio = [true_positive, true_negative, false_positive, false_negative]
    explode = (0.0, 0.0, 0.2, 0.2)
    plot.pie(ratio, explode=explode, labels=labels, autopct='%.4f%%', startangle=90)
    plot.title(title)

def showGraph():
    plot.show()

def run():
    filepath = 'test\\FunctionHavedName.csv'
    data = readFile(filepath)

    cosine, lcs = 0.7, 0.7
    classifiedData = classifyData(data, cosine, lcs)

    makeGraphByClassifiedData(classifiedData, cosine, lcs)
    showGraph()

if __name__ == '__main__':
    run()
# filtered_data.cosine.hist()
# filtered_data.plot.pie()

# notfiltered_data.to_csv('test\\notfiltered data.csv', index=False)
# filtered_data.to_csv('test\\filtered data.csv', index=False)
# sameNameFunction_data.to_csv('test\\same name function data.csv', index=False)
# sameFunction_data.to_csv('test\\same function data.csv', index=False)