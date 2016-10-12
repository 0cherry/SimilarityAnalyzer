import pandas
import matplotlib.pyplot as plot

# def filtering(row, cosine, lcs):
#     def filterByFunctionName(row):
#         if row['srcName'] == row['dstName'] and row['srcName'].find("sub") < 0:
#             return 1
#         return 0
#     def filterByFunctionSize(row, threshold):
#         f1size, f2size = row['srcNumOfMne'], row['dstNumOfMne']
#         minsize, maxsize = min(f1size, f2size), max(f1size, f2size)
#         standard = minsize * threshold
#         if minsize < 5 or maxsize < 5:
#             return 0
#         if maxsize <= standard:
#             return 1
#         return 0
#     def filterByCosine(row, threshold):
#         if row['cosine'] >= threshold:
#             return 1
#         return 0
#     def filterByMnemonicLCS(row, threshold):
#         if row['mLCS'] >= threshold:
#             return 1
#         return 0
#
#     print row[row.srcName]
#     filterByFunctionName(data) and filterByFunctionSize(data, 1.1) and filterByCosine(data, cosine) and filterByMnemonicLCS(data, lcs)

def readFile(filepath):
    # data [srcName, srcAddr, srcNumOfMne, dstName, dstAddr, cosine, cosineTime, mLCS, mLCSTime]
    data = pandas.read_csv(filepath)
    return data

def filterData(data, cosine, lcs):
    # noFiltered_data = data
    FilteredData = data[(data.cosine >= cosine) & (data.mLCS >= lcs)]
    NotFilteredData = data[((data.cosine < cosine) | (data.mLCS < lcs))]

    true_positive = FilteredData[(FilteredData.srcName == FilteredData.dstName)]
    true_negative = FilteredData[(FilteredData.srcName != FilteredData.dstName)]
    false_negative = NotFilteredData[(NotFilteredData.srcName == NotFilteredData.dstName)]
    false_positive = NotFilteredData[(NotFilteredData.srcName != NotFilteredData.dstName)]
    result = [true_positive, true_negative, false_negative, false_positive]
    return result

def makeGraphByFilteredData(classifiedData, cosine, lcs):
    true_positive = classifiedData[0].srcName.count()
    true_negative = classifiedData[1].srcName.count()
    false_negative = classifiedData[2].srcName.count()
    false_positive= classifiedData[3].srcName.count()

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
    result = filterData(data, cosine, lcs)

    makeGraphByFilteredData(result, cosine, lcs)
    showGraph()

if __name__ == '__main__':
    run()
# filtered_data.cosine.hist()
# filtered_data.plot.pie()

# notfiltered_data.to_csv('test\\notfiltered data.csv', index=False)
# filtered_data.to_csv('test\\filtered data.csv', index=False)
# sameNameFunction_data.to_csv('test\\same name function data.csv', index=False)
# sameFunction_data.to_csv('test\\same function data.csv', index=False)