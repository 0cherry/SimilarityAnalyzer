import os
import csv
import commands
import time
from datetime import datetime

ida_path = 'C:\\IDA\\'
data_file_path = "D:\\NLP\\data"


def print_time():
    print datetime.today()


def is_directory(path):
    return os.path.isdir(path)


def get_file_list(path):
    return os.listdir(path)


def is_file(path):
    return os.path.isfile(path)


def recursive_operate_ida_with_plugin(path):
    file_list = None
    if is_directory(path):
        file_list = get_file_list(path)
        path = '\\'.join([path, ''])
    else:
        # script_path = 'D:\\PackerIdentifiactor\\ida_EP_extractor.py'
        command = ida_path + 'idaq64 -A -OIDAPython:D:\SimilarityAnalyzer\ida2fninfo.py "' + path + '"'
        os.system(command)
        os.system('del "' + os.path.dirname(path) + '\\*.i64"')

    if file_list is not None:
        for f in file_list:
            recursive_operate_ida_with_plugin(path + f)


def operate_ida_with_plugin(path):
    file_list = get_file_list(path)
    path = '\\'.join([path, ''])

    if file_list is not None:
        for file in file_list:
            command = ida_path + 'idaq64 -A -OIDAPython:D:\SimilarityAnalyzer\ida2fninfo.py "' + path + file + '"'
            os.system(command)
            print '{} complete time : {}'.format(path + file, datetime.today())
            os.system('del "' + os.path.dirname(path) + '\\*.i64"')


def preprocess():
    # set header
    with open('D:\\SimilarityAnalyzer\\fninfo\\' + 'openssl_export_function.csv', 'w') as f:
        f.write('version,function,RVA(10),offset(10),code,assembly,size(byte),block,edge,call,cmp\n')


def run():
    # print_time()
    preprocess()
    operate_ida_with_plugin(data_file_path)
    print 'complete time : {}'.format(datetime.today())
    # print_time()

run()