import pandas
import json
import re
import requests
import numpy

rfc1918 = re.compile('(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)')

def is_privateip(ip):
    return rfc1918.match(ip)

def csv_to_json(csvFilePath, table_no):
    # get the first gap
    gap_no = get_first_gap(csvFilePath)
    if table_no == 0:
        dataframe = pandas.read_csv(csvFilePath, nrows=(gap_no - 1), delimiter=', ')
    else:
        dataframe = pandas.read_csv(csvFilePath, skiprows=gap_no, delimiter=', ')
    return json.loads(dataframe.to_json(orient='records'))

# read CSV file, retrieves the line no. of the first gap between two tables
def get_first_gap(csvFilePath):
    # read CSV file and get retrieve the line no. of the gap between two tables
    with open(csvFilePath, encoding='UTF-8') as file:
        line_no = 1
        # skip the whitespace line
        file.readline()
        while file:
            line = file.readline()
            if line == '\n':
                break
            line_no += 1
    file.close()
    return line_no

def get_dns_response(name):
    # Fetch Google's DNS API
    api_url = 'https://dns.google/resolve'
    params = {'name': name}

    response = requests.get(api_url, params=params)
    return response.json()

# Compare array of two DNS addresses, with answers1 being response received from router, answers2 from external dns
def compare_dns(name, answers1):
    answers2 = []

    external_dns_obj = get_dns_response(name)
    for answer in external_dns_obj['Answer']:
        answers2.append(answer['data'])
    answers2.sort()

    if not numpy.array_equal(answers1, answers2):
        return answers2
    else:
        return None