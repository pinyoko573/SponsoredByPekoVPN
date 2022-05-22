import pandas
import json

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