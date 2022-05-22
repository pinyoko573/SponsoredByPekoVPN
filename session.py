from time import sleep
from utils import csv_to_json
from subprocess import Popen, PIPE
import signal
import os

def session_start():
    return 0
    # test = subprocess.Popen('ls')
    # test.terminate()

def get_ap_list():
    process = Popen(['airodump-ng', 'wlan0', '--output-format', 'csv', '-w', 'ap'], stdin=PIPE, stdout=PIPE)
    sleep(5)
    process.send_signal(signal.SIGINT)
    process.kill()

    ap_list = (csv_to_json('ap-01.csv', 0))
    os.remove('ap-01.csv')
    return ap_list