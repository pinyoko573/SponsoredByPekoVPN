from time import sleep
from utils import csv_to_json
from packet import decap
from subprocess import Popen, PIPE
from datetime import datetime
from mac_vendor_lookup import MacLookup
import signal
import os
import json

from models import Session, SessionClient
from database import db_session

def session_start(apInfo, passphrase):
    try:
        # Retrieves basic information from json and creates a newSession_obj to Session table to get id
        apInfo = json.loads(apInfo)
        ap_mac = apInfo['BSSID']
        newSession_obj = Session(mac=ap_mac, essid=apInfo['ESSID'], channel=apInfo['channel'], privacy=apInfo['Privacy'], cipher=apInfo['Cipher'], authentication=apInfo['Authentication'], passphrase=passphrase, is_active=True, date_created=datetime.now())

        db_session.add(newSession_obj)
        db_session.flush()

        # Starts capturing all the wifi packets that has communicated with AP using tcpdump
        expression = 'wlan addr1 '+ap_mac+' or wlan addr2 '+ap_mac
        filename = 'session-{}.cap'.format(newSession_obj.id)
        process = Popen(['tcpdump', '-i', 'wlan0', '-l', '-w', filename, expression], stdin=PIPE, stdout=PIPE)

        # Updates the process id in newSession_obj
        newSession_obj.processid = process.pid

        # Gets vendor information for AP
        vendor = ''
        try:
            vendor = MacLookup().lookup(ap_mac)
        except:
            vendor = 'Unknown'

        # Adds AP information to SessionClient table
        newSessionClient_obj = SessionClient(session_id = newSession_obj.id, mac = ap_mac, vendor = vendor, is_ap = True)
        db_session.add(newSessionClient_obj)
        db_session.commit()
    except Exception as e:
        print(e)
        db_session.close()
        return -1
    else:
        session_id = newSession_obj.id
        db_session.close()
        return session_id

def session_stop(session_id):
    try:
        # Get the record from session table and update the active and date_ended
        session_obj = db_session.query(Session).filter(Session.id == session_id).one()
        session_obj.is_active = False
        session_obj.date_ended = datetime.now()

        # Terminate tcpdump with the processid from session table
        os.kill(session_obj.processid, signal.SIGINT)

        # Decrypt the encrypted WPA/WPA2 packets
        filename = 'session-{}.cap'.format(session_obj.id)
        process = Popen(['airdecap-ng', '-e', session_obj.essid, '-p', session_obj.passphrase, filename], stdin=PIPE, stdout=PIPE)
        process.wait()

        # Unpacket the packet file and store information to database
        decap(session_id)
        
    except Exception as e:
        print(e)
        db_session.close()
        return False
    else:
        db_session.close()
        return True

def get_session_list():
    # Get all rows of Session table
    session_objs = db_session.query(Session).all()

    # Create an empty session_list, count the number of clients
    session_list = []
    for session_obj in session_objs:
        session = session_obj.__dict__
        del session['_sa_instance_state']

        # Count number of clients
        no_of_clients = db_session.query(SessionClient).filter(SessionClient.session_id == session['id']).count()
        session['no_of_clients'] = no_of_clients

        session_list.append(session)

    db_session.close()

    return { 'data': session_list }

def get_ap_list():
    if os.path.exists('ap-01.csv'):
        os.remove('ap-01.csv')
    # Retrieves AP channel using airodump and output into csv
    process = Popen(['airodump-ng', 'wlan0', '--output-format', 'csv', '-w', 'ap'], stdin=PIPE, stdout=PIPE)
    sleep(5)
    process.terminate()
    process.kill()
    process.wait()

    # Convert csv to json
    ap_list = csv_to_json('ap-01.csv', 0)
    for i in ap_list:
        i['ESSID'] = i['ESSID'][:-1]
        
    return { 'data': ap_list }

def get_client_list(session_id):
    if os.path.exists('ap_mac-01.csv'):
        os.remove('ap_mac-01.csv')

    # Gets the session object based on ID
    session_obj = db_session.query(Session).filter(Session.id == session_id).one()
    ap_mac = session_obj.mac

    # Gets the list of clients that are already in SessionClient table
    clients_obj = db_session.query(SessionClient).filter(SessionClient.session_id == session_id, SessionClient.is_ap == False).all()
    client_list = []
    for client_obj in clients_obj:
        client = client_obj.__dict__
        client['is_success'] = True
        client['# packets'] = '-'
        del client['_sa_instance_state']

        client_list.append(client)

    # Retrieves list of clients communicating with AP using airodump and output into csv
    process = Popen(['airodump-ng', 'wlan0', '--bssid', ap_mac, '--output-format', 'csv', '-w', 'ap_mac'], stdin=PIPE, stdout=PIPE)
    sleep(10) # Time (in seconds) to stop the AP capture
    process.terminate()
    process.kill()
    process.wait()

    # Convert csv to json and check if the client already existed in table. Else, add into client_list
    scan_client_list = csv_to_json('ap_mac-01.csv', 1)
    for scan_client in scan_client_list:
        # Check if scan_client existed in client_list using MAC
        is_existed = False
        for client in client_list:
            if client['mac'] == scan_client['Station MAC']:
                is_existed = True
                break
        
        if not is_existed:
            # Get vendor
            vendor = ''
            try:
                vendor = MacLookup().lookup(scan_client['Station MAC'])
            except:
                vendor = 'Unknown'

            scan_client['vendor'] = vendor
            scan_client['mac'] = scan_client['Station MAC']
            # scan_client['BSSID'] = scan_client['BSSID'][:-1]
            scan_client['is_success'] = False
            client_list.append(scan_client)

    # Convert csv to json
    # client_list = csv_to_json('ap_mac-01.csv', 1)
    # for client in client_list:
    #     vendor = ''
    #     try:
    #         vendor = MacLookup().lookup(client['Station MAC'])
    #     except:
    #         vendor = 'Unknown'
        
    #     client['vendor'] = vendor
    #     client['BSSID'] = client['BSSID'][:-1]


    db_session.close()
    return { 'data': client_list }

def force_eapol_handshake(session_id, client_data):
    # Retrieves AP MAC
    session_obj = db_session.query(Session).filter(Session.id == session_id).one()
    ap_mac = session_obj.mac
    client_data = json.loads(client_data)
    client_mac = client_data['Station MAC']

    # Switches channel of wireless adapter
    Popen(['iwconfig', 'wlan0', 'channel', str(session_obj.channel)], stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # Filter and capture EAPOL handshake using tcpdump
    expression = 'ether proto 0x888e and (wlan addr1 '+ap_mac+' or wlan addr1 '+client_mac+')'
    process = Popen(['tcpdump', '-i', 'wlan0', '-l', '-vvv', '-w', 'eapol.cap', expression], stdin=PIPE, stdout=PIPE, stderr=PIPE)

    Popen(['aireplay-ng', '-0', '5', '-a', ap_mac, '-c', client_mac, 'wlan0'], stdin=PIPE, stdout=PIPE, stderr=PIPE)

    sleep(15) # Time (in seconds) to stop the tcpdump
    process.send_signal(signal.SIGINT)
    (), stderr = process.communicate()
    process.terminate()
    process.kill()

    # Use string of stderr to find the number of packets captured
    stderr = stderr.decode('utf-8').split('\n')[1].split('\r')
    no_eapol_packets = int(stderr[len(stderr) - 1][0])

    print('{} eapol packets captured'.format(no_eapol_packets))
    # Only return success if number of eapol packets > 4
    # This portion needs to be replaced with pyrit
    if no_eapol_packets >= 4:
        # Adds client into SessionClient table
        newSessionClient_obj = SessionClient(session_id=session_obj.id, mac=client_mac, vendor=client_data['vendor'], is_ap=False)
        db_session.add(newSessionClient_obj)
        db_session.commit()

        db_session.close()
        return True
    else:
        db_session.close()
        return False