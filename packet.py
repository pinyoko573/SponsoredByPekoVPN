from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR, DNSRR
from scapy.layers.inet import *
import cryptography

from utils import compare_dns, get_dns_response, is_privateip

from models import ClientARP, SessionClient, Website, Protocol, WebsiteClient, PacketTime, DNS, DNSAnswer, DNSAnswerExternal
from database import db_session

from mac_vendor_lookup import MacLookup

load_layer('tls')

# variable to store list of hostnames and clients who visited website to prevent duplicates
clients_list = {}
website_list = {}
protocol_list = {}
dns_list = {}
packets_sent_client_list = {}
packets_rec_client_list = {}
packets_sent_time_list = [0]
packets_rec_time_list = [0]

def decap(session_id):
    # Retrieve all the clients, store the MAC address and sessionclient_id on a dictionary
    try:
        sessionClient_objs = db_session.query(SessionClient).filter(SessionClient.session_id == session_id).all()
        # If there are no clients being captured
        if len(sessionClient_objs) <= 1:
            return

        for sessionClient_obj in sessionClient_objs:
            # Decapitalize mac address as scapy reads it in lower case
            clients_list[sessionClient_obj.mac.lower()] = sessionClient_obj.id
    except Exception as e:
        print(e)
        return

    # Loops every frame and extract out information
    packet_counter = 0
    filename = 'output/session-{}-dec.cap'.format(session_id)

    # Get the starting timestamp of the packet. Number of packets is counted every minute
    start_timestamp = PcapReader(filename).read_packet(0).time
    next_timestamp = start_timestamp + 60
    min_count = 0

    for packet in PcapReader(filename):
        try:
            # Gets the type of protocol through the packet's layers
            protocol_type = get_protocol(get_packet_layers(packet))

            # Counts type of protocol in a list
            if protocol_type in protocol_list:
                protocol_list[protocol_type] += 1
            else:
                protocol_list[protocol_type] = 1

            # If protocol=ARP, store IP on ClientARP table through replies
            if protocol_type == 'ARP':
                arp_dump(session_id, packet)
            # If protocol=DNS, store DNS record on DNS table through Resource records packet
            elif protocol_type == 'DNS':
                dns_dump(packet)
            # If protocol=HTTP 1 or TLS, store website info on Website table
            elif protocol_type == 'HTTP 1' or protocol_type == 'TLS':
                website_dump(packet)

            # If time of packet is passed by a minute, append new array
            if not (packet.time < next_timestamp):
                next_timestamp += 60 # next_timestamp + 1 minute
                packets_sent_time_list.append(0)
                packets_rec_time_list.append(0)
                min_count += 1

            # Counts the number of packets sent/received by a client
            # In the IP layer, if source is private IP -> client sends the packet
            if is_privateip(packet[IP].src):
                packets_sent_time_list[min_count] += 1

                if packet[Ether].src in packets_sent_client_list:
                    packets_sent_client_list[packet[Ether].src] += 1
                else:
                    packets_sent_client_list[packet[Ether].src] = 1
            # In the IP layer, if dst is private IP -> client receives the packet
            if is_privateip(packet[IP].dst):
                packets_rec_time_list[min_count] += 1

                if packet[Ether].dst in packets_rec_client_list:
                    packets_rec_client_list[packet[Ether].dst] += 1
                else:
                    packets_rec_client_list[packet[Ether].dst] = 1
        except:
            pass

        packet_counter += 1

    # Store protocol in protocol table, website in website and websiteclients table
    protocol_dump(session_id)
    website_insert(session_id)
    dns_insert(session_id)
    sent_rec_packets_insert()
    timestamp_insert(session_id, start_timestamp, min_count)

    db_session.close()

def get_packet_layers(packet):
    layer_list = []
    layer_count = 0
    while True:
        layer = packet.getlayer(layer_count)
        if layer is None:
            break
        layer_list.append(layer.name)
        layer_count += 1

    return layer_list

# There is no method that could get the exact protocol shown in wireshark, this is a quickfix to solution
def get_protocol(layer_list):
    if 'IP' in layer_list[1]:
        if layer_list[2] == ('TCP') or layer_list[2] == ('UDP'):
            if layer_list[3] is Empty or layer_list[3] == 'Raw' or layer_list[3] == 'Encrypted Content' or layer_list[3] == 'Padding' or 'Router' in layer_list[3]:
                return layer_list[2].split()[0]
            else:
                if layer_list[3] == 'NTPHeader':
                    return 'NTP'
                else:
                    return layer_list[3]
        else:
            return layer_list[2].split()[0]
    else:
        return layer_list[1]

def arp_dump(session_id, packet):
    layer = packet.getlayer(scapy.layers.l2.ARP)
    # If packet is ARP reply
    if layer.op == 2:
        # Get id of sessionclient based on MAC and session_id
        mac = layer.hwsrc
        ip = layer.psrc        
        # If id of sessionclient and ip is already in table, do not insert
        clientarp_count = db_session.query(ClientARP).filter(ClientARP.sessionclient_id == clients_list[mac], ClientARP.ip == ip).count()
        if not clientarp_count == 1:
            newClientArp_obj = ClientARP(sessionclient_id = clients_list[mac], ip = ip)
            db_session.add(newClientArp_obj)
            db_session.commit()

def website_dump(packet):
    # Inserts each website into the website list which will be used to store in database later
    is_https = False
    hostname = None
    # If the packet doesnt have httprequest or TLSclienthello layer, skip
    if packet.haslayer(HTTPRequest):
        layer = packet.getlayer(HTTPRequest)
        hostname = layer.Host.decode('utf-8')
    elif packet.haslayer(scapy.layers.tls.handshake.TLSClientHello):
        is_https = True
        layer = packet.getlayer(scapy.layers.tls.extensions.ServerName)
        hostname = layer.servername.decode('utf-8')
    else:
        return

    # Get the client id from mac address
    client_mac = packet[Ether].src
    
    # Check if the website and client id is included in website_list
    if hostname not in website_list:
        website_list[hostname] = { 'is_https': is_https, 'clients' : [] }
    
    if website_list[hostname]['clients'].count(clients_list[client_mac]) == 0:
        website_list[hostname]['clients'].append(clients_list[client_mac])

def website_insert(session_id):
    # Inserts every website found from the packet into the database
    for website in website_list.keys():
        newWebsite_obj = Website(session_id = session_id, hostname = website, is_https = website_list[website]['is_https'])
        db_session.add(newWebsite_obj)
        db_session.flush()

        for client in website_list[website]['clients']:
            newWebsiteClient_obj = WebsiteClient(website_id = newWebsite_obj.id, sessionclient_id = client)
            db_session.add(newWebsiteClient_obj)
    
    db_session.commit()

def protocol_dump(session_id):
    # Inserts the protocols and count found from the packet into the database
    for protocol in protocol_list.keys():
        newProtocol_obj = Protocol(session_id = session_id, type = protocol, count = protocol_list[protocol])
        db_session.add(newProtocol_obj)
    db_session.commit()

def sent_rec_packets_insert():
    # Inserts the number of sent and received packets for each client into the database
    for client in clients_list:
        sessionClient_obj = db_session.query(SessionClient).filter(SessionClient.id == clients_list[client]).one()
        sessionClient_obj.packets_sent = packets_sent_client_list[client]
        sessionClient_obj.packets_rec = packets_rec_client_list[client]
    db_session.commit()

def timestamp_insert(session_id, start_timestamp, min_count):
    # Inserts the number of sent and received packets per minute into database 
    timestamp = start_timestamp
    for min in range(min_count + 1):
        # sent
        newPacketTimeSent_obj = PacketTime(session_id = session_id, timestamp = int(timestamp), count_sent = packets_sent_time_list[min], count_rec = packets_rec_time_list[min])
        db_session.add(newPacketTimeSent_obj)

        timestamp += 60 # 1 minute
    db_session.commit()

def dns_dump(packet):
    # For DNS we only capture RR as it only contains the important info
    # note: DOES NOT WORK ON RECURSIVE DNS
    if packet.haslayer(scapy.layers.dns.DNSRR):
        # We only accept 1 DNS question as this is a standard
        name = packet[DNSQR][0].qname.decode('utf-8')
        transaction_id = packet[scapy.layers.dns.DNS].id
        # If (name+transaction_id) is already in dns_list, ignore it as it may send multiple response if tcp doesnt respond
        if str(name)+str(transaction_id) not in dns_list:
            dns = { 'name': name, 'transaction_id': hex(transaction_id) }
            rr_layercount = packet[scapy.layers.dns.DNS].ancount

            # DNSRR, containing the IP addresses for DNS
            answers = []
            for i in range(rr_layercount):
                answers.append(packet[DNSRR][i].rdata)
            answers.sort() # sort for comparison
            dns['answers'] = answers

            # DNS comparison
            externaldns_answers = compare_dns(name, answers)
            if externaldns_answers is None:
                dns['is_flagged'] = False
            else:
                dns['external_answers'] = externaldns_answers
                dns['is_flagged'] = True

            # store object into dns list
            dns_list[str(name)+str(transaction_id)] = dns

def dns_insert(session_id):
    # Insert every DNS record from dns_list into database
    for dns_obj in dns_list.keys():
        newDNS_obj = DNS(session_id = session_id, transaction_id = dns_list[dns_obj]['transaction_id'], name = dns_list[dns_obj]['name'], is_flagged = dns_list[dns_obj]['is_flagged'])
        db_session.add(newDNS_obj)
        db_session.flush()

        for answer in dns_list[dns_obj]['answers']:
            newDNSAnswer_obj = DNSAnswer(dns_id = newDNS_obj.id, ip = answer)
            db_session.add(newDNSAnswer_obj)

        if 'external_answers' in dns_list[dns_obj]:
            for answer in dns_list[dns_obj]['external_answers']:
                newExternalDNSAnswer_obj = DNSAnswerExternal(dns_id = newDNS_obj.id, ip = answer)
                db_session.add(newExternalDNSAnswer_obj)

    db_session.commit()

def scan_macadress(session_id):
    # Scans the entire packets and collects all MAC addresses
    filename = 'session-{}-dec.cap'.format(session_id)

    clients_list = {}

    for packet in PcapReader(filename):
        sent_mac = packet[Ether].src.upper()
        if sent_mac not in clients_list:
            clients_list[sent_mac] = None

    # Gets the vendor for every mac address and add each client into SessionClient table
    for mac in clients_list.keys():
        vendor = ''
        try:
            vendor = MacLookup().lookup(mac)
        except:
            vendor = 'Unknown'

        newSessionClient_obj = SessionClient(session_id=session_id, mac=mac, vendor=vendor, is_ap=False)
        db_session.add(newSessionClient_obj)

    db_session.commit()
    db_session.close()