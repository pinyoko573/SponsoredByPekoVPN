from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import *
import cryptography

from models import ClientARP, SessionClient, Website, Protocol, WebsiteClient
from database import db_session

load_layer('tls')

# variable to store list of hostnames and clients who visited website to prevent duplicates
website_data = {}
protocol_list = {}

def decap(session_id):
    # Loops every frame and extract out information
    packet_counter = 0
    for packet in PcapReader('sample-dec.cap'):
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
            # If protocol=HTTP 1 or TLS, store website info on Website table
            elif protocol_type == 'HTTP 1' or protocol_type == 'TLS':
                website_dump(session_id, packet)
        except:
            pass

        packet_counter += 1

    # Store protocol in protocol table, website in website and websiteclients table
    protocol_dump(session_id)
    website_save(session_id)

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
        sessionClient_obj = db_session.query(SessionClient).filter(SessionClient.session_id == session_id, SessionClient.mac == mac).one()
        
        # If id of sessionclient and ip is already in table, do not insert
        clientarp_count = db_session.query(ClientARP).filter(ClientARP.sessionclient_id == sessionClient_obj.id, ClientARP.ip == ip).count()
        if not clientarp_count == 1:
            newClientArp_obj = ClientARP(sessionclient_id = sessionClient_obj.id, ip = ip)
            db_session.add(newClientArp_obj)
            db_session.commit()

def website_dump(session_id, packet):
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
    sessionClient_obj = db_session.query(SessionClient).filter(SessionClient.session_id == session_id, SessionClient.mac == client_mac).one()
    
    # Check if the website and client id is included in website_list
    if hostname not in website_data:
        website_data[hostname] = { 'is_https': is_https, 'clients' : [] }
    
    if website_data[hostname]['clients'].count(sessionClient_obj.id) == 0:
        website_data[hostname]['clients'].append(sessionClient_obj.id)

def website_save(session_id):
    for website in website_data.keys():
        newWebsite_obj = Website(session_id = session_id, hostname = website, is_https = website_data[website]['is_https'])
        db_session.add(newWebsite_obj)
        db_session.flush()

        for client in website_data[website]['clients']:
            newWebsiteClient_obj = WebsiteClient(website_id = newWebsite_obj.id, sessionclient_id = client)
            db_session.add(newWebsiteClient_obj)
    
    db_session.commit()

def protocol_dump(session_id):
    for protocol in protocol_list.keys():
        newProtocol_obj = Protocol(session_id = session_id, type = protocol, count = protocol_list[protocol])
        db_session.add(newProtocol_obj)
    db_session.commit()

decap(1)