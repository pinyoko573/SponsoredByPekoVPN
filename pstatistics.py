from models import ClientARP, PacketTime, Protocol, SessionClient, Website, WebsiteClient
from database import db_session

def get_protocol_list(session_id):
    protocol_list = []
    try:
        protocols_obj = db_session.query(Protocol).filter(Protocol.session_id == session_id).all()
        for protocol in protocols_obj:
            protocol = protocol.__dict__
            del protocol['_sa_instance_state']

            protocol_list.append(protocol)
    except Exception as e:
        db_session.close()
        return { 'data': protocol_list }
    else:
        db_session.close()
        return { 'data': protocol_list }

def get_timestamp_list(session_id):
    timestamp_list = []
    try:
        timestamps_obj = db_session.query(PacketTime).filter(PacketTime.session_id == session_id).all()
        for timestamp in timestamps_obj:
            timestamp = timestamp.__dict__
            del timestamp['_sa_instance_state']

            timestamp_list.append(timestamp)
    except Exception as e:
        db_session.close()
        return { 'data': timestamp_list }
    else:
        db_session.close()
        return { 'data': timestamp_list }
    
def get_clients(session_id):
    clients_list = []
    try:
        clients_obj = db_session.query(SessionClient, ClientARP.ip).join(ClientARP, ClientARP.sessionclient_id == SessionClient.id).filter(SessionClient.session_id == session_id).group_by(SessionClient.id).order_by(SessionClient.is_ap.desc()).all()
        for client in clients_obj:
            ip = client[1]
            client = client[0].__dict__
            del client['_sa_instance_state']
            client['ip'] = ip
            
            clients_list.append(client)
    except Exception as e:
        db_session.close()
        return { 'data': clients_list }
    else:
        db_session.close()
        return { 'data': clients_list }

def get_website_list(session_id):
    website_list = []
    try:
        websites_obj = db_session.query(Website, SessionClient.mac, ClientARP.ip).join(WebsiteClient, WebsiteClient.website_id == Website.id).join(SessionClient, SessionClient.id == WebsiteClient.sessionclient_id).join(ClientARP, ClientARP.sessionclient_id == SessionClient.id).filter(Website.session_id == session_id).group_by(WebsiteClient.id).order_by(WebsiteClient.website_id.asc()).all()
        # As db query has sorted by website id in asc, declare a prev website object and compare if it has same website with curr loop
        prev_website_obj = None

        # Temp variable converts website_obj to dict, and add any mac/ip that are visiting the same website as previous
        temp = None

        for website_obj in websites_obj:
            if website_obj[0] is prev_website_obj:
                temp['clients'].append({ 'mac': website_obj[1], 'ip': website_obj[2] })
            else:
                website_list.append(temp)
                website_dict = website_obj[0].__dict__
                del website_dict['_sa_instance_state']

                temp = { 'website': website_dict, 'clients': [{ 'mac': website_obj[1], 'ip': website_obj[2] }]}
                prev_website_obj = website_obj[0]

        website_list.pop(0)
    except Exception as e:
        db_session.close()
        return { 'data': website_list }
    else:
        db_session.close()
        return { 'data': website_list }

def get_arp_list(session_id):
    arp_list = []
    try:
        arps_object = db_session.query(ClientARP.ip, SessionClient.mac, SessionClient.is_ap).join(SessionClient, SessionClient.id == ClientARP.sessionclient_id).filter(SessionClient.session_id == session_id).order_by(ClientARP.sessionclient_id.asc()).all()

        for arp_object in arps_object:
            ip = arp_object[0]
            mac = arp_object[1]
            is_ap = arp_object[2]
            if not arp_list or not arp_list[-1]["mac"] == mac:
                arp_list.append({"mac": mac, "ip": [ip], "is_ap": is_ap})
            else:
                arp_list[-1]["ip"].append(ip)

    except Exception as e:
        db_session.close()
        return { 'data': arp_list }
    else:
        db_session.close()
        return { 'data': arp_list }