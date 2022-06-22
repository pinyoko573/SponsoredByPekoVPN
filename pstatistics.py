from models import PacketTime, Protocol
from database import db_session

def get_protocol_list(session_id):
    protocol_list = []
    try:
        protocols_obj = db_session.query(Protocol).filter(Protocol.session_id == session_id).all()
        for protocol in protocols_obj:
            protocol = protocol.__dict__
            del protocol['_sa_instance_state']

            protocol_list.append(protocol)
        db_session.close()
    except Exception as e:
        return { 'data': protocol_list }
    else:
        return { 'data': protocol_list }

def get_timestamp_list(session_id):
    timestamp_list = []
    try:
        timestamps_obj = db_session.query(PacketTime).filter(PacketTime.session_id == session_id).all()
        for timestamp in timestamps_obj:
            timestamp = timestamp.__dict__
            del timestamp['_sa_instance_state']

            timestamp_list.append(timestamp)
        db_session.close()
    except Exception as e:
        return { 'data': timestamp_list }
    else:
        return { 'data': timestamp_list }