from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class Session(Base):
    __tablename__ = 'session'
    id = Column(Integer, primary_key=True)
    mac = Column(String)
    essid = Column(String)
    channel = Column(Integer)
    privacy = Column(String)
    cipher = Column(String)
    authentication = Column(String)
    passphrase = Column(String)
    processid = Column(Integer)
    is_active = Column(Boolean)
    date_created = Column(DateTime)
    date_ended = Column(DateTime)

    sessionclient = relationship('SessionClient', back_populates = 'session')
    website = relationship('Website', back_populates = 'session')
    protocol = relationship('Protocol', back_populates = 'session')
    externalip = relationship('ExternalIP', back_populates = 'session')

class SessionClient(Base):
    __tablename__ = 'sessionclient'
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('session.id'))
    mac = Column(String)
    vendor = Column(String)
    is_ap = Column(Boolean)
    packets_sent = Column(Integer)
    packets_rec = Column(Integer)

    session = relationship('Session', back_populates = 'sessionclient')
    clientarp = relationship('ClientARP', back_populates = 'sessionclient')
    websiteclient = relationship('WebsiteClient', back_populates = 'sessionclient')
    externalipclient = relationship('ExternalIPClient', back_populates = 'sessionclient')

class ClientARP(Base):
    __tablename__ = 'clientarp'
    id = Column(Integer, primary_key=True)
    sessionclient_id = Column(Integer, ForeignKey('sessionclient.id'))
    ip = Column(String)

    sessionclient = relationship('SessionClient', back_populates = 'clientarp')

class Website(Base):
    __tablename__ = 'website'
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('session.id'))
    hostname = Column(String)
    is_https = Column(Integer)

    session = relationship('Session', back_populates = 'website')
    websiteclient = relationship('WebsiteClient', back_populates = 'website')

class WebsiteClient(Base):
    __tablename__ = 'websiteclient'
    id = Column(Integer, primary_key=True)
    website_id = Column(Integer, ForeignKey('website.id'))
    sessionclient_id = Column(Integer, ForeignKey('sessionclient.id'))

    website = relationship('Website', back_populates = 'websiteclient')
    sessionclient = relationship('SessionClient', back_populates = 'websiteclient')

class Protocol(Base):
    __tablename__ = 'protocol'
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('session.id'))
    type = Column(String)
    count = Column(Integer)

    session = relationship('Session', back_populates = 'protocol')

class ExternalIP(Base):
    __tablename__ = 'externalip'
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('session.id'))
    external_ip = Column(String)

    session = relationship('Session', back_populates = 'externalip')
    externalipclient = relationship('ExternalIPClient', back_populates = 'externalip')

class ExternalIPClient(Base):
    __tablename__ = 'externalipclient'
    id = Column(Integer, primary_key=True)
    sessionclient_id = Column(Integer, ForeignKey('sessionclient.id'))
    externalip_id = Column(Integer, ForeignKey('externalip.id'))
    count = Column(Integer)

    externalip = relationship('ExternalIP', back_populates = 'externalipclient')
    sessionclient = relationship('SessionClient', back_populates = 'externalipclient')

# class DNS(Base):
#     __tablename__ = 'dns'
#     id = Column(Integer, primary_key=True)
#     transaction_id = Column(String)
#     hostname = Column(String)
#     req_packet_id = Column(Integer, ForeignKey('packet.id'))
#     res_packet_id = Column(Integer, ForeignKey('packet.id'))
#     is_flagged = Column(Boolean)

#     packet = relationship('Packet', back_populates='dns')
