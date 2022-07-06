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

    sessionclient = relationship('SessionClient', back_populates = 'session', cascade="all, delete")
    website = relationship('Website', back_populates = 'session', cascade="all, delete")
    protocol = relationship('Protocol', back_populates = 'session', cascade="all, delete")
    packettime = relationship('PacketTime', back_populates = 'session', cascade="all, delete")
    dns = relationship('DNS', back_populates = 'session', cascade="all, delete")

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
    clientarp = relationship('ClientARP', back_populates = 'sessionclient', cascade="all, delete")
    websiteclient = relationship('WebsiteClient', back_populates = 'sessionclient', cascade="all, delete")

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
    websiteclient = relationship('WebsiteClient', back_populates = 'website', cascade="all, delete")

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

class PacketTime(Base):
    __tablename__ = 'packettime'
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('session.id'))
    timestamp = Column(Integer)
    count_sent = Column(Integer)
    count_rec = Column(Integer)

    session = relationship('Session', back_populates = 'packettime')

class DNS(Base):
    __tablename__ = 'dns'
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('session.id'))
    transaction_id = Column(String)
    name = Column(String)
    is_flagged = Column(Boolean)

    session = relationship('Session', back_populates = 'dns')
    dnsanswer = relationship('DNSAnswer', back_populates = 'dns', cascade="all, delete")
    dnsanswerexternal = relationship('DNSAnswerExternal', back_populates = 'dns', cascade="all, delete")

class DNSAnswer(Base):
    __tablename__ = 'dnsanswer'
    id = Column(Integer, primary_key=True)
    dns_id = Column(Integer, ForeignKey('dns.id'))
    ip = Column(String)

    dns = relationship('DNS', back_populates = 'dnsanswer')

class DNSAnswerExternal(Base):
    __tablename__ = 'dnsanswerexternal'
    id = Column(Integer, primary_key=True)
    dns_id = Column(Integer, ForeignKey('dns.id'))
    ip = Column(String)

    dns = relationship('DNS', back_populates = 'dnsanswerexternal')