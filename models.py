from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class Session(Base):
    __tablename__ = 'session'
    id = Column(Integer, primary_key=True)
    mac = Column(String)
    essid = Column(String)
    channel = Column(Integer)
    cipher = Column(String)
    authentication = Column(String)
    passphrase = Column(String)
    is_active = Column(Boolean)
    date_created = Column(DateTime)
    date_ended = Column(DateTime)

    sessionclient = relationship('SessionClient', back_populates = 'session')
    packet = relationship('Packet', back_populates = 'session')

class SessionClient(Base):
    __tablename__ = 'sessionclient'
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('session.id'))
    mac = Column(String)
    ip = Column(String)
    vendor = Column(String)
    is_ap = Column(Boolean)

    session = relationship('Session', back_populates = 'sessionclient')

class Packet(Base):
    __tablename__ = 'packet'
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('session.id'))
    source_ip = Column(String)
    destination_ip = Column(String)
    protocol = Column(String)
    length = Column(Integer)

    session = relationship('Session', back_populates = 'packet')
    website = relationship('Website', back_populates = 'packet', uselist = False)

class Website(Base):
    __tablename__ = 'website'
    id = Column(Integer, primary_key=True)
    packet_id = Column(Integer, ForeignKey('packet.id'))
    hostname = Column(String)
    is_https = Column(Integer)

    packet = relationship('Packet', back_populates = 'website')

