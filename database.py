from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# Database connection
engine = create_engine('sqlite:///database.db', echo=True)
session = sessionmaker(bind=engine)
db_session = session()
Base = declarative_base()