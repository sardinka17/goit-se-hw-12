from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = 'postgresql+psycopg2://postgres:123456789@localhost:5432/restapi_contacts'

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_postgres_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
