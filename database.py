from sqlmodel import SQLModel, create_engine, Session
from typing import Annotated
from fastapi import Depends
from models import Book, User

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

engine = create_engine(sqlite_url, echo=True)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


session_dependency = Annotated[Session, Depends(get_session)]
