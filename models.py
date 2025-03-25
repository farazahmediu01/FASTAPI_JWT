from sqlmodel import Field, SQLModel
from datetime import date
from enum import Enum
from typing import Literal


class Book(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    title: str
    publisher: str
    publication_date: date
    page_count: int
    language: str


class BookReadModel(SQLModel):
    id: int
    title: str
    publisher: str
    publication_date: date
    page_count: int
    language: str


class BookCreateModel(SQLModel):
    title: str
    publisher: str
    publication_date: date
    page_count: int
    language: str


class BookUpdateModel(SQLModel):
    title: str | None = None
    publisher: str | None = None
    publication_date: date | None = None
    page_count: int | None = None
    language: str | None = None


# --- User Model---


class Role(Enum):
    USER = "USER"
    ADMIN = "ADMIN"
    GUEST = "GUEST"


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    password: str = Field(max_length=60, index=True)
    role: Role = Field(default=Role.USER, index=True)


class CreateUser(SQLModel):
    username: str
    password: str


# --- JWT Token Model ---


class Token(SQLModel):
    access_token: str
    token_type: Literal["bearer"]


# Payload
class TokenData(SQLModel):
    username: str
    exp: int
    role: Role | None = None
    sub: str | None = None
