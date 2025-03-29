from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import jwt, JWTError
from sqlmodel import Session, select

from database import session_dependency, create_db_and_tables, engine
from models import User, CreateUser, Token, TokenData, Role

# Configuration
SECRET_KEY = "3d9862ee148b7256adac27cf397169b71124611dfaa319c3abea91f216ed17b3"
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 5

# Tools
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")  # get token from request headers.

# Setup FastAPI app and database
app = FastAPI()
create_db_and_tables()


# --- Helper Functions ---

"""Turn a plain password into a secure hash."""
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


"""Check if a plain password matches a hashed one."""
def check_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


"""Look up a user in the database by their username."""
def find_user_by_username(username: str) -> User:
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        user = session.exec(statement).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user


"""Check if a username and password are valid."""
def verify_user(username: str, password: str) -> User:
    user = find_user_by_username(username)
    if not check_password(password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect password")
    return user


# --- JWT Functions ---

def create_token(
    data: dict,
    role: Role = Role.USER,
    expires_in_minutes: int = TOKEN_EXPIRE_MINUTES,
) -> Token:
    """Create a JWT access token with an expiration time"""
    payload = data.copy()

    expire_time = datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
    payload["exp"] = expire_time

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM) 
    return Token(access_token=token, token_type="bearer")


def decode_token(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_data = TokenData.model_validate(payload)  # Validate the token data
        user = find_user_by_username(token_data.username)
        return user

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate crendentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# --- Endpoints ---

"""Issue a token if username and password are correct."""
@app.post("/login")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = verify_user(form_data.username, form_data.password)
    token = create_token({"username": user.username})
    return token
    # return Token(access_token=token, token_type="bearer")


"""Let a user into the secret room if their token is valid."""
@app.get("/secret-room")  # VIP
async def secret_room(user: Annotated[User, Depends(decode_token)]):
    return {"message": f"{user.username.title()} is Now in the Secret Room"}


"""Register New User."""
@app.post("/users/", response_model=User)
async def create_user(new_user: CreateUser, session: session_dependency):
    query = select(User).where(User.username == new_user.username)
    existing_user = session.exec(query).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed_password = hash_password(new_user.password)
    db_user = User(username=new_user.username, password=hashed_password)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

