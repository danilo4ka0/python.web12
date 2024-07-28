import typing
from pydantic import BaseModel

import os
import sys


sys.path.append("C:/Users/demo/Desktop/python.web12")

try:
    from database import Base
    print("Импорт успешен!")
except ImportError as e:
    print(f"Ошибка импорта: {e}")


from fastapi import FastAPI, Depends, HTTPException, status
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from python.web12.database import SessionLocal, engine, Base  # Абсолютный импорт
from python.web12.models import User, Contact  # Абсолютный импорт
from python.web12.schemas import UserCreate, User, ContactCreate, Contact, Token, TokenData, Login, Settings  # Абсолютный импорт
from python.web12.crud import get_user_by_email, create_user, authenticate_user, get_contacts, create_contact  # Абсолютный импорт
from fastapi.security import OAuth2PasswordRequestForm

import os
import sys
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

logger.debug(f"Current working directory: {os.getcwd()}")
logger.debug(f"Python path: {sys.path}")

from database import Base



app = FastAPI()

Base.metadata.create_all(bind=engine)

@AuthJWT.load_config
def get_config():
    return Settings()

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post('/register', response_model=User, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=409, detail="Email already registered")
    return create_user(db=db, user=user)

@app.post('/login', response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    db_user = authenticate_user(db, email=form_data.username, password=form_data.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token = Authorize.create_access_token(subject=db_user.email)
    refresh_token = Authorize.create_refresh_token(subject=db_user.email)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post('/refresh', response_model=Token)
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_subject()
    access_token = Authorize.create_access_token(subject=current_user)
    return {"access_token": access_token, "refresh_token": Authorize.create_refresh_token(subject=current_user), "token_type": "bearer"}

@app.get('/contacts/', response_model=List[Contact])
def read_contacts(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_subject()
    return get_contacts(db, owner_email=current_user, skip=skip, limit=limit)

@app.post('/contacts/', response_model=Contact, status_code=status.HTTP_201_CREATED)
def create_contact(contact: ContactCreate, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_subject()
    return create_contact(db=db, contact=contact, owner_email=current_user)
