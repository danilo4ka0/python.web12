from pydantic import BaseModel
from typing import Optional, List

class UserBase(BaseModel):
    email: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    contacts: List['Contact'] = []

    class Config:
        orm_mode = True

class ContactBase(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone: str
    birthday: str
    additional_info: Optional[str] = None

class ContactCreate(ContactBase):
    pass

class Contact(ContactBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class Login(BaseModel):
    email: str
    password: str

class Settings(BaseModel):
    authjwt_secret_key: str = "your_secret_key"
