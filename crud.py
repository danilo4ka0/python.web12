from sqlalchemy.orm import Session
from passlib.context import CryptContext
from . import models, schemas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user or not user.verify_password(password):
        return False
    return user

def get_contacts(db: Session, owner_email: str, skip: int = 0, limit: int = 10):
    return db.query(models.Contact).join(models.User).filter(models.User.email == owner_email).offset(skip).limit(limit).all()

def create_contact(db: Session, contact: schemas.ContactCreate, owner_email: str):
    owner = get_user_by_email(db, email=owner_email)
    db_contact = models.Contact(**contact.dict(), owner_id=owner.id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact
