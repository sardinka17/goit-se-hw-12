from fastapi import APIRouter, HTTPException, Depends, status, Path, Query
from sqlalchemy.orm import Session

from src.database.db import get_postgres_db
from src.database.models import User
from src.repository import contacts as repository_contacts
from src.schemas.contacts import ContactModel, ContactCreate, ContactUpdate, ContactResponse
from src.services.auth import auth_service

router = APIRouter(prefix='/contacts', tags=['contacts'])


@router.get('/')
def get_all_contacts(
        offset: int = 0,
        limit: int = 50,
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_postgres_db)
) -> list[ContactModel]:
    contacts = repository_contacts.get_all_contacts(offset, limit, current_user, db)

    return contacts


@router.get('/{contact_id}')
def get_contact(
        contact_id: int = Path(ge=1),
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_postgres_db)
) -> ContactResponse:
    contact = repository_contacts.get_contact(contact_id, current_user, db)

    if not contact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Contact is not found')

    return contact


@router.post('/', status_code=status.HTTP_201_CREATED)
def create_contact(
        body: ContactCreate,
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_postgres_db)
) -> ContactResponse:
    return repository_contacts.create_contact(body, current_user, db)


@router.put('/{contact_id}')
def update_contact(
        contact_id: int,
        body: ContactUpdate,
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_postgres_db)
) -> ContactResponse:
    contact = repository_contacts.update_contact(contact_id, body, current_user, db)

    if not contact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Contact is not found')

    return contact


@router.delete('/{contact_id}', status_code=status.HTTP_204_NO_CONTENT)
def delete_contact(
        contact_id: int,
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_postgres_db)
):
    contact = repository_contacts.delete_contact(contact_id, current_user, db)

    if not contact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Contact is not found')

    return contact


@router.get('/search_by_first_name/')
def get_contact_by_first_name(
        contact_first_name: str = Query(),
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_postgres_db)
) -> ContactResponse:
    contact = repository_contacts.get_contact_by_first_name(contact_first_name, current_user, db)

    if not contact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Contact is not found')

    return contact


@router.get('/search_by_last_name/')
def get_contact_by_last_name(
        contact_last_name: str = Query(),
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_postgres_db)
) -> ContactResponse:
    contact = repository_contacts.get_contact_by_last_name(contact_last_name, current_user, db)

    if not contact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Contact is not found')

    return contact


@router.get('/search_by_email/')
def get_contact_by_email(
        contact_email: str = Query(),
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_postgres_db)
) -> ContactResponse:
    contact = repository_contacts.get_contact_by_email(contact_email, current_user, db)

    if not contact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Contact is not found')

    return contact


@router.get('/upcoming_birthdays/')
def get_contacts_upcoming_birthdays(
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_postgres_db)
):
    contacts = repository_contacts.get_contacts_upcoming_birthdays(current_user, db)

    return contacts
