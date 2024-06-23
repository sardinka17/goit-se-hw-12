from fastapi import APIRouter, HTTPException, Depends, Security, status
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from src.database.db import get_postgres_db
from src.repository import users as repository_users
from src.schemas.users import UserModel, UserResponse, TokenModel
from src.services.auth import auth_service

router = APIRouter(prefix='/auth', tags=['auth'])
security = HTTPBearer()


@router.post('/signup', response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def signup(body: UserModel, db: Session = Depends(get_postgres_db)):
    exist_user = repository_users.get_user_by_email(body.email, db)

    if exist_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Account already exists')

    body.password = auth_service.get_password_hash(body.password)
    new_user = repository_users.create_user(body, db)

    return {'user': new_user, 'detail': "User successfully created"}


@router.post('/login', response_model=TokenModel)
def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_postgres_db)):
    user = repository_users.get_user_by_email(body.username, db)

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid email or password')

    if not auth_service.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid email or password')

    access_token = auth_service.create_access_token(data={'sub': user.email})
    refresh_token = auth_service.create_refresh_token(data={'sub': user.email})
    repository_users.update_token(user, refresh_token, db)

    return {'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'bearer'}


@router.get('/refresh_token', response_model=TokenModel)
def refresh_token(
        credentials: HTTPAuthorizationCredentials = Security(security),
        db: Session = Depends(get_postgres_db)
):
    token = credentials.credentials
    email = auth_service.decode_refresh_token(token)
    user = repository_users.get_user_by_email(email, db)

    if user.refresh_token != token:
        repository_users.update_token(user, None, db)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid refresh token')

    access_token = auth_service.create_access_token(data={'sub': email})
    refresh_token = auth_service.create_refresh_token(data={'sub': email})
    repository_users.update_token(user, refresh_token, db)

    return {'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'bearer'}
