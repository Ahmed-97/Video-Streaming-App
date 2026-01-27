from fastapi import APIRouter, Cookie, Depends, HTTPException, Response
import boto3
from backend.db.middleware.auth_middleware import get_current_user
from backend.db.models.user import User
from backend.db.db import get_db
from backend.helper.auth_helper import get_secret_hash
from backend.pydantic_models.auth_models import ConfirmSignupRequest, LoginRequest, SignupRequest
from backend.secret_keys import SecretKeys
from sqlalchemy.orm import Session


router = APIRouter()
secret_keys = SecretKeys()

COGNITO_CLIENT_ID = secret_keys.COGNITO_CLIENT_ID
COGNITO_CLIENT_SECRET = secret_keys.COGNITO_CLIENT_SECRET

cognito_client = boto3.client(
    "cognito-idp",
    region_name=secret_keys.REGION_NAME
)


@router.post("/signup")
def signup_user(
    data: SignupRequest,
    db: Session = Depends(get_db)
):

    try:
        secret_hash = get_secret_hash(
            data.email,
            COGNITO_CLIENT_ID,
            COGNITO_CLIENT_SECRET,
        )

        cognito_response = cognito_client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=data.email,
            Password=data.password,
            SecretHash=secret_hash,
            UserAttributes=[
                {"Name": "email", "Value": data.email},
                {"Name": "name", "Value": data.name}
            ],
        )

        cognito_sub = cognito_response.get("UserSub")

        if not cognito_sub:
            raise HTTPException(400, "Cognito did not return a valid user sub")

        new_user = User(
            name=data.name,
            email=data.email,
            cognito_sub=cognito_sub
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

    except Exception as e:
        raise HTTPException(400, f'Cognito signup exception: {e}')


@router.post("/login")
def login_user(data: LoginRequest, response: Response):
    try:
        secret_hash = get_secret_hash(
            data.email,
            COGNITO_CLIENT_ID,
            COGNITO_CLIENT_SECRET
        )

        cognito_response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": data.email,
                "PASSWORD": data.password,
                "SECRET_HASH": secret_hash
            }
        )

        auth_result = cognito_response.get("AuthenticationResult")

        if not auth_result:
            raise HTTPException(400, "Incorrect cognito response")

        access_token = auth_result.get("AccessToken")
        refresh_token = auth_result.get("RefreshToken")

        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=True
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True
        )

        return {"message": "User logged in successfully!"}

    except Exception as e:
        raise HTTPException(400, f'Cognito login exception: {e}')


@router.get("/me")
def protected_route(user=Depends(get_current_user)):
    return {"message": "You are authenticated", "user": user}
