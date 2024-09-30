#!/usr/bin/env python3

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import EmailStr
from sqlalchemy.orm import Session

from app.engine.load import load
from app.config.config import settings
from app.models.admin import Admin
from app.models.user import User
from app.schema.auth import Token
from app.utils.auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    set_access_cookies,
    delete_access_cookies,
)
from app.utils.auth import send_verification_mail, verify_token


router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/token")
def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(load),
) -> Token:
    """
    Login endpoint.

    This endpoint authenticates a user using their username and password.
    If the credentials are valid, it generates an access token and sets it as a cookie in the response.

    Parameters:
    - response (Response): The FastAPI response object.
    - form_data (OAuth2PasswordRequestForm): The form data containing the username and password.
    - db (Session): The database session.

    Returns:
    - Token: A Token object containing the access token and token type.

    Raises:
    - HTTPException: If the username or password is incorrect.
    """
    user = authenticate_user(form_data.username.strip().lower(), form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=[{"msg": "Incorrect username or password"}],
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=[{"msg": "Please verify your email address first"}],
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role}, expires_delta=access_token_expires
    )
    set_access_cookies(access_token, response)
    return Token(access_token=access_token, token_type="bearer", role=user.role)


@router.get("/verify_email/{token}")
def verify_email(token: str, db: Session = Depends(load)):
    result = verify_token(token)

    if not result:

        # to do remove user details if existing
        # call the function that cleans in async way
        # clean_db()
        # token has expired
        return RedirectResponse(
            url="https://support.image-line.com/innovaeditor/assets/reg%20fail.jpg"
        )
    else:
        email = result["email"]
        user = db.query_eng(User).filter(User.email == email).first()
        if user is None:
            return RedirectResponse(
                url="https://support.image-line.com/innovaeditor/assets/reg%20fail.jpg"
            )
        user.is_verified = True
        db.update(user)

    return RedirectResponse(
        url="https://miro.medium.com/v2/resize:fit:459/0*U6n0FSc-IU_yeagC.png"
    )


@router.get("/resened_verification_mail")
async def resend_verification_mail(
    http_request: Request, email: EmailStr, db: Session = Depends(load)
):
    """
    Resend verification email endpoint.

    This endpoint sends a verification email to the user's registered email address.
    It uses the provided user object to retrieve the email address.

    Parameters:
    - http_request (Request): The FastAPI request object.
    - user (ShowUser): The current user object. This is obtained using the `get_current_user` dependency.

    Raises:
    - HTTPException: If the email sending fails.
    """
    user = db.query_eng(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=[{"msg": "User not found."}]
        )

    admin = db.query_eng(Admin).filter(Admin.id == user.id).first()
    message = await send_verification_mail(user.email, http_request, admin)

    return {"message": message}


@router.post("/logout")
def logout(response: Response):
    """
    Logout endpoint.

    This endpoint clears the access cookies and returns a success message.

    Parameters:
    - response (Response): The FastAPI response object.

    Returns:
    - dict: A dictionary containing a success message.
    """
    # Clear access cookies
    delete_access_cookies(response)

    # Return a success message
    return {"detail": "Logged out successfully"}


@router.get("/me/")
def me(user: User = Depends(get_current_user)):
    return user
