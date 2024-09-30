#!/usr/bin/python
"""sets environment variable using pydantic BaseSettings"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import EmailStr


from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    """contains all required env settings loaded from .env"""

    model_config = SettingsConfigDict(env_file="../../.env", env_file_encoding="utf-8")

    # database settings
    DB_USER: str
    DB_PASSWORD: str
    DB_NAME: str
    DB_HOST: str
    DB_PORT: str

    # JWT
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_MINUTES: int

    # email settings
    EMAIL_HOST: str
    EMAIL_PORT: str
    EMAIL_USERNAME: str
    EMAIL_PASSWORD: str
    EMAIL_FROM: EmailStr

    # aws
    # S3_BUCKET_NAME: str
    # S3_REGION: str
    # S3_ACCESS_KEY: str
    # S3_SECRET_KEY: str

    # paystack
    # PAYSTACK_SECRET_KEY: str


settings = Settings()
