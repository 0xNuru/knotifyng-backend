#!/usr/bin/env python3

from sqlalchemy import Column, ForeignKey, String

from app.models.user import User


class Admin(User):
    """admin table"""

    __tablename__ = "admin"
    id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    first_name: str = Column(String(128), nullable=False)
    last_name: str = Column(String(128), nullable=False)
    date_of_birth = Column(String, nullable=True)
    address: str = Column(String(256), nullable=True)
