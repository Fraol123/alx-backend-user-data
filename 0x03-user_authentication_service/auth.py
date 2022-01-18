#!/usr/bin/env python3
""" Authentication"""

from bcrypt import hashpw, gensalt, checkpw
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from uuid import uuid4
from typing import Union

def _hash_password(password: str) -> str:
    """ Takes in string arg, converts to unicode Returns
    salted, hashed pswd as bytesstring"""
    return hashpw(password.encode('utf-8'), gensalt())

from db import DB


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers and returns a new user if email isn't listed"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """ Checks if user pswd is valid, locating by email """
        try:
            found_user = self._db.find_user_by(email=email)
            return checkpw(
                password.encode('utf-8'),
                found_user.hashed_password
            )
        except NoResultFound:
            return False
