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
