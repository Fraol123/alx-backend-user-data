#!/usr/bin/env python3
"""API session authentication module"""

from api.v1.auth.auth import Auth
from models.user import User
import uuid


class SessionAuth(Auth):
    """ Session Authentication """