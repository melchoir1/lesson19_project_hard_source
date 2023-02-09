from flask import request
from flask_restx import abort
import jwt

from helpers.constans import SECRET, ALGO

def auth_requiest(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' is not request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer')[-1]

        try:
            jwt.decode(token, SECRET, algorithms=[ALGO])
        except Exception as e:
            print(f"JWT Decode Exception: {e}")
            abort(401)
        return func(*args, **kwargs)

    return wrapper

def admin_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' is not request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer')[-1]

        try:
            user = jwt.decode(token, SECRET, algorithms=[ALGO])
            if user['role'] != 'admin':
                return 'Not admin'
        except Exception as e:
            print(f"JWT Decode Exception: {e}")
            abort(401)
        return func(*args, **kwargs)

    return wrapper