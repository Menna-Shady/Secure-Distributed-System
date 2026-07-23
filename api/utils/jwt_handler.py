import jwt
import datetime
import os

SECRET = os.getenv("JWT_SECRET", "secret")

def generate_token(data):
    payload = {
        "data": data,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")