# FastAPI Server
import base64
import hmac
import hashlib
import json
from signal import valid_signals
from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response
from pydantic import UrlSchemePermittedError


app = FastAPI()

SECRET_KEY = "8cfb5b6d5513f77c780589a1d33d84d24026ea7d46ebbc70ba6c1734b39e39f4"
PASSWORD_SALT = "2f390802bfee582fbe8e1192cd7ed2828b617fc06f4b859a4376bbdb12d9551b"


def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_sign_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256( (password + PASSWORD_SALT).encode() )\
        .hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash

users = {
    "alexey@user.com": {
        "name": "Алексей",
        "password": "0bee971758ea934a5ca493b4dd9b7b5ef65cc73183384ab0fe3c356303192faf",
        "balance": 100_000
    },
    "petr@user.com": {
        "name": "Петр",
        "password": "821c23a42668a861be26c5a95fb91cb8865a2fbe006de7a70d18056a67716801",
        "balance": 555_555
    }
}

@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
        if not username:
            return Response(login_page , media_type="text/html")
        valid_username = get_username_from_sign_string(username)
        if not valid_username:
            response = Response(login_page , media_type="text/html")
            response.delete_cookie(key="username")
            return response

        try:
            user = users[valid_username]
        except KeyError:
            response = Response(login_page, media_type="text/html")
            response.delete_cookie(key="username")
            return response
        return Response(
            f"Привет, {users[valid_username]['name']}!<br />"
            f"Баланс: {users[valid_username]['balance']}"
            , media_type="text/html")

@app.post("/login")
def process_login_page(data: dict = Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю!"
            }), 
            media_type="application/json")
    
    response = Response(
        json.dumps({
            "success": True,
            "message": f"Привет, {user['name']}!<br />Баланс: {user['balance']}"
        }),
        f"Привет: {user['name']}!<br />Баланс: {user['balance']}",
        media_type='application/json')

    cookie_value = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)
    response.set_cookie(key="username", value=username)
    return response
