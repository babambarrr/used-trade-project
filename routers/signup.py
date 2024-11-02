import json
import bcrypt
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
import os
import re

router = APIRouter()


@router.post("/signup")
async def signup(request: Request):
    data = await request.json()
    user_id = data.get("user_id")
    password = data.get("password")

    if not user_id or not password:
        raise HTTPException(status_code=400, detail="user_id and password are required")

    if not validate_user_id(user_id):
        raise HTTPException(status_code=400, detail="Invalid user_id format")

    sanitized_user_id = sanitize_user_id(user_id)
    file_path = get_user_file_path(sanitized_user_id)

    if user_exists(file_path):
        return JSONResponse(
            content={"message": "이미 존재하는 아이디입니다."}, status_code=400
        )

    create_user_directory()

    hashed_password = hash_password(password)
    user_data = create_user_data(
        sanitized_user_id, hashed_password, data.get("created_at")
    )

    save_user_data(file_path, user_data)

    return JSONResponse(content={"message": "회원가입 성공"}, status_code=201)


def validate_user_id(user_id):
    """
    Validate the user_id format.
    """
    return bool(re.match(r"^[a-zA-Z0-9_-]+$", user_id))


def sanitize_user_id(user_id):
    """
    Remove any characters that are not alphanumeric, underscore, or hyphen.
    """
    return re.sub(r"[^a-zA-Z0-9_-]", "", user_id)


def get_user_file_path(user_id):
    """
    Generate the file path for the user data.
    """
    base_dir = "data"
    return os.path.join(base_dir, f"{user_id}.json")


def user_exists(file_path):
    """
    Check if the user already exists.
    """
    return os.path.exists(file_path)


def create_user_directory():
    """
    Create the user data directory if it does not exist.
    """
    base_dir = "data"
    os.makedirs(base_dir, exist_ok=True)


def hash_password(password):
    """
    Hash the password using bcrypt.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_user_data(user_id, hashed_password, created_at=None):
    """
    Create the user data dictionary.
    """
    return {
        "user_id": user_id,
        "password": hashed_password,
        "point": 0,
        "created_at": created_at or datetime.now().strftime("%Y/%m/%d"),
        "registered_products": [],
        "purchased_products": [],
        "liked_products": [],
    }


def save_user_data(file_path, user_data):
    """
    Save the user data to a file.
    """
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(user_data, f)
