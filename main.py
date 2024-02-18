from flask import request, jsonify
from . import app
import base64
import bcrypt
from models import db
from models import User
import re

def validate_user_id(user_id):
    return bool(re.match("^[a-zA-Z0-9]{6,20}$", user_id))

def validate_password(password):
    return bool(re.match("^[!-~]{8,20}$", password))

def is_user_id_taken(user_id):
    return User.query.filter_by(user_id=user_id).first() is not None

def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def authenticate_user(auth_header):
    if not auth_header:
        return None
    auth_token = auth_header.split(" ")[1]
    try:
        user_credentials = base64.b64decode(auth_token).decode('utf-8')
        user_id, password = user_credentials.split(":")
        user = User.query.filter_by(user_id=user_id).first()
        if user and bcrypt.check_password_hash(user.password, password):
            return user
    except Exception as e:
        return None

@app.route('/signup', methods=['POST'])
def create_account():
    data = request.json
    user_id = data.get('user_id')
    password = data.get('password')

    if not validate_user_id(user_id) or not validate_password(password):
        return jsonify({"message": "Account creation failed", "cause": "Invalid user_id or password format"}), 400
    
    if is_user_id_taken(user_id):
        return jsonify({"message": "Account creation failed", "cause": "already same user_id used"}), 400

    if not user_id or not password:
        return jsonify({"message": "Account creation failed", "cause": "required user_id and password"}), 400
    
    hashed_password = hash_password(password)
    new_user = User(user_id=user_id, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Account successfully created", "user": {"user_id": user_id, "nickname": user_id}}), 200

@app.route('/users/<string:user_id>', methods=['GET'])
def get_user(user_id):
    auth_header = request.headers.get('Authorizaton')
    user = authenticate_user(auth_header)

    if not user or user.user_id != user_id:
        return jsonify({"message": "Authentication Failed"}), 401
    
    target_user = User.query.filter_by(user_id=user_id).first()
    if not target_user:
        return jsonify({"message": "No User found"})
    
    nickname = target_user.nickname if target_user.nickname else target_user.user_id
    
    response_data = {
        "message": "User details by user_id",
        "user": {
            "user_id": user_id,
            "nickname": nickname
        }
    }

    if target_user.comment:
        response_data["user"]["comment"] = target_user.comment

    return jsonify(response_data), 200

@app.route('/users/<string: user_id>', methods=['PATCH'])
def update_user(user_id):
    auth_header = request.header.get('Authorization')
    user = authenticate_user(auth_header)

    if not user:
        return jsonify({"message": "Authentication Failed"}), 401
    
    if user.user_id != user_id:
        return jsonify({"message": "No Permission for Update"}), 403
    
    target_user = User.query.filter_by(user_id=user_id).first()
    if not target_user:
        return jsonify({"message": "No User found"})
    
    data = request.json
    nickname = data.get('nickname')
    comment = data.get('comment')

    if nickname is None and comment is None:
        return jsonify({"message": "User updation failed", "cause": "required nickname or comment"}), 400
    
