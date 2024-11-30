from src.constants.http_status_code import HTTP_400_BAD_REQUEST, HTTP_409_CONFLICT, HTTP_201_CREATED, HTTP_200_OK, HTTP_401_UNAUTHORIZED
from flask import Blueprint, app, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import validators
from src.database import User, db  # Ensure User and db are imported correctly
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity

auth = Blueprint("auth", __name__, url_prefix="/api/v1/auth")

@auth.route('/register', methods=['POST'])
def register():
    # Get data from the request
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']

    # Validate password length
    if len(password) < 6:
        return jsonify({'error': "Password is too short"}), HTTP_400_BAD_REQUEST

    # Validate username length
    if len(username) < 3:
        return jsonify({'error': "Username is too short"}), HTTP_400_BAD_REQUEST

    # Validate username (should be alphanumeric and no spaces)
    if not username.isalnum() or " " in username:
        return jsonify({'error': "Username should be alphanumeric, also no spaces"}), HTTP_400_BAD_REQUEST

    # Validate email format
    if not validators.email(email):
        return jsonify({'error': "Email is not valid"}), HTTP_400_BAD_REQUEST

    # Check if the email is already taken
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({'error': "Email is taken"}), HTTP_409_CONFLICT

    # Check if the username is already taken
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'error': "Username is taken"}), HTTP_409_CONFLICT

    # Hash the password before saving
    pwd_hash = generate_password_hash(password)

    # Create a new user
    user = User(username=username, password=pwd_hash, email=email)
    
    # Add user to the database and commit the transaction
    db.session.add(user)
    db.session.commit()

    # Return a success response
    return jsonify({
        'message': "User created",
        'user': {
            'username': username,
            'email': email
        }
    }), HTTP_201_CREATED

@auth.post('/login')
def login():
    email = request.json.get('email', '')
    password = request.json.get('password', '')

    user = User.query.filter_by(email=email).first()

    if user:
        is_pass_correct = check_password_hash(user.password, password)

        if is_pass_correct:
            refresh = create_refresh_token(identity=str(user.id))
            access = create_access_token(identity=str(user.id))

            return jsonify({
                'user': {
                    'refresh': refresh,
                    'access': access,
                    'username': user.username,
                    'email': user.email
                }

            }), HTTP_200_OK

    return jsonify({'error': 'Wrong credentials'}), HTTP_401_UNAUTHORIZED

@auth.get("/me")
@jwt_required()
def me():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first() 
    return jsonify({
        'username':user.username,
        'email': user.email
    }), HTTP_200_OK

@auth.post('/token/refresh')
@jwt_required(refresh=True)

def refresh_users_token():
    identity = get_jwt_identity()
    access = create_access_token(identity=identity)

    return jsonify({
        'access': access
    }), HTTP_200_OK

