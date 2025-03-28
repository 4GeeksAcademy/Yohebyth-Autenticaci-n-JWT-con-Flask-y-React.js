"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route('/signup', methods=['POST'])
def handle_create_user():

    body = request.get_json()
    if not body:
        return jsonify({'msj': 'body is required'}), 400  
    if 'email' not in body:
        return jsonify({'msj': 'email is required'}), 400  
    if "password" not in body:
        return jsonify({'msg':'password is required'}), 400
    exist_user = User.query.filter_by(email=body['email']).first()
    if exist_user:
         return jsonify({'msj': 'User already exist'}), 404  

    new_user = User()
    new_user.email = body["email"]
    new_user.password = body["password"]    
    new_user.is_active = True

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'id': new_user.id}), 200

@api.route('/login', methods=['POST'])
def handle_login():

    body = request.get_json()
    if not body:
        return jsonify({'msj': 'body is required'}), 400  
    if 'email' not in body:
        return jsonify({'msj': 'email is required'}), 400  
    if "password" not in body:
        return jsonify({'msg':'password is required'}), 400
    
    user = User.query.filter_by(email=body['email'], password=body['password']).first()
    if user is None:
        return jsonify({'msg': 'incorrect email or password'}), 404
    
    access_token = create_access_token(identity = user.email)

    return jsonify({'id': user.id, 'access_token': access_token}), 200

@api.route('/user', methods=['GET'])
@jwt_required()
def handle_get_user():
    
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    if user is None:
        return jsonify({'msg': 'unauthorized user'})
    user = user.serialize()

    return jsonify(user), 200