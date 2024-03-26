import os
import random
import json
import sqlite3
import hashlib
import uuid

from dotenv import load_dotenv

from flask import Flask, render_template, request, abort, jsonify, g

from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VideoGrant, ChatGrant
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

load_dotenv()

twilio_account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
twilio_api_key_sid = os.environ.get('TWILIO_API_KEY_SID')
twilio_api_key_secret = os.environ.get('TWILIO_API_KEY_SECRET')
twilio_client = Client(twilio_api_key_sid, twilio_api_key_secret,
                       twilio_account_sid)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # FIXME ADD SECRET KEY!
Base = declarative_base()


######################################### GET DICTIONARY ##########################################


ADVANCED_DICT = 'dictionary/advanced_dict.json'

try:
    with open(ADVANCED_DICT, 'r') as f:
        advanced_dict = json.load(f)
except FileNotFoundError:
    advanced_dict = {}


########################################### GET WORD API ##########################################


@app.route('/get_word', methods=['GET'])
def get_word():
    russian = random.choice(list(advanced_dict.keys()))

    if len(advanced_dict[russian].split(' ')) > 1:
        english_synonyms = advanced_dict[russian].split(' ')
        english = random.choice(english_synonyms)
        return jsonify({english: russian})
    else:
        english = advanced_dict[russian]
        return jsonify({english: russian})


########################################### USER MODEL SQLALCHEMY ################################################


# class User(Base):
#     __tablename__ = 'users'
#     username = Column(String, primary_key=True)
#     password = Column(String)


########################################### SESSION MODEL SQLALCHEMY ################################################


#


########################################### DB CONNECT ################################################
########################################### WITH NO SQLALCHEMY ########################################


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('database.db')
    return db


########################################### WITH SQLALCHEMY ###########################################


# engine = create_engine('sqlite:///database.db')
# Base.metadata.create_all(engine)
# Session = sessionmaker(bind=engine)


########################################### HASH PASSWORD ################################################


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


########################################### REGISTER ################################################
########################################### WITH NO SQLALCHEMY ######################################


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not username or not password or not confirm_password:
        return jsonify({'message': 'All fields are required'}), 400

    if password != confirm_password:
        return jsonify({'message': 'Passwords do not match'}), 400

    hashed_password = hash_password(password)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    existing_user = cursor.fetchone()
    if existing_user:
        return jsonify({'message': 'Username already exists'}), 400

    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    db.commit()
    return jsonify({'message': 'User registered successfully'}), 201


########################################### WITH SQLALCHEMY ##########################################


# @app.route('/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     confirm_password = data.get('confirm_password')
#
#     if not username or not password or not confirm_password:
#         return jsonify({'message': 'All fields are required'}), 400
#
#     if password != confirm_password:
#         return jsonify({'message': 'Passwords do not match'}), 400
#
#     hashed_password = hash_password(password)
#
#     session = Session()
#     existing_user = session.query(User).filter_by(username=username).first()
#     if existing_user:
#         session.close()
#         return jsonify({'message': 'Username already exists'}), 400
#
#     new_user = User(username=username, password=hashed_password)
#     session.add(new_user)
#     session.commit()
#     session.close()
#
#     return jsonify({'message': 'User registered successfully'}), 201


########################################### LOGIN ################################################


@app.route('/login', methods=['POST'])
def temp_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'All fields are required'}), 400

    hashed_password = hash_password(password)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
    user = cursor.fetchone()


########################################### CREATE SESSION TOKEN ################################################


    if user:
        session_token = str(uuid.uuid4())
        cursor.execute("INSERT INTO sessions (username, session_token) VALUES (?, ?)", (username, session_token))
        db.commit()
        return jsonify({'message': 'Login successful', 'session_token': session_token}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401


########################################### LOGOUT ################################################


@app.route('/logout', methods=['DELETE'])
def logout():
    session_token = request.headers.get('Authorization')

    if not session_token:
        return jsonify({'message': 'Missing session token'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM sessions WHERE session_token=?", (session_token,))
    db.commit()
    return jsonify({'message': 'Logout successful'}), 200


########################################### GET PROFILE ################################################


@app.route('/profile', methods=['GET'])
def get_profile():
    session_token = request.headers.get('Authorization')

    if not session_token:
        return jsonify({'message': 'Missing session token'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM sessions WHERE session_token=?", (session_token,))
    user = cursor.fetchone()
    if user:
        return jsonify({'username': user[0]}), 200
    else:
        return jsonify({'message': 'Unauthorized'}), 401


########################################### UPDATE PROFILE ################################################


@app.route('/profile', methods=['PUT', 'PATCH'])
def update_profile():
    session_token = request.headers.get('Authorization')
    data = request.get_json()
    new_username = data.get('new_username')

    if not session_token or not new_username:
        return jsonify({'message': 'Missing session token or new username'}), 400

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT username FROM sessions WHERE session_token=?", (session_token,))
    user_row = cursor.fetchone()
    if user_row:
        old_username = user_row[0]
        cursor.execute("UPDATE users SET username=? WHERE username=?", (new_username, old_username))
        cursor.execute("UPDATE sessions SET username=? WHERE session_token=?", (new_username, session_token))
        db.commit()
        return jsonify({'message': 'Profile updated successfully'}), 200
    else:
        return jsonify({'message': 'Invalid session token'}), 401


########################################### GET ALL PARTIES ######################################


@app.route("/party", methods=["GET"])
def get_party():
    try:
        conversations = twilio_client.conversations.conversations.list()

        if not conversations:
            return jsonify({"message": "There are no parties found."}), 404

        parties_list = []
        for conversation in conversations:
            parties_list.append({
                "party_sid": conversation.sid,
                "party_name": conversation.friendly_name
            })

        return jsonify({"parties": parties_list})

    except TwilioRestException as e:
        return jsonify({"message": f"Error retrieving party: {e}"}), 500


########################################### GET PARTY BY SID ######################################


@app.route('/party/<party_sid>', methods=['GET'])
def get_party_by_sid(party_sid):
    try:
        conversation = twilio_client.conversations.conversations(party_sid).fetch()

        if not conversation:
            return jsonify({"message": f"Party with sid '{party_sid}' not found."}), 404

        conversation_data = {
            "party_sid": conversation.sid,
            "party_name": conversation.friendly_name,
        }

        return jsonify(conversation_data)

    except TwilioRestException as e:
        return jsonify({"message": f"Error retrieving party: {e}"}), 500


########################################### CREATE PARTY ################################################


@app.route('/party', methods=['POST'])
def create_party():
    try:
        data = request.get_json()
        party_name = data.get('party_name')

        party_object = twilio_client.conversations.v1.conversations.create(
            friendly_name=party_name)

        return jsonify({
            'party_sid': party_object.sid,
            'party_name': party_object.friendly_name,
            'message': 'Party created successfully'
        }), 201

    except TwilioRestException as e:
        return jsonify({"message": f"Error retrieving party: {e}"}), 500


########################################### DELETE PARTY BY SID ################################################


@app.route('/party/<party_sid>', methods=['DELETE'])
def delete_party_by_sid(party_sid):
    try:
        conversation = twilio_client.conversations.conversations(party_sid).fetch()

        if not conversation:
            return jsonify({"message": "There are no parties found."}), 404

        conversation.delete()

        return jsonify({"success": True, "message": f"The party with sid '{party_sid}' has been deleted successfully."})

    except TwilioRestException as e:
        return jsonify({"message": f"Error retrieving party: {e}"}), 500


########################################## GET MAIN PAGE #########################################


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


########################################## CREATE/GET NEW ROOM TWILIO ####################################


def get_room(name):
    for conversation in twilio_client.conversations.v1.conversations.stream():
        if conversation.friendly_name == name:
            return conversation

    return twilio_client.conversations.v1.conversations.create(
        friendly_name=name)


########################################### LOGIN TWILIO ############################################


@app.route('/login_twilio', methods=['POST'])
def login():
    username = request.get_json(force=True).get('username')
    if not username:
        abort(401)

    conversation = get_room('My Room')
    try:
        conversation.participants.create(identity=username)
    except TwilioRestException as exc:
        if exc.status != 409:
            raise

########################################## CREATE JWT TOKEN ########################################

    token = AccessToken(twilio_account_sid, twilio_api_key_sid,
                        twilio_api_key_secret, identity=username)
    token.add_grant(VideoGrant(room='My Room'))
    token.add_grant(ChatGrant(service_sid=conversation.chat_service_sid))

    return {'token': token.to_jwt().encode().decode(),
            'conversation_sid': conversation.sid}


########################################## RUN PYTHONANYWHERE SERVER ########################################


if __name__ == '__main__':
    app.run(debug=True)
