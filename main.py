import os
import random
import json
import sqlite3
import hashlib
import uuid

from dotenv import load_dotenv

from flask import Flask, render_template, request, abort, jsonify, g

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
app.config['SECRET_KEY'] = 'your_secret_key'  #FIXME!


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


########################################### DB CONNECT ################################################


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('database.db')
    return db


########################################### HASH PASSWORD ################################################


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


########################################### REGISTER ################################################


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
    cursor.execute("SELECT * FROM users WHERE username=:username", {"username": username})
    existing_user = cursor.fetchone()
    if existing_user:
        return jsonify({'message': 'Username already exists'}), 400

    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    db.commit()
    return jsonify({'message': 'User registered successfully'}), 201


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


@app.route('/logout', methods=['POST'])
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
        cursor.execute("SELECT * FROM users WHERE username=?", (new_username,))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({'message': 'New username already exists'}), 400

        cursor.execute("UPDATE users SET username=? WHERE username=?", (new_username, old_username))
        cursor.execute("UPDATE sessions SET username=? WHERE session_token=?", (new_username, session_token))
        db.commit()
        return jsonify({'message': 'Profile updated successfully'}), 200
    else:
        return jsonify({'message': 'Invalid session token'}), 401


########################################### GET ALL ROOMS ################################################


@app.route('/rooms', methods=['GET'])
def get_all_rooms():
    # Здесь должна быть реализация получения списка всех комнат
    return jsonify({'message': 'List of all rooms'}), 200


########################################### CREATE ROOM ################################################


@app.route('/rooms', methods=['POST'])
def create_room():
    # Здесь должна быть реализация создания новой комнаты
    return jsonify({'message': 'Room created successfully'}), 201


########################################### DELETE ROOM ################################################


@app.route('/rooms/<int:room_id>', methods=['DELETE'])
def delete_room(room_id):
    # Здесь должна быть реализация удаления комнаты
    return jsonify({'message': 'Room deleted successfully'}), 200


########################################### CREATE PARTY TWILIO ############################################


# @app.route('/create_party', methods=['POST'])
# def create_party(party_name):
#     for conversation in twilio_client.conversations.v1.conversations.stream():
#         if conversation.friendly_name == party_name:
#             return jsonify({"error": "Party with this name already exists."}), 409
#
#     new_conversation = twilio_client.conversations.v1.conversations.create(
#         friendly_name=party_name)
#
#     room_data = {
#         "sid": new_conversation.sid,
#         "friendly_name": new_conversation.friendly_name,
#     }
#
#     return jsonify(room_data), 201


########################################### GET ALL PARTIES TWILIO ############################################


# @app.route('/get_all_parties', methods=['GET'])
# def get_all_parties():
#     all_conversations = list(twilio_client.conversations.v1.conversations.stream())
#
#     if not all_conversations:
#         return jsonify({'message': 'There are no parties created at this moment.'}), 200
#
#     party_data = []
#     for conversation in all_conversations:
#         party_data.append({
#             'sid': conversation.sid,
#             'friendly_name': conversation.friendly_name,
#         })
#
#     return jsonify({'parties': party_data}), 200


########################################### ADD PLAYER IN PARTY TWILIO #######################################


# @app.route('/add_player', methods=['POST'])
# def add_player(username, party_name):
#     if not username:
#         abort(401)
#
#     try:
#         party_name.participants.create(identity=username)
#     except TwilioRestException as exc:
#         if exc.status != 409:
#             raise


# @app.route('/join_party/<party_sid>', methods=['GET'])
# def join_party(party_sid):
#     # Здесь вы должны добавить код для подключения к выбранной комнате (party_sid)
#     return "Joining party with SID: {}".format(party_sid)


########################################## GET MAIN PAGE #########################################


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


########################################## CREATE/GET NEW ROOM TWILIO ####################################


def get_party(name):
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

    conversation = get_party('My Room')
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
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS sessions (username TEXT, session_token TEXT PRIMARY KEY)")
        db.commit()
    app.run(debug=True)
