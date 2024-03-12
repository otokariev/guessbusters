import os
import random
import json

from dotenv import load_dotenv

from flask import Flask, render_template, request, abort, jsonify

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


######################################### GET DICTIONARY ##########################################


ADVANCED_DICT = 'dictionary/advanced_dict.json'

try:
    with open(ADVANCED_DICT, 'r') as f:
        advanced_dict = json.load(f)
except FileNotFoundError:
    advanced_dict = {}


########################################## GET MAIN PAGE #########################################


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


########################################## CREATE/GET NEW ROOM ####################################


def get_party(name):
    for conversation in twilio_client.conversations.v1.conversations.stream():
        if conversation.friendly_name == name:
            return conversation

    return twilio_client.conversations.v1.conversations.create(
        friendly_name=name)


########################################### CREATE PARTY ############################################


# @app.route('/create_party', methods=['POST'])
# def create_party(party_name):
#     for conversation in twilio_client.conversations.v1.conversations.stream():
#         if conversation.friendly_name == party_name:
#
#             # return "Party with this name already exists."
#
#     new_conversation = twilio_client.conversations.v1.conversations.create(
#         friendly_name=party_name)
#
#     return new_conversation


########################################### GET ALL PARTIES ############################################


# @app.route('/get_all_parties', methods=['GET'])
# def get_all_parties():
#     all_conversations = list(twilio_client.conversations.v1.conversations.stream())
#     if not all_conversations:
#         return "There are no parties created at this moment."
#     else:
#         return all_conversations


########################################### ADD PLAYER IN PARTY #######################################


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


########################################### LOGIN PAGE ############################################


@app.route('/login', methods=['POST'])
def login():
    username = request.get_json(force=True).get('username')
    if not username:
        abort(401)

    # conversation = create_party('My party')
    conversation = get_party('My party')
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


########################################## RUN LOCAL SERVER ########################################


# if __name__ == '__main__':
#     app.run(host='0.0.0.0')


########################################## RUN PYTHONANYWHERE SERVER ########################################


if __name__ == '__main__':
    app.run(debug=False)


########################################## TEST LOGIN LOCAL CURL ########################################


# Curl local testing login

# curl -X POST \
#   -H "Content-Type: application/json" \
#   -d '{"username":"Alex"}' \
#   http://127.0.0.1:5000/login
