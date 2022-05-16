import json
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
import hashlib

app = Flask(__name__)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})  # 모든 origin 허용

client = MongoClient('localhost', 27017)

db = client.dbturtlegram


@app.route("/")
def hello_word():
    return jsonify({'message': 'success'})


@app.route("/signup", methods=["POST"])
def sign_up():
    data = json.loads(request.data)
    print(data.get('email'))
    print(data['password'])

    email = request.data['email']
    password = request.data['password']

    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    doc = {
        'email': email,
        'password': password_hash
    }

    db.users.insert_one(doc)
    return jsonify({'result': 'success', 'msg': '회원가입 완료!'})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
