import json
from queue import Empty
from sre_constants import SUCCESS
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from pymongo import MongoClient
import hashlib

app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})  # 모든 origin 허용

client = MongoClient('localhost', 27017)

db = client.dbturtlegram


@app.route("/")
def hello_word():
    return jsonify({'message': 'success'})


@app.route("/signup", methods=["POST"])
def sign_up():
    data = json.loads(request.data)

    email_received = data.get('email')
    password_received = data['password']

    hashed_password = hashlib.sha256(password_received.encode('utf-8')).hexdigest()


    #이메일/패스워드가 없을 때 에러 처리
    if email_received == "" or password_received == "" :
        return jsonify({'msg' : '이메일 혹은 패스워드를 입력해주세요!'})
    
    if '@' not in email_received:
        return jsonify({'msg' : '이메일 형식이 아닙니다.'})

    #이메일 중복 처리
    print(email_received)
    print(db.users.find_one({'email':email_received}))
    if db.users.find_one({'email':email_received}):
        return jsonify({'msg' : '중복된 이메일입니다.'})

    #정상적 처리
    else:
        doc = {
            'email': email_received,
            'password': hashed_password
        }

        db.users.insert_one(doc)
        return jsonify({'msg': '회원가입 완료!'}), 201

    

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
