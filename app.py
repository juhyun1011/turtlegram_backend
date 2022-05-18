import json
from queue import Empty
from sre_constants import SUCCESS
from bson import ObjectId
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from pymongo import MongoClient
import jwt, hashlib
from datetime import datetime, timedelta

SECRET_KEY = "turtle"

app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})  # 모든 origin 허용

client = MongoClient('localhost', 27017)

db = client.dbturtlegram


@app.route("/")
def hello_word():
    return jsonify({'message': 'success'})

#회원가입
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
    # print(email_received)
    # print(db.users.find_one({'email':email_received}))
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

    
#로그인
@app.route("/login", methods=["POST"])
def login():
    print(request)
    data = json.loads(request.data)
    print(data)

    email = data.get("email")
    password = data.get("password")
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
    print(hashed_pw)
    

    result = db.users.find_one({
        'email' : email,
        'password' : hashed_pw
    })
    print(result)

    if result is None:
        return jsonify({"message" : "아이디나 비밀번호가 옳지 않습니다."}), 401

   
    payload = {
        'id': str(result["_id"]),
        'exp': datetime.utcnow() + timedelta(seconds=60*60*24) #로그인 24시간 유지
    }
    
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    print(token)

    return jsonify({'message':"success", 'token': token})
    

@app.route("/getuserinfo", methods=["GET"])
def get_user_info():
    token = request.headers.get("Authorization")
    print(token)

    # if not token:
    #     return jsonify({"message" : "no token"}), 402

    user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    print(user)
    result = db.users.find_one({
        '_id': ObjectId(user["id"])
    })

    print(result)

    return jsonify({"message":"success", "email": result["email"]})

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
