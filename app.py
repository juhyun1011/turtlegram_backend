from functools import wraps
import json
from sre_constants import SUCCESS
from bson import ObjectId
from flask import Flask, jsonify, request, Response, abort
from flask_cors import CORS
from pymongo import MongoClient
import jwt, hashlib
from datetime import datetime, timedelta
from functools import wraps
from bson.json_util import dumps

SECRET_KEY = "turtle"

app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})  # 모든 origin 허용

client = MongoClient('localhost', 27017)

db = client.dbturtlegram

def authorize(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not 'Authorization' in request.headers:
            abort(401)
        token = request.headers['Authorization']
        try: 
            user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except:
            abort(401)
        return f(user, *args, **kwargs)
    return decorated_function





@app.route("/")
@authorize
def hello_word(user):
    # print(user)
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
    # print(data)

    email = data.get("email")
    password = data.get("password")
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
    # print(hashed_pw)
    

    result = db.users.find_one({
        'email' : email,
        'password' : hashed_pw
    })
    # print(result)

    if result is None:
        return jsonify({"message" : "아이디나 비밀번호가 옳지 않습니다."}), 401

   
    payload = {
        'id': str(result["_id"]),
        'exp': datetime.utcnow() + timedelta(seconds=60*60*24) #로그인 24시간 유지
    }
    
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    print(token)

    return jsonify({'message':"success", 'token': token})
    
#사용자 정보 확인
@app.route("/getuserinfo", methods=["GET"])
@authorize
def get_user_info(user):
    result = db.users.find_one({
        '_id': ObjectId(user["id"])
    })

    return jsonify({"message":"success", "email": result["email"], "id": user["id"]})

#게시글 등록
@app.route("/article", methods=["POST"])
@authorize
def post_article(user):
    data = json.loads(request.data)
    # print(data)

    db_user = db.users.find_one({'_id' : ObjectId(user.get('id'))})  #다시 objectid로 변환

    now = datetime.now().strftime("%H:%M:%S")
    doc = {
        'title' : data.get('title', None),
        'content' : data.get('content', None),
        'user' : user['id'],
        'user_email' : db_user['email'],
        'time': now
    }
    # print(doc)

    db.article.insert_one(doc)

    return jsonify({"message":"success"})

#게시글 보여주기
@app.route("/article", methods=["GET"])
def get_article():
    articles = list(db.article.find())
    for article in articles:
        article["_id"] = str(article["_id"])

    return jsonify({"message":"success", "articles":articles})

#변수명 url 사용(게시글 상세 페이지)
@app.route("/article/<article_id>", methods=["GET"])
def get_article_detail(article_id):
    article = db.article.find_one({"_id":ObjectId(article_id)})   #article_id 값을 objectid화 해준 뒤 검색

    #댓글 불러오기
    comments = list(db.comment.find({"article":article_id}))

    if article:
        article["_id"] = str(article["_id"])
        article["comments"] = json.loads(dumps(comments))  #덤프 이용해서 object id를 str로
        return jsonify({"message":"success", "article":article})
    else: 
        return jsonify({"message":"fail"}), 404

#게시글 수정
@app.route("/article/<article_id>", methods=["PATCH"])
@authorize #작성자만 수정할 수 있도록 권한 부여
def patch_article_detail(user, article_id):

    data = json.loads(request.data)
    title = data.get("title")
    content = data.get("content")

    article = db.article.update_one({"_id": ObjectId(article_id), "user": user["id"]}, {
        "$set" : {"title": title, "content" : content}})
    print(article.matched_count)  #성공시 1, 실패시 0 return

    if article.matched_count:
        return jsonify({"message":"succese"})
    else:
        return jsonify({"message":"fail"}), 403


#게시글 삭제
@app.route("/article/<article_id>", methods=["DELETE"])
@authorize
def delete_article_detail(user, article_id):
    article = db.article.delete_one(
        {"_id":ObjectId(article_id), "user": user["id"]}
    )
    if article.deleted_count:
        return jsonify({"message":"success"})
    else:
        return jsonify({"message":"fail"}), 403


#댓글 생성
@app.route("/article/<article_id>/comment", methods=["POST"])
@authorize
def post_comment(user, article_id):
    data = json.loads(request.data)
    print(data)

    db_user = db.users.find_one({'_id': ObjectId(user.get('id'))})
    now = datetime.now().strftime("%H:%M:%S")
    doc = {
        'article' : article_id,
        'content' : data.get('content', None),
        'user' : user['id'],
        'user_email' : db_user['email'],
        'time': now
    }
    print(doc)

    db.comment.insert_one(doc)

    return jsonify({"message":"success"})

#댓글 read 또 다른 방식(댓글만 따로)
@app.route("/article/<article_id>/comment", methods=["GET"])
def get_comment(article_id):
    comments = list(db.comment.find({"article":article_id}))
    json_comments = json.loads(dumps(comments))
    return jsonify({"message":"success", "comments":json_comments})


#좋아요
@app.route("/article/<article_id>/like", methods=["POST"])
@authorize
def post_liked(user, article_id):
    print(user, article_id)
    db_user = db.users.find_one({'_id':ObjectId(user.get('id'))})

    now = datetime.now().strftime("%H:%M:%S")
    doc = {
        'article': article_id,
        'user' : user['id'],
        'user_email' : db_user['email'],
        'time': now
    }
    print(doc)

    db.like.insert_one(doc)

    return jsonify({"message":"success"})













if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
