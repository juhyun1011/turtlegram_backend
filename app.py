import json
from flask import Flask, jsonify, request
from flask_cors import CORS


app = Flask(__name__)


@app.route("/")
def hello_word():
    return jsonify({'message': 'success'})


@app.route("/signup", methods=["POST"])
def sign_up():
    print(request)
    print(request.form)
    print(request.data)
    data = json.loads(request.data)
    print(data)
    print(data.get('id'))
    print(data['password'])

    return jsonify({'message': 'success2'})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
