from flask import Flask, jsonify, request, json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token)

app = Flask(__name__)

app.config["MONGO_DBNAME"] = 'users'
app.config["MONGO_URI"]  =  'mongodb://localhost:27017/users'
app.config['JWT_SECRET_KEY'] = 'secret'


mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt    = JWTManager(app)

CORS(app)

@app.route("/signup", methods = ['POST'])
def signup():
    users      = mongo.db.users
    username   = request.get_json()['username']
    rollno     = request.get_json()['rollno']
    email      = request.get_json()['email']
    password   = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    created     = datetime.utcnow()

    user_id = users.insert({
        'username' : username,
        'rollno'   : rollno,
        'email'    : email,
        'password' : password,
        'created'  : created,
    })
    new_user = users.find_one({'_id' : user_id})

    result = {'username' : new_user['username'] + 'registered'}

    return jsonify({'result' : result})

@app.route("/signin" , methods = ['POST'])
def signin():
    users = mongo.db.users
    email = request.get_json()['email']
    password = request.get_json()['password']
    rollno  = request.get_json()['rollno']
    result = ""

    response = users.find_one({'email': email})

    if response:
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
                'username' : response['username'],
                'rollno'   : response['rollno'],
                'email'    : response['email']
            })

            result  = jsonify({"token" : access_token})

        else:
            result = jsonify({"error": "Invalid password/username"})

    else:
        result = jsonify({"error": "No data found"})
    
    return result


            

if __name__ == "__main__":
    app.run(debug = True)
