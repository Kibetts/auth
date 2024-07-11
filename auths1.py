from flask import Flask, jsonify, request, make_response
from flask_restful import Api, Resource
import jwt
import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = 'mysecretkey'

# In-memory database
users = {}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-tokens')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(*args, **kwargs)
    return decorated

class Register(Resource):
    def post(self):
        data = request.get_json()
        if not data or not data.get('username') or not data.get('password'):
            return make_response('Missing credentials', 400)
        
        username = data['username']
        if username in users:
            return make_response('User already exists', 400)

        hashed_password = generate_password_hash(data['password'], method='sha256')
        users[username] = hashed_password
        return jsonify({'message': 'Registered successfully'})

class Login(Resource):
    def post(self):
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        username = auth.username
        if username not in users:
            return make_response('User not found', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
        
        if check_password_hash(users[username], auth.password):
            token = jwt.encode({'user': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({'token': token})

        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

class Protected(Resource):
    @token_required
    def get(self):
        return jsonify({'message': 'This is only available for people with valid token'})

class Unprotected(Resource):
    def get(self):
        return jsonify({'message': 'Anyone can view this'})

api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(Unprotected, '/unprotected')
api.add_resource(Protected, '/protected')

if __name__ == '__main__':
    app.run(debug=True)
