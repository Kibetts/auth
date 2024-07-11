from flask import Flask, jsonify, request, make_response
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
api = Api(app)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gighunt.db'
app.config['JWT_SECRET_KEY'] = 'Tingatales1'
app.config['SECRET_KEY'] = 'Tingatales1'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Create tables
with app.app_context():
    db.create_all()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(*args, **kwargs)
    return decorated

class SignUpResource(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'Username already exists'}), 400
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'message': 'User created successfully'}), 201

class LoginResource(Resource):
    def post(self):
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
        
        user = User.query.filter_by(username=auth.username).first()
        
        if not user or not check_password_hash(user.password, auth.password):
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
        
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['JWT_SECRET_KEY'], algorithm="HS256")
        
        return jsonify({'token': token})

class ProtectedResource(Resource):
    @token_required
    def get(self):
        return jsonify({'message': 'This is a protected resource'})

class UnprotectedResource(Resource):
    def get(self):
        return jsonify({'message': 'Anyone can view this'})

api.add_resource(SignUpResource, '/signup')
api.add_resource(LoginResource, '/login')
api.add_resource(ProtectedResource, '/protected')
api.add_resource(UnprotectedResource, '/unprotected')

if __name__ == '__main__':
    app.run(debug=True)