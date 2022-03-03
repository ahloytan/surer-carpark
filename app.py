from flask import Flask, jsonify, request, make_response, session, render_template, redirect, url_for, flash
import jwt
import datetime
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import os
import hashlib, uuid
import secrets
import urllib.request, json
import requests
from utils import default
import json
from flask_login import UserMixin, login_user, logout_user, LoginManager, login_required

SECRET_KEY = os.urandom(32)

app = Flask(__name__, static_url_path='')
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# ==================== CONNECTING TO DATABASE ====================#
db_username = os.getenv("DB_USERNAME")
db_password = os.getenv("DB_PASSWORD")
db_endpoint = os.getenv("DB_ENDPOINT")
app.config['SECRET_KEY'] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+mysqlconnector://{db_username}:{db_password}@{db_endpoint}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
db = SQLAlchemy(app)

################## User Class Creation ##################
class User(db.Model, UserMixin):
    __tablename__ = "user"

    email = db.Column(db.String(256), primary_key=True)
    hashed_password = db.Column(db.String(256),nullable=True)
    salt = db.Column(db.String(256),nullable=True)
    first_name = db.Column(db.String(256),nullable=False)
    last_name = db.Column(db.String(256),nullable=False)
    contact_no = db.Column(db.String(8), nullable=True)

    def __init__(self, email, hashed_password, salt, first_name, last_name,contact_no):
        self.email = email
        self.hashed_password = hashed_password
        self.salt = salt
        self.first_name = first_name
        self.last_name = last_name
        self.contact_no = contact_no

    def get_id(self):
        return self.email

    def json(self):
        return {"email": self.email, "hashed_password": self.hashed_password, "salt":self.salt,"first_name":self.first_name, "last_name": self.last_name, "contact_no": self.contact_no}

################## Sessions Class Creation ##################
class Sessions(db.Model):
    __tablename__ = "sessions"

    user_email = db.Column(db.String(256), db.ForeignKey('user.email'), primary_key=True)
    session_id = db.Column(db.String(256), primary_key=True)

    def __init__(self, user_email, session_id):
        self.user_email = user_email
        self.session_id = session_id

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        if not token:
            return jsonify({'message' : 'Token is missing'}), 403

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])
        except:

            return jsonify({'message' : 'Token is invalid/expired'}), 403

        return f(*args, **kwargs)

    return decorated

@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('home.html')
    else:
        return 'logged in currently'

@app.route('/unprotected')
def unprotected():
    return jsonify({'message': 'Anyone can view this!'})

@app.route('/protected')
@token_required
@login_required
def protected_member():
    url = "https://api.data.gov.sg/v1/transport/carpark-availability"
    tokenValue = request.args.get('token')

    decoded = jwt.decode(tokenValue, key=app.config['SECRET_KEY'])
    user = User.query.filter_by(email=decoded['email']).first()
    current_session = Sessions.query.filter_by(user_email=decoded['email']).first()

    if current_session:
        response = urllib.request.urlopen(url)
        data = response.read()
        carpark_data = json.loads(data)
        # print(carpark_data)

        return render_template('member.html', user = {
            'Email': user.email,
            'First Name': user.first_name,
            'Last Name': user.last_name,
            'Contact Number': user.contact_no
        }, carpark_data = carpark_data)

    flash('Please log in first')
    return redirect(url_for('home'))
    # return jsonify({'message': 'This is only available for people with valid tokens', 'token': tokenValue, 'member_details': user.json()})

@app.route('/changer', methods=['POST'])
@login_required
def changer():

    jwt = request.form['jwt']
    return redirect(url_for('protected_member', token=[jwt]))

@app.route('/login', methods=['POST'])
def login():
    try:
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        # Normal log in, validate pw
        password = request.form['password']
        hashed_db_password = user.hashed_password
        db_salt = user.salt

        session_id = secrets.token_urlsafe(16)
        current_session = Sessions.query.filter_by(user_email=email).first()
        print(current_session)
        if current_session:
            current_session.session_id = session_id
            # print(current_session.session_id)
        else:
            print(email)
            user_session = Sessions(email, session_id)
            db.session.add(user_session)
        db.session.commit()

        hashed_password = hashlib.sha512((password + db_salt).encode('utf-8')).hexdigest()
        if hashed_password != hashed_db_password:
            flash('Incorrect password')
            return redirect(url_for('home'))
        else:
            token = jwt.encode({'email': request.form['email'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=15)}, app.config["SECRET_KEY"])
            # msgToken = jsonify({'token': token.decode('UTF-8')})
            # print(token)
            login_user(user)
            return render_template('login.html', token = {
                'token': token.decode('utf-8')
            }), { 'Set-Cookie':f'SESSION_ID={session_id}; Path=/; HttpOnly; SameSite=None; Secure' }

    except Exception as e:
        print(e)
        flash('Something went wrong with logging in')
        return redirect(url_for('home'))


@app.route('/register', methods=['POST'])
def register():
    email = request.form['email2']
    first_name = request.form['fname']
    last_name = request.form['lname']
    password = request.form['password2']
    contact = request.form['contact']

    acc = User.query.filter_by(email=email).first()


    if(acc):
        return json.loads(json.dumps({
            "error": "Email already exist"
        }, default=default)), 422

    else:
        salt = uuid.uuid4().hex
        hashed_password= hashlib.sha512((password + salt).encode('utf-8')).hexdigest()
        user = User(email, hashed_password, salt, first_name, last_name, contact)

    try:
        if (email and first_name and last_name and password):
            db.session.add(user)
            db.session.commit()

            flash('You have successfully registered an account!')
            return redirect(url_for('home'))

        flash('Unexpected error in registration. Please try again.')
        return redirect(url_for('home'))

    except Exception as e:
        print(e)
        return json.loads(json.dumps({
            "error": "Unexpected error in registration. Please try again."
        }, default=default)), 500

@app.route('/logout', methods = ['POST'])
@login_required
def logout():
    session_id = request.cookies.get('SESSION_ID')
    print(session_id, "HAHAHAHh")

    try:
        Sessions.query.filter_by(session_id=session_id).delete()
        db.session.commit()
        logout_user()
        flash('You have successfully logged out!')
        return redirect(url_for('home'))

    except Exception as e:
        print(e)
        return json.loads(json.dumps({"error": "Something went wrong with logging out"}, default=default)), 500

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

if __name__ == '__main__':
    app.run(debug=True, port=5000)
