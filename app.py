from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_jwt_extended import decode_token
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import os
from dotenv import load_dotenv


app = Flask(__name__)

load_dotenv()

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQLALCHEMY_DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT config
app.config['JWT_SECRET_KEY'] = "super-secret-key"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Flask session (to store JWT temporarily for HTML pages)
app.secret_key = "another-secret-key"

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Helper to check the token in the session
def check_session_jwt():
    # 1. Check if 'token' exists in session
    if 'token' not in session:
        return False, "No token in session"

    token = session['token']
    
    try:
        # 2. Decode the token to check its validity (signature, expiration)
        decoded_token = decode_token(token)
        
        # 3. Extract the identity (user_id) from the decoded token
        user_id = decoded_token['sub']
        
        # Optionally, you can refresh the token if it's nearing expiration 
        # or if you want to ensure the session always has a fresh token. 
        # This is beyond a simple check but a common pattern.
        
        # 4. Return success and the user_id
        return True, user_id
        
    except ExpiredSignatureError:
        # Token is valid but expired
        session.clear() # Clear the session to force re-login
        return False, "Token expired"
    
    except InvalidTokenError:
        # Token is malformed or signature is invalid
        session.clear() 
        return False, "Invalid token"
    
    except Exception as e:
        # Other potential errors
        session.clear()
        return False, f"Token error: {e}"



def ist_now():
    from datetime import datetime,timedelta,timezone
    
    return datetime.now(timezone.utc) +(timedelta(hours=5, minutes=30))

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=ist_now())

def init_db():
    with app.app_context():
        db.create_all()

# Home
@app.route('/')
def home():
    if 'token' in session:
        return redirect(url_for('notes'))
    return redirect(url_for('login'))

# Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            return "User already exists!"

        hashed_password = generate_password_hash(password)
        user = User(email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("register.html")

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            token = create_access_token(identity=str(user.id))
            session['token'] = token
            # session['user_id'] = user.id
            return redirect(url_for('notes'))
        return "Invalid credentials!"
    return render_template("login.html")

# Notes Page
@app.route('/notes', methods=['GET', 'POST'])
# @jwt_required()
def notes():
    is_valid, user_info = check_session_jwt()
    
    if not is_valid:
        return redirect(url_for('login'))
    
    try:
        user_id = int(user_info)
    except (TypeError, ValueError):
        # Handle case where user_info isn't a valid ID (shouldn't happen with valid JWT)
        return "Unauthorized!", 403

    user = User.query.filter_by(id=user_id).first()
    user_name = user.email if user else "Unknown"

    # user_id = get_jwt_identity()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        note = Note(title=title, content=content, user_id=user_id)
        db.session.add(note)
        db.session.commit()

    notes = Note.query.filter_by(user_id=user_id).all()
    return render_template("notes.html", notes=notes, current_user=user_name)

@app.route('/notes/edit/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    is_valid, user_info = check_session_jwt()
    if not is_valid:
        return redirect(url_for('login'))
        
    user_id = int(user_info)

    note = Note.query.get_or_404(note_id)
    # Check if the user ID from the token matches the note's owner
    if note.user_id != user_id: 
        return "Unauthorized!", 403

    if request.method == 'POST':
        note.title = request.form['title']
        note.content = request.form['content']
        db.session.commit()
        return redirect(url_for('notes'))

    return render_template('edit_note.html', note=note)

# Delete Note
@app.route('/notes/delete/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    is_valid, user_info = check_session_jwt()
    if not is_valid:
        return redirect(url_for('login'))
        
    user_id = int(user_info)

    note = Note.query.get_or_404(note_id)
    # Check if the user ID from the token matches the note's owner
    if note.user_id != user_id: 
        return "Unauthorized!", 403

    db.session.delete(note)
    db.session.commit()
    return redirect(url_for('notes'))


# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

from flask import jsonify

# Register API
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "User already exists"}), 400
    hashed_password = generate_password_hash(password)
    user = User(email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "User registered successfully"}), 201

# Login API
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        token = create_access_token(identity=str(user.id))
        return jsonify({"access_token": token}), 200
    return jsonify({"msg": "Invalid credentials"}), 401

# Get all notes
@app.route('/api/notes', methods=['GET'])
@jwt_required()
def api_get_notes():
    user_id = get_jwt_identity()
    notes = Note.query.filter_by(user_id=user_id).all()
    return jsonify([{"id": n.id, "title": n.title, "content": n.content, "timestamp": n.timestamp} for n in notes])

# Create note
@app.route('/api/notes', methods=['POST'])
@jwt_required()
def api_create_note():
    user_id = get_jwt_identity()
    data = request.get_json()
    note = Note(title=data['title'], content=data.get('content', ''), user_id=user_id)
    db.session.add(note)
    db.session.commit()
    return jsonify({"msg": "Note created", "id": note.id}), 201

# Edit note
@app.route('/api/notes/<int:note_id>', methods=['PUT'])
@jwt_required()
def api_edit_note(note_id):
    user_id = int(get_jwt_identity())
    note = Note.query.get_or_404(note_id)
    if note.user_id != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
    data = request.get_json()
    note.title = data.get('title', note.title)
    note.content = data.get('content', note.content)
    db.session.commit()
    return jsonify({"msg": "Note updated"})

# Delete note
@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@jwt_required()
def api_delete_note(note_id):
    user_id = int(get_jwt_identity())
    note = Note.query.get_or_404(note_id)
    if note.user_id != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
    db.session.delete(note)
    db.session.commit()
    return jsonify({"msg": "Note deleted"})

from app import app as application


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
    