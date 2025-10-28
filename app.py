# app.py
import os
from datetime import timedelta
from uuid import uuid4

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- Flask Config ---
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)

# --- Init extensions ---
db = SQLAlchemy(app)
jwt = JWTManager(app)


# --- Models ---
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid4()))
    email = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    name = db.Column(db.String)
    profile_picture = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "profile_picture": self.profile_picture,
        }


# --- Routes ---

@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    name = data.get("name")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 409

    hashed_pw = generate_password_hash(password)
    user = User(email=email, password_hash=hashed_pw, name=name)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully", "user": user.to_dict()}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({"token": access_token, "user": user.to_dict()}), 200


@app.route("/users/<user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(user.to_dict()), 200


# --- Main ---
if __name__ == "__main__":
    app.run(debug=True)
