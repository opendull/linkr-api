from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
import uuid
import psycopg2
import psycopg2.extras
from datetime import datetime
from dataclasses import dataclass
from sqlalchemy.pool import NullPool
import firebase_admin
from firebase_admin import credentials, messaging
import os
import json
import base64

app = Flask(__name__)

def get_db_connection():
    return psycopg2.connect(
        host="aws-1-us-east-1.pooler.supabase.com",
        port=6543,
        database="postgres",
        user="postgres.ousvcwmcauatiwrwjkxd",
        password="Shubham@1023153",  # or better: os.getenv("DB_PASSWORD")
        sslmode="require"
    )

# Read Firebase JSON from environment variable (single-line JSON string)
base64_creds = os.getenv("FIREBASE_CRED_JSON")

if not base64_creds:
    raise RuntimeError("FIREBASE_CRED_JSON environment variable not set!")

json_creds_str = base64.b64decode(base64_creds).decode('utf-8')
# Convert the JSON string to a Python dictionary
creds_dict = json.loads(json_creds_str)

if not firebase_admin._apps:
    cred = credentials.Certificate(creds_dict)
    firebase_admin.initialize_app(cred)  

# -----------------------------
# CONFIGURATION
# -----------------------------
#Shubham%401023153
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'postgresql+psycopg2://postgres.ousvcwmcauatiwrwjkxd:Shubham%401023153@aws-1-us-east-1.pooler.supabase.com:6543/postgres?sslmode=require'
)

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "poolclass": NullPool,
    "connect_args": {"sslmode": "require"},
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


def send_fcm_notification(token: str, title: str, body: str, data: dict = None):
    """Send a push notification via Firebase Cloud Messaging."""
    message = messaging.Message(
        notification=messaging.Notification(title=title, body=body),
        token=token,
        data=data or {}
    )
    try:
        response = messaging.send(message)
        print("✅ FCM sent:", response)
    except Exception as e:
        print("❌ FCM error:", e)

# -----------------------------
# MODELS
# -----------------------------

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    profile_picture = db.Column(db.String, nullable=True)


class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String, nullable=False, default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Friend(db.Model):
    __tablename__ = 'friends'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    user2_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@dataclass
class Location:
    user_id: str
    latitude: float
    longitude: float
    updated_at: datetime = None

    @staticmethod
    def from_row(row):
        """Helper to convert DB row (dict or tuple) into a Location object."""
        return Location(
            user_id=row["user_id"],
            latitude=row["latitude"],
            longitude=row["longitude"],
            updated_at=row.get("updated_at") if isinstance(row, dict) else row[3]
        )
    
class Ping(db.Model):
    __tablename__ = 'pings'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

class UserFCMToken(db.Model):
    __tablename__ = 'user_fcm_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    fcm_token = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# -----------------------------
# AUTH ROUTES
# -----------------------------

@app.route('/')
def home():
    return jsonify({"message": "API running!"})

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password_raw = data.get('password')

    if not all([name, email, password_raw]):
        return jsonify({'message': 'All fields are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered'}), 400

    password_hash = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
    user = User(name=name, email=email, password_hash=password_hash)

    db.session.add(user)
    db.session.commit()

    return jsonify({
        'message': 'User registered successfully',
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'profile_picture': user.profile_picture
        }
    }), 201


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = create_access_token(identity=user.id)
    return jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'profile_picture': user.profile_picture
        }
    })


@app.route('/users/<id>', methods=['GET'])
@jwt_required()
def get_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'profile_picture': user.profile_picture
    })

# -----------------------------
# FRIENDSHIP ROUTES
# -----------------------------

@app.route('/friends', methods=['GET'])
@jwt_required()
def get_friends():
    # Convert JWT identity to UUID to match database type
    user_id = uuid.UUID(get_jwt_identity())

    # Query friendships where the current user is either user1 or user2
    friendships = Friend.query.filter(
        (Friend.user1_id == user_id) | (Friend.user2_id == user_id)
    ).all()

    friend_list = []
    for f in friendships:
        # Determine the friend ID (the other user in the friendship)
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        friend = User.query.get(friend_id)
        if friend:
            friend_list.append({
                'id': str(friend.id),  # Convert UUID to string for JSON
                'name': friend.name,
                'email': friend.email
            })

    return jsonify(friend_list)


@app.route('/friends/request', methods=['POST'])
@jwt_required()
def send_friend_request():
    user_id = get_jwt_identity()
    data = request.get_json()
    receiver_id = data.get('receiver_id')

    if user_id == receiver_id:
        return jsonify({'message': 'Cannot send request to yourself'}), 400

    # Prevent duplicate or reverse friend requests
    existing_request = FriendRequest.query.filter(
        ((FriendRequest.requester_id == user_id) & (FriendRequest.receiver_id == receiver_id)) |
        ((FriendRequest.requester_id == receiver_id) & (FriendRequest.receiver_id == user_id))
    ).first()
    if existing_request:
        return jsonify({'message': 'Request already exists'}), 400

    # Prevent if already friends
    already_friends = Friend.query.filter(
        ((Friend.user1_id == user_id) & (Friend.user2_id == receiver_id)) |
        ((Friend.user2_id == user_id) & (Friend.user1_id == receiver_id))
    ).first()
    if already_friends:
        return jsonify({'message': 'You are already friends'}), 400

    friend_req = FriendRequest(requester_id=user_id, receiver_id=receiver_id)
    db.session.add(friend_req)
    db.session.commit()

    return jsonify({'message': 'Friend request sent successfully'}), 201


@app.route('/friends/requests', methods=['GET'])
@jwt_required()
def get_pending_requests():
    user_id = get_jwt_identity()
    requests = FriendRequest.query.filter_by(receiver_id=user_id, status='pending').all()
    result = []
    for req in requests:
        sender = User.query.get(req.requester_id)
        if sender:
            result.append({
                'request_id': req.id,
                'sender_id': sender.id,
                'sender_name': sender.name,
                'sender_email': sender.email
            })
    return jsonify(result)


@app.route('/friends/request/<int:request_id>/accept', methods=['POST'])
@jwt_required()
def accept_friend_request(request_id):
    current_user_id = str(get_jwt_identity())

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Fetch the friend request
    cursor.execute("SELECT * FROM friend_requests WHERE id = %s", (request_id,))
    request_data = cursor.fetchone()

    if not request_data:
        cursor.close()
        conn.close()
        return jsonify({'message': 'Request not found'}), 404

    # Ensure the current user is the receiver
    if str(request_data['receiver_id']) != str(current_user_id):
        cursor.close()
        conn.close()
        return jsonify({'message': 'Invalid or unauthorized request'}), 403

    # Update request status to 'accepted'
    cursor.execute("""
        UPDATE friend_requests 
        SET status = 'accepted', updated_at = NOW()
        WHERE id = %s
    """, (request_id,))

    # ✅ Ensure correct order for friends table
    user1_id, user2_id = sorted([request_data['requester_id'], request_data['receiver_id']])

    # Insert into friends table safely (avoid duplicates)
    cursor.execute("""
        INSERT INTO friends (user1_id, user2_id)
        VALUES (%s, %s)
        ON CONFLICT (user1_id, user2_id) DO NOTHING
    """, (user1_id, user2_id))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'message': 'Friend request accepted successfully'})


@app.route('/friends/request/<int:req_id>/reject', methods=['POST'])
@jwt_required()
def reject_request(req_id):
    user_id = get_jwt_identity()
    request_obj = FriendRequest.query.get(req_id)

    if not request_obj or request_obj.receiver_id != user_id:
        return jsonify({'message': 'Invalid or unauthorized request'}), 400

    request_obj.status = 'rejected'
    db.session.commit()

    return jsonify({'message': 'Friend request rejected'})


@app.route('/friends/<id>', methods=['DELETE'])
@jwt_required()
def remove_friend(id):
    user_id = get_jwt_identity()

    friendship = Friend.query.filter(
        ((Friend.user1_id == user_id) & (Friend.user2_id == id)) |
        ((Friend.user2_id == user_id) & (Friend.user1_id == id))
    ).first()

    if not friendship:
        return jsonify({'message': 'Friendship not found'}), 404

    db.session.delete(friendship)
    db.session.commit()

    return jsonify({'message': 'Friend removed successfully'})

# ---------- 1️⃣  POST /location  ----------
@app.route("/location", methods=["POST"])
@jwt_required()
def update_location():
    data = request.get_json()
    user_id = get_jwt_identity()
    latitude = data.get("latitude")
    longitude = data.get("longitude")

    if latitude is None or longitude is None:
        return jsonify({"error": "Latitude and longitude required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Insert or update (UPSERT)
        cur.execute("""
            INSERT INTO locations (user_id, latitude, longitude, updated_at)
            VALUES (%s, %s, %s, now())
            ON CONFLICT (user_id)
            DO UPDATE SET latitude = EXCLUDED.latitude,
                          longitude = EXCLUDED.longitude,
                          updated_at = now();
        """, (user_id, latitude, longitude))
        conn.commit()
        return jsonify({"message": "Location updated successfully"}), 200
    finally:
        cur.close()
        conn.close()


# ---------- 2️⃣  GET /location/friends  ----------
@app.route("/location/friends", methods=["GET"])
@jwt_required()
def get_friends_locations():
    user_id = get_jwt_identity()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        cur.execute("""
            SELECT u.id, u.name, u.email, l.latitude, l.longitude, l.updated_at
            FROM friends f
            JOIN users u ON (
            (u.id = f.user1_id OR u.id = f.user2_id)
            AND u.id != %s
            )
            JOIN locations l ON l.user_id = u.id
            WHERE (f.user1_id = %s OR f.user2_id = %s)
            """, (user_id, user_id, user_id))

        friends_locations = cur.fetchall()
        return jsonify(friends_locations), 200
    finally:
        cur.close()
        conn.close()


# ---------- 3️⃣  GET /location/<user_id>  ----------
@app.route("/location/<uuid:friend_id>", methods=["GET"])
@jwt_required()
def get_friend_location(friend_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        cur.execute("""
            SELECT u.id, u.name, l.latitude, l.longitude, l.updated_at
            FROM users u
            JOIN locations l ON l.user_id = u.id
            WHERE u.id = %s;
        """, (str(friend_id),))
        location = cur.fetchone()
        if not location:
            return jsonify({"error": "Location not found"}), 404
        return jsonify(location), 200
    finally:
        cur.close()
        conn.close()

# -----------------------------
# PING
# -----------------------------
@app.route('/ping', methods=['POST'])
@jwt_required()
def send_ping():
    data = request.get_json()
    current_user_id = get_jwt_identity()
    receiver_id = data.get('receiver_id')

    if not receiver_id:
        return jsonify({"error": "receiver_id required"}), 400
    if receiver_id == current_user_id:
        return jsonify({"error": "Cannot ping self"}), 400

    ping = Ping(sender_id=current_user_id, receiver_id=receiver_id)
    db.session.add(ping)
    db.session.commit()

    # Send notification via Firebase
    sender = User.query.get(current_user_id)
    tokens = UserFCMToken.query.filter_by(user_id=receiver_id).all()
    for t in tokens:
        send_fcm_notification(
            t.fcm_token,
            title="New Ping",
            body=f"{sender.name if sender else 'Someone'} pinged you",
            data={"ping_id": str(ping.id), "sender_id": str(current_user_id)}
        )

    return jsonify({"message": "Ping sent and notification triggered!"}), 201

@app.route('/ping/incoming', methods=['GET'])
@jwt_required()
def incoming_pings():
    current_user_id = get_jwt_identity()
    pings = Ping.query.filter_by(receiver_id=current_user_id, status='pending').all()

    results = [{
        "id": p.id,
        "sender_id": p.sender_id,
        "status": p.status,
        "created_at": p.created_at
    } for p in pings]

    return jsonify(results)

@app.route('/ping/<int:ping_id>/respond', methods=['POST'])
@jwt_required()
def respond_ping(ping_id):
    data = request.get_json()
    status = data.get('status')
    current_user_id = get_jwt_identity()

    if status not in ['accepted', 'rejected']:
        return jsonify({"error": "Invalid status"}), 400

    ping = Ping.query.filter_by(id=ping_id, receiver_id=current_user_id).first()
    if not ping:
        return jsonify({"error": "Ping not found or unauthorized"}), 404

    ping.status = status
    db.session.commit()

    return jsonify({"message": f"Ping {status} successfully!"})


# -----------------------------
# SEARCH USERS (Optional Helper)
# -----------------------------
@app.route('/users/search', methods=['GET'])
@jwt_required()
def search_users():
    query = request.args.get('q', '').lower()
    user_id = get_jwt_identity()

    if not query:
        return jsonify({'message': 'Query is required'}), 400

    users = User.query.filter(
        (User.name.ilike(f'%{query}%')) | (User.email.ilike(f'%{query}%'))
    ).all()

    result = [
        {'id': u.id, 'name': u.name, 'email': u.email}
        for u in users if u.id != user_id
    ]
    return jsonify(result)


# -----------------------------
# FIREBASE CLOUD MESSAGING
# -----------------------------

@app.route('/fcm/register', methods=['POST'])
@jwt_required()
def register_fcm():
    """
    Register or update the Firebase token of a device for the current user.
    The Android app should call this when it gets a new FCM token.
    """
    data = request.get_json()
    new_token = data.get('token')
    if not new_token:
        return jsonify({"error": "FCM token is required"}), 400

    user_id = get_jwt_identity()

    # Check if the user already has a token
    existing_token = UserFCMToken.query.filter_by(user_id=user_id).first()
    if existing_token:
        # Update the token and updated_at timestamp
        existing_token.fcm_token = new_token
        existing_token.updated_at = datetime.utcnow()
    else:
        # Insert new token
        db.session.add(UserFCMToken(user_id=user_id, fcm_token=new_token))

    db.session.commit()
    return jsonify({"message": "FCM token registered/updated successfully"}), 200

# -----------------------------
# MAIN
# -----------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
