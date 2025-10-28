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

def get_db_connection():
    return psycopg2.connect(
        host="aws-1-us-east-1.pooler.supabase.com",
        database="postgres",
        user="postgres.ousvcwmcauatiwrwjkxd",
        password="Shubham@1023153",
        port=6543,
        sslmode="require"
    )

# -----------------------------
# CONFIGURATION
# -----------------------------
#Shubham%401023153
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'postgresql+psycopg2://postgres.ousvcwmcauatiwrwjkxd:Shubham%401023153@aws-1-us-east-1.pooler.supabase.com:6543/postgres?sslmode=require'
)

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "pool_size": 1,
    "max_overflow": 0
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

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
    user_id = get_jwt_identity()
    friendships = Friend.query.filter(
        (Friend.user1_id == user_id) | (Friend.user2_id == user_id)
    ).all()

    friend_list = []
    for f in friendships:
        friend_id = f.user2_id if f.user1_id == user_id else f.user1_id
        friend = User.query.get(friend_id)
        if friend:
            friend_list.append({'id': friend.id, 'name': friend.name, 'email': friend.email})

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

    cursor.execute("SELECT * FROM friend_requests WHERE id = %s", (request_id,))
    request_data = cursor.fetchone()

    if not request_data:
        return jsonify({'message': 'Request not found'}), 404

    # ✅ Ensure the current user is the receiver
    if str(request_data['receiver_id']) != str(current_user_id):
        return jsonify({'message': 'Invalid or unauthorized request'}), 403

    # ✅ Update status to accepted
    cursor.execute("""
        UPDATE friend_requests 
        SET status = 'accepted', updated_at = NOW()
        WHERE id = %s
    """, (request_id,))

    # ✅ Add both as friends
    cursor.execute("""
        INSERT INTO friends (user1_id, user2_id)
        VALUES (%s, %s)
    """, (request_data['requester_id'], request_data['receiver_id']))

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
        return jsonify({"error": "receiver_id is required"}), 400

    # Prevent sending ping to self
    if receiver_id == current_user_id:
        return jsonify({"error": "You cannot ping yourself"}), 400

    new_ping = Ping(sender_id=current_user_id, receiver_id=receiver_id)
    db.session.add(new_ping)
    db.session.commit()

    return jsonify({"message": "Ping sent successfully!"}), 201

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
# MAIN
# -----------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
