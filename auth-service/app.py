#auth-service/app.py
from flask import Flask, request, jsonify
import psycopg2
from psycopg2.errors import UniqueViolation
import jwt
import bcrypt
import os
from datetime import datetime, timedelta
from utils.validators import validate_email, validate_password
from authlib.integrations.flask_client import OAuth
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["5 per hour"]
)

JWT_SECRET = os.getenv("JWT_SECRET", "mysecretkey")
app.secret_key = os.getenv("SECRET_KEY")
oauth_state_secret = os.getenv("OAUTH_STATE_SECRET", "change_me")
# =====================
# GOOGLE OAUTH
# =====================
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# =====================
# DB
# =====================
def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "db"),
        database=os.getenv("DB_NAME", "secure_system"),
        user=os.getenv("DB_USER", "admin"),
        password=os.getenv("DB_PASSWORD", "admin")
    )

def log_audit(user_id, action, status, ip_address, details=""):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO audit_logs (user_id, action, status, ip_address, details)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, action, status, ip_address, details))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print("Audit log error:", e)
 
# =====================
# INIT DB
# =====================
def init_db():
    for i in range(10):
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50),
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT,
                    role TEXT DEFAULT 'user',
                    auth_provider TEXT DEFAULT 'local',
                    google_id TEXT
                );
            """)
            conn.commit()
            cur.close()
            conn.close()
            print("DB initialized successfully")
            return
        except Exception as e:
            print(f"DB not ready, retrying ({i+1}/10)... {e}")
            time.sleep(3)
    raise Exception("Could not connect to DB after 10 retries")

init_db()

def create_admin_user():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s", ("admin@test.com",))
        if not cur.fetchone():
            hashed = bcrypt.hashpw("Admin1234!".encode(), bcrypt.gensalt())
            cur.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (%s,%s,%s,%s)",
                ("admin", "admin@test.com", hashed.decode(), "admin")
            )
            conn.commit()
            print("Admin user created: admin@test.com / Admin1234!")
        else:
            print("Admin user already exists")
        cur.close()
        conn.close()
    except Exception as e:
        print("Error creating admin:", e)

create_admin_user()


# =====================
@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")
    username = data.get("username")

    if not validate_email(email):
       return jsonify({"error": "Invalid email format"}), 400

    if not validate_password(password):
       return jsonify({"error": "Weak password"}), 400

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())


    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            INSERT INTO users
            (username, email, password_hash, role)
            VALUES (%s, %s, %s, %s)
            """,
            (username, email, hashed_pw.decode(), "user")
        )

        conn.commit()

    except psycopg2.errors.UniqueViolation:
       conn.rollback()

       return jsonify({
         "error": "User already exists"
    }), 400

    finally:
        cur.close()
        conn.close()
    
    
    log_audit(None, "register", "success", request.remote_addr, f"email={email}")
    return jsonify({"message": "User registered"})


# =====================
# LOGIN
# =====================
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")
    if not validate_email(email):
       return jsonify({"error": "Invalid email"}), 400
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, password_hash, role FROM users WHERE email=%s", (email,))
    user = cur.fetchone()

    if not user:
        log_audit(None, "login_failed", "failed", request.remote_addr, f"email={email}")
        return jsonify({"error": "Invalid credentials"}), 401

    user_id, hashed_pw, role = user

    if isinstance(hashed_pw, str):
        hashed_pw = hashed_pw.encode()

    if not bcrypt.checkpw(password.encode(), hashed_pw):
        log_audit(user_id, "login_failed", "failed", request.remote_addr, f"email={email}")
        return jsonify({"error": "Invalid credentials"}), 401

    from utils.jwt_handler import generate_token
    token = generate_token({
        "user_id": user_id,
        "email": email,
        "role": role
    })

    log_audit(user_id, "login_success", "success", request.remote_addr, f"email={email}")
    return jsonify({"token": token})


# =====================
# VERIFY
# =====================
@app.route("/verify", methods=["POST"])
def verify():
    token = request.json.get("token")

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return jsonify({"valid": True, "user": decoded})
    except:
        return jsonify({"valid": False}), 401


# =====================
# LOGOUT
# =====================
@app.route("/logout", methods=["POST"])
def logout():
    auth_header = request.headers.get("Authorization")
    user_id = None

    if auth_header:
        try:
            token = auth_header.split(" ")[1]
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            user_id = decoded.get("user_id")
        except:
            pass

    log_audit(user_id, "logout", "success", request.remote_addr)
    return jsonify({"message": "Logged out successfully"})


# =====================
# GOOGLE CALLBACK
# =====================
from utils.jwt_handler import generate_token

@app.route("/login/google")
def login_google():
    redirect_uri = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://localhost/login/google/callback"
    )
    from flask import session
    session['oauth_next'] = request.args.get('next', 'admin')
    return google.authorize_redirect(redirect_uri)

@app.route("/login/google/callback")
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get("userinfo")

        email = user_info["email"]
        name = user_info.get("name", "")
        google_id = user_info["sub"]

        conn = get_db_connection()
        cur = conn.cursor()

        # check existing user
        cur.execute("SELECT id, email, role FROM users WHERE email=%s", (email,))
        user = cur.fetchone()

        if not user:
            cur.execute("""
                INSERT INTO users (username, email, auth_provider, google_id, role)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, email, role
            """, (name, email, "google", google_id, "user"))

            user = cur.fetchone()
            conn.commit()

        cur.close()
        conn.close()

        jwt_token = generate_token({
            "user_id": user[0],
            "email": user[1],
            "role": user[2],
            "auth_provider": "google"
        })

        from flask import session, redirect
        next_page = session.pop('oauth_next', 'admin')
        if next_page == 'user':
            return redirect(f"https://localhost/user?token={jwt_token}")
        return redirect(f"https://localhost/dashboard?token={jwt_token}")

    except Exception as e:
        print("OAuth Error:", e)
        return redirect("https://localhost/dashboard?error=oauth_failed")
# =====================
# RUN
# =====================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)