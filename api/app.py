#api/app.py
from flask import Flask, request, jsonify, Response
import uuid
import os
import psycopg2
import pika
import requests
from functools import wraps
from utils.signature import sign_data
from utils.signature import verify_signature
from utils.signature import generate_keys
from utils.validators import validate_string_length, sanitize_input
from utils.file_security import allowed_file, validate_mime
from werkzeug.utils import secure_filename
from utils.crypto import decrypt_file, encrypt_file, generate_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# generate_keys()
from utils.signature import generate_keys
import os
if not os.path.exists("keys/private.pem"):
    generate_keys()

app = Flask(__name__)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["10 per minute"]
)
# =====================
# SECURITY LIMITS (NEW)
# =====================
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB limit

INSTANCE_NAME = os.getenv("INSTANCE_NAME", "api")
AUTH_SERVICE_URL = "http://auth-service:5000"
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY")

# =====================
# INTERNAL SERVICE AUTH
# =====================
def internal_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Internal-Key")
        if not key or key != INTERNAL_API_KEY:
            return jsonify({"message": "Forbidden: invalid internal key"}), 403
        return f(*args, **kwargs)
    return decorated

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
# VERIFY TOKEN
# =====================
def verify_token_with_auth_service(token):
    try:
        res = requests.post(
            f"{AUTH_SERVICE_URL}/verify",
            json={"token": token}
        )
        if res.status_code == 200:
            user = res.json()["user"]
            # token structure: {data: {user_id, role, ...}, exp: ...}
            if "data" in user:
                return user["data"]
            return user
        return None
    except:
        return None


# =====================
# AUTH MIDDLEWARE
# =====================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({"message": "Missing token"}), 401

        try:
            token = auth_header.split(" ")[1]
        except:
            return jsonify({"message": "Invalid token format"}), 401

        user = verify_token_with_auth_service(token)

        if not user:
            log_audit(None, "unauthorized_access", "failed", request.remote_addr, "invalid token")
            return jsonify({"message": "Invalid or expired token"}), 401

        request.user = user
        return f(*args, **kwargs)

    return decorated


# =====================
# RBAC DECORATOR
# =====================
def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):

            user_role = request.user.get("role")

            if user_role not in allowed_roles:

                log_audit(
    request.user.get("user_id"),
    "unauthorized_access",
    "forbidden",
    request.remote_addr,
    f"required_roles={allowed_roles}, user_role={user_role}"
) 
                return jsonify({
                    "message": "Forbidden",
                    "your_role": user_role,
                    "required_roles": allowed_roles
                }), 403

            return f(*args, **kwargs)

        return wrapper
    return decorator


# =====================
# GLOBAL ERROR HANDLER (NEW)
# =====================
@app.errorhandler(Exception)
def handle_error(e):
    return jsonify({
        "error": "Internal server error"
    }), 500


# =====================
# HOME
# =====================
@app.route("/", methods=["GET"])
def home():
    return f"{INSTANCE_NAME} is running", 200


# =====================
# INTERNAL ENDPOINT (service-to-service)
# =====================
@app.route("/internal/status", methods=["POST"])
@internal_key_required
def internal_status():
    data = request.get_json() or {}
    return jsonify({"message": "Internal call accepted", "data": data}), 200


# =====================
# TASK (RabbitMQ)
# =====================
@app.route("/task", methods=["POST"])
@limiter.limit("5 per minute")
@token_required
def task():

    request_id = str(uuid.uuid4())
    data = request.get_json() or {}

    # 🔐 INPUT SANITIZATION (NEW)
    data = {k: sanitize_input(str(v)) for k, v in data.items()}

    connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        host=os.getenv("RABBITMQ_HOST", "rabbitmq"),
        credentials=pika.PlainCredentials(
            os.getenv("RABBITMQ_USER", "guest"),
            os.getenv("RABBITMQ_PASSWORD", "guest")
        )
    )
)
    channel = connection.channel()
    channel.queue_declare(queue="tasks")

    channel.basic_publish(
        exchange="",
        routing_key="tasks",
        body=f"{request_id} from {INSTANCE_NAME}"
    )

    connection.close()

    return jsonify({
        "message": "Task received",
        "request_id": request_id,
        "data": data
    })


# =====================
# FILE UPLOAD
# =====================
@app.route("/upload", methods=["POST"])
@token_required
def upload_file():

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    # 🔐 FILE VALIDATION (ENHANCED)
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    if not validate_mime(file):
        return jsonify({"error": "Invalid MIME type"}), 400

    # 🔐 SAFE FILENAME
    filename = secure_filename(file.filename)
    unique_name = str(uuid.uuid4()) + "_" + filename

    os.makedirs("uploads/storage", exist_ok=True)
    file_path = os.path.join("uploads/storage", unique_name)

    file_data = file.read()

    # encryption + hashing
    encrypted_data = encrypt_file(file_data)
    file_hash = generate_hash(file_data)
    signature = sign_data(file_data)

    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id SERIAL PRIMARY KEY,
            user_id TEXT,
            filename TEXT,
            path TEXT,
            file_hash TEXT,
            signature TEXT
        );
    """)

    cur.execute(
    "INSERT INTO uploaded_files (user_id, filename, path, file_hash, signature) VALUES (%s, %s, %s, %s, %s)",
    (request.user["user_id"], unique_name, file_path, file_hash, signature.hex())
    )

    conn.commit()
    cur.close()
    conn.close()

    log_audit(
    request.user["user_id"],
    "file_upload",
    "success",
    request.remote_addr,
    f"filename={unique_name}"
)
    return jsonify({"message": "File uploaded", "filename": unique_name})


# =====================
# FILE DOWNLOAD
# =====================
@app.route("/download/<filename>", methods=["GET"])
@token_required
def download_file(filename):

    file_path = os.path.join("uploads/storage", filename)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT file_hash, signature FROM uploaded_files WHERE filename=%s", (filename,))
    result = cur.fetchone()

    if not result:
        return jsonify({"error": "File not found"}), 404

    stored_hash = result[0]
    stored_signature = bytes.fromhex(result[1])

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_file(encrypted_data)

    # integrity check
    if generate_hash(decrypted_data) != stored_hash:
        return jsonify({"error": "Integrity check failed"}), 403

    
    
    # 🔥 DIGITAL SIGNATURE CHECK
    if not verify_signature(decrypted_data, stored_signature):
       return jsonify({"error": "Signature verification failed"}), 403
    
    log_audit(
    request.user["user_id"],
    "file_download",
    "success",
    request.remote_addr,
    f"filename={filename}"
)
    
    return Response(decrypted_data, mimetype="application/octet-stream")

# =====================
# INPUT VALIDATION ADDED ENDPOINT EXAMPLE (NEW PATTERN)
# =====================
@app.route("/courses", methods=["GET"])
@limiter.limit("5 per minute")
@token_required
@role_required("admin", "user")
def get_courses():
    return jsonify({"message": "Courses list"})


# =====================
# ADMIN ONLY
# =====================
@app.route("/admin/dashboard")
@token_required
@role_required("admin")
def admin_dashboard():
    return jsonify({"message": "Admin dashboard"})

@app.route("/admin/stats", methods=["GET"])
@token_required
@role_required("admin")
def admin_stats():

    conn = get_db_connection()
    cur = conn.cursor()

    # USERS
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]

    # FILES
    cur.execute("SELECT COUNT(*) FROM uploaded_files")
    total_files = cur.fetchone()[0]

    # LOGS (لو عندك audit_logs)
    try:
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE action='login_failed'")
        failed_logins = cur.fetchone()[0]
    except:
        failed_logins = 0

    try:
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE action='login_success'")
        success_logins = cur.fetchone()[0]
    except:
        success_logins = 0

    # QUEUE TASKS (approx from logs or table)
    try:
        cur.execute("SELECT COUNT(*) FROM tasks_log")
        tasks = cur.fetchone()[0]
    except:
        tasks = 0

    cur.close()
    conn.close()

    return jsonify({
        "total_users": total_users,
        "total_files": total_files,
        "failed_logins": failed_logins,
        "success_logins": success_logins,
        "queue_tasks": tasks
    })

# =====================
# USER - MY FILES
# =====================
@app.route("/my/files", methods=["GET"])
@token_required
def my_files():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, filename, file_hash FROM uploaded_files WHERE user_id=%s ORDER BY id DESC", (str(request.user["user_id"]),))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    files = [{"id": r[0], "filename": r[1], "file_hash": r[2]} for r in rows]
    return jsonify({"files": files})

# =====================
# ADMIN - LIST USERS
# =====================
@app.route("/admin/users", methods=["GET"])
@token_required
@role_required("admin")
def admin_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, role, is_active, created_at FROM users ORDER BY id DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    users = [
        {"id": r[0], "username": r[1], "email": r[2], "role": r[3], "is_active": r[4], "created_at": str(r[5])}
        for r in rows
    ]
    return jsonify({"users": users})

# =====================
# ADMIN - LIST FILES
# =====================
@app.route("/admin/files", methods=["GET"])
@token_required
@role_required("admin")
def admin_files():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, user_id, filename, file_hash FROM uploaded_files ORDER BY id DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    files = [
        {"id": r[0], "user_id": r[1], "filename": r[2], "file_hash": r[3]}
        for r in rows
    ]
    return jsonify({"files": files})

# =====================
# ADMIN - AUDIT LOGS
# =====================
@app.route("/admin/logs", methods=["GET"])
@token_required
@role_required("admin")
def admin_logs():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, action, status, ip_address, details, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 50")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    logs = [
        {"user_id": r[0], "action": r[1], "status": r[2], "ip": r[3], "details": r[4], "timestamp": str(r[5])}
        for r in rows
    ]
    return jsonify({"logs": logs})

# =====================
# RUN
# =====================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)