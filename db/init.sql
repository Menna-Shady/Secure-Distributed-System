-- =====================
-- USERS TABLE
-- =====================
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    email VARCHAR(100) UNIQUE NOT NULL,
    auth_provider VARCHAR(20) DEFAULT 'local',
    google_id VARCHAR(255),
    password_hash TEXT,
    role TEXT DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================
-- AUDIT LOGS TABLE
-- =====================
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INT,
    action VARCHAR(255),
    status VARCHAR(50),
    ip_address VARCHAR(100),
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================
-- UPLOADED FILES TABLE
-- =====================
CREATE TABLE IF NOT EXISTS uploaded_files (
    id SERIAL PRIMARY KEY,
    user_id TEXT,
    filename TEXT,
    path TEXT,
    file_hash TEXT,
    signature TEXT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================
-- WORKER LOGS TABLE
-- =====================
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    request_id TEXT,
    instance TEXT,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Admin user يتعمل عن طريق auth-service عند الـ startup
-- (check auth-service/app.py -> create_admin_user)
-- =====================
-- ROLES TABLE
-- =====================
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT
);

-- =====================
-- PERMISSIONS TABLE
-- =====================
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT
);

-- =====================
-- USER_ROLES TABLE
-- =====================
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    role_id INT REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- =====================
-- ROLE_PERMISSIONS TABLE
-- =====================
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INT REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INT REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- =====================
-- SEED DATA
-- =====================
INSERT INTO roles (name, description) VALUES
    ('admin', 'Full system access'),
    ('user', 'Standard user access')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (name, description) VALUES
    ('view_all_users', 'Can view all users'),
    ('view_all_files', 'Can view all files'),
    ('view_audit_logs', 'Can view audit logs'),
    ('upload_file', 'Can upload files'),
    ('download_own_file', 'Can download own files')
ON CONFLICT (name) DO NOTHING;

-- admin gets all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

-- user gets limited permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'user' AND p.name IN ('upload_file', 'download_own_file')
ON CONFLICT DO NOTHING;