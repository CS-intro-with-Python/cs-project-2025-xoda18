import os
import logging
from datetime import datetime
from functools import wraps
from logging.handlers import RotatingFileHandler

from flask import Flask, request, session, redirect, url_for, render_template, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# --------------------Models--------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)


class VlessKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey("server.id"), nullable=False)
    key_text = db.Column(db.Text, nullable=False)
    assigned_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    assigned_at = db.Column(db.DateTime, nullable=True)

    server = db.relationship("Server")
    assigned_user = db.relationship("User")


# --------------------Helpers--------------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            abort(403)
        return fn(*args, **kwargs)

    return wrapper


def validate_username_password(username: str, password: str):
    if not username or not password:
        return "username and password are required"
    if len(username) < 3:
        return "username is too short"
    if len(password) < 6:
        return "password is too short"
    return None


def tail_file(path: str, max_lines: int = 200) -> str:
    if not os.path.exists(path):
        return "(log file not found)"
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    return "".join(lines[-max_lines:])


def pick_server_with_free_keys():
    servers = Server.query.order_by(Server.id.asc()).all()
    best_server = None
    best_assigned = None

    for s in servers:
        free_count = VlessKey.query.filter_by(server_id=s.id, assigned_user_id=None).count()
        if free_count <= 0:
            continue

        assigned_count = VlessKey.query.filter(
            VlessKey.server_id == s.id,
            VlessKey.assigned_user_id.isnot(None)
        ).count()

        if best_server is None or assigned_count < best_assigned:
            best_server = s
            best_assigned = assigned_count

    return best_server


def seed_demo_data_if_needed(app: Flask):
    if os.getenv("SEED_DEMO_DATA", "0") != "1":
        return

    if Server.query.count() > 0 or VlessKey.query.count() > 0:
        return

    s1 = Server(name="Server #1")
    s2 = Server(name="Server #2")
    db.session.add_all([s1, s2])
    db.session.commit()

    demo_keys = [
        VlessKey(server_id=s1.id, key_text="vless://DEMO_KEY_1@server1:443?type=tcp&security=reality#demo1"),
        VlessKey(server_id=s1.id, key_text="vless://DEMO_KEY_2@server1:443?type=tcp&security=reality#demo2"),
        VlessKey(server_id=s2.id, key_text="vless://DEMO_KEY_3@server2:443?type=tcp&security=reality#demo3"),
        VlessKey(server_id=s2.id, key_text="vless://DEMO_KEY_4@server2:443?type=tcp&security=reality#demo4"),
    ]
    db.session.add_all(demo_keys)
    db.session.commit()
    app.logger.info("Seeded demo data: 2 servers and %d keys", len(demo_keys))


# --------------------App Factory--------------------

def create_app(test_config: dict | None = None):
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///local.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    if test_config:
        app.config.update(test_config)

    db.init_app(app)

    log_path = os.getenv("LOG_PATH", "/tmp/app.log")
    app.config["LOG_PATH"] = log_path

    app.logger.setLevel(logging.INFO)
    if not any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers):
        file_handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3)
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

    with app.app_context():
        db.create_all()

        admin_user = os.getenv("ADMIN_USERNAME", "admin")
        admin_pass = os.getenv("ADMIN_PASSWORD", "admin12345")

        if not User.query.filter_by(username=admin_user).first():
            u = User(
                username=admin_user,
                password_hash=generate_password_hash(admin_pass),
                is_admin=True
            )
            db.session.add(u)
            db.session.commit()
            app.logger.info("Created default admin user=%s", admin_user)

        seed_demo_data_if_needed(app)

    # --------------------Routes:Auth--------------------

    @app.get("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.get("/register")
    def register_page():
        return render_template("register.html")

    @app.post("/register")
    def register():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        err = validate_username_password(username, password)
        if err:
            app.logger.info("Register failed: %s", err)
            return render_template("register.html", error=err), 400

        if User.query.filter_by(username=username).first():
            app.logger.info("Register failed: username exists=%s", username)
            return render_template("register.html", error="username already exists"), 409

        user = User(username=username, password_hash=generate_password_hash(password), is_admin=False)
        db.session.add(user)
        db.session.commit()

        app.logger.info("User registered id=%s username=%s", user.id, user.username)
        return redirect(url_for("login"))

    @app.get("/login")
    def login():
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            app.logger.info("Login failed for username=%s", username)
            return render_template("login.html", error="invalid credentials"), 401

        session["user_id"] = user.id
        session["is_admin"] = bool(user.is_admin)
        app.logger.info("Login success user_id=%s is_admin=%s", user.id, user.is_admin)

        if user.is_admin:
            return redirect(url_for("admin_panel"))
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    def logout():
        uid = session.get("user_id")
        session.clear()
        app.logger.info("Logout user_id=%s", uid)
        return redirect(url_for("login"))

    # --------------------Routes:User--------------------

    @app.get("/dashboard")
    @login_required
    def dashboard():
        uid = session["user_id"]
        user = User.query.get(uid)
        key = VlessKey.query.filter_by(assigned_user_id=uid).first()
        return render_template("dashboard.html", user=user, key=key)

    @app.post("/api/key")
    @login_required
    def api_get_or_create_key():
        uid = session["user_id"]

        existing = VlessKey.query.filter_by(assigned_user_id=uid).first()
        if existing:
            app.logger.info("Key requested but already assigned user_id=%s key_id=%s", uid, existing.id)
            return jsonify({"key": existing.key_text, "server_id": existing.server_id, "key_id": existing.id})

        server = pick_server_with_free_keys()
        if not server:
            app.logger.error("No free keys available for user_id=%s", uid)
            return jsonify({"error": "no free keys available"}), 503

        key = VlessKey.query.filter_by(server_id=server.id, assigned_user_id=None).order_by(VlessKey.id.asc()).first()
        if not key:
            app.logger.error("Server chosen but no free key found server_id=%s", server.id)
            return jsonify({"error": "internal allocation error"}), 500

        key.assigned_user_id = uid
        key.assigned_at = datetime.utcnow()
        db.session.commit()

        app.logger.info("Assigned key user_id=%s key_id=%s server_id=%s", uid, key.id, server.id)
        return jsonify({"key": key.key_text, "server_id": key.server_id, "key_id": key.id})

    @app.post("/api/key/delete")
    @login_required
    def api_delete_key():
        uid = session["user_id"]
        key = VlessKey.query.filter_by(assigned_user_id=uid).first()
        if not key:
            app.logger.info("Delete key requested but no key for user_id=%s", uid)
            return jsonify({"error": "no key to delete"}), 404

        app.logger.info("Unassigned key user_id=%s key_id=%s", uid, key.id)
        key.assigned_user_id = None
        key.assigned_at = None
        db.session.commit()
        return jsonify({"ok": True})

    # --------------------Routes:Admin--------------------

    @app.get("/admin")
    @admin_required
    def admin_panel():
        users = User.query.order_by(User.id.asc()).all()
        servers = Server.query.order_by(Server.id.asc()).all()

        server_rows = []
        for s in servers:
            total = VlessKey.query.filter_by(server_id=s.id).count()
            free = VlessKey.query.filter_by(server_id=s.id, assigned_user_id=None).count()
            assigned = total - free
            server_rows.append({
                "id": s.id,
                "name": s.name,
                "total": total,
                "free": free,
                "assigned": assigned,
            })

        keys = VlessKey.query.order_by(VlessKey.id.asc()).limit(200).all()
        log_text = tail_file(app.config["LOG_PATH"], max_lines=250)

        return render_template(
            "admin.html",
            users=users,
            servers=server_rows,
            keys=keys,
            log_text=log_text
        )

    @app.post("/admin/add_server")
    @admin_required
    def admin_add_server():
        name = request.form.get("name", "").strip()
        if not name:
            return redirect(url_for("admin_panel"))

        s = Server(name=name)
        db.session.add(s)
        db.session.commit()
        app.logger.info("Admin added server id=%s name=%s", s.id, s.name)
        return redirect(url_for("admin_panel"))

    @app.post("/admin/add_keys")
    @admin_required
    def admin_add_keys():
        server_id = request.form.get("server_id", "").strip()
        raw = request.form.get("keys", "")

        try:
            sid = int(server_id)
        except ValueError:
            return redirect(url_for("admin_panel"))

        srv = Server.query.get(sid)
        if not srv:
            return redirect(url_for("admin_panel"))

        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        added = 0
        for ln in lines:
            db.session.add(VlessKey(server_id=sid, key_text=ln))
            added += 1

        db.session.commit()
        app.logger.info("Admin added %d keys to server_id=%s", added, sid)
        return redirect(url_for("admin_panel"))

    # --------------------Errors--------------------

    @app.errorhandler(403)
    def forbidden(_):
        return "403 Forbidden", 403

    @app.errorhandler(404)
    def not_found(_):
        return "404 Not Found", 404

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
