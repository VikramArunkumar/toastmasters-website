import os
import sqlite3
from functools import wraps
from pathlib import Path
from uuid import uuid4
from io import BytesIO

from flask import Flask, flash, redirect, render_template, request, session, url_for, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import qrcode

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "toastmasters.db"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-this-secret")
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@d101tm.org").strip().lower()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

ROLES = [
    "District Director",
    "Program Quality Director",
    "Club Growth Director",
]
ROLES += [f"Division {d} Director" for d in ["A", "B", "C", "D", "E", "G"]]
for division, count in {"A": 4, "B": 6, "C": 5, "D": 5, "E": 5, "G": 5}.items():
    ROLES += [f"Area Director {division}{i}" for i in range(1, count + 1)]

SITE_CARDS = [
    ("About District 101", "A lively and diverse Toastmasters community that puts members first and supports members at every level."),
    ("Join", "Find a club that fits your goals, schedule, and location across the District 101 region."),
    ("Member Resources", "Tools to help members grow through communication, leadership, Pathways, and service."),
    ("Officer Resources", "A one-stop source for club and district officer tips, training, forms, and leadership tools."),
    ("Become a District Leader", "Explore district leadership opportunities through contests, trainings, conferences, and special events."),
    ("Calendar", "District 101 hosts trainings, contests, workshops, conferences, and other community events."),
]


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                linkedin TEXT,
                password_hash TEXT NOT NULL,
                officer_role TEXT,
                profile_picture TEXT,
                pending_officer_role TEXT,
                officer_role_status TEXT DEFAULT 'none',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                event_time TEXT NOT NULL,
                picture TEXT,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS event_checkins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                checked_in_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(event_id, email),
                FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
            )
            """
        )
        # Lightweight migrations for existing local databases.
        columns = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "pending_officer_role" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN pending_officer_role TEXT")
        if "officer_role_status" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN officer_role_status TEXT DEFAULT 'none'")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Please log in as an admin first.", "warning")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


def approved_officer_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("admin_logged_in"):
            return view(*args, **kwargs)
        user = current_user()
        if not user:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        if user["officer_role_status"] != "approved" or not user["officer_role"]:
            flash("Only approved officers or admins can manage events.", "warning")
            return redirect(url_for("events"))
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_globals():
    return {"current_user": current_user(), "roles": ROLES, "is_admin": session.get("admin_logged_in", False)}


@app.route("/")
def home():
    with get_db() as conn:
        leaders = conn.execute(
            "SELECT name, email, linkedin, officer_role, profile_picture FROM users WHERE officer_role_status = 'approved' AND officer_role IS NOT NULL AND officer_role != '' ORDER BY officer_role"
        ).fetchall()
    leader_map = {leader["officer_role"]: leader for leader in leaders}
    return render_template("home.html", site_cards=SITE_CARDS, leader_map=leader_map)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            flash("Welcome back!", "success")
            return redirect(url_for("profile"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 6:
            flash("Name, email, and a password of at least 6 characters are required.", "warning")
            return render_template("register.html")
        try:
            with get_db() as conn:
                cur = conn.execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    (name, email, generate_password_hash(password)),
                )
                session["user_id"] = cur.lastrowid
            flash("Account created. Complete your profile below.", "success")
            return redirect(url_for("profile"))
        except sqlite3.IntegrityError:
            flash("An account with that email already exists.", "danger")
    return render_template("register.html")




@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            flash("Admin login successful.", "success")
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin email or password.", "danger")
    return render_template("admin_login.html", admin_email=ADMIN_EMAIL)


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    with get_db() as conn:
        pending_roles = conn.execute(
            "SELECT id, name, email, officer_role, pending_officer_role, officer_role_status, created_at FROM users WHERE officer_role_status = 'pending' ORDER BY created_at DESC"
        ).fetchall()
        users = conn.execute(
            "SELECT id, name, email, linkedin, officer_role, pending_officer_role, officer_role_status, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
        events = conn.execute(
            """
            SELECT e.*, u.name AS creator_name, COUNT(c.id) AS checkin_count
            FROM events e
            LEFT JOIN users u ON e.created_by = u.id
            LEFT JOIN event_checkins c ON e.id = c.event_id
            GROUP BY e.id
            ORDER BY e.event_time ASC
            """
        ).fetchall()
    return render_template("admin_dashboard.html", pending_roles=pending_roles, users=users, events=events)


@app.route("/admin/roles/<int:user_id>/approve", methods=["POST"])
@admin_required
def admin_approve_role(user_id):
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["officer_role_status"] != "pending" or not user["pending_officer_role"]:
            flash("No pending role request found for that user.", "warning")
        else:
            conn.execute(
                "UPDATE users SET officer_role = pending_officer_role, pending_officer_role = NULL, officer_role_status = 'approved' WHERE id = ?",
                (user_id,),
            )
            flash(f"Approved {user['name']} for {user['pending_officer_role']}.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/roles/<int:user_id>/decline", methods=["POST"])
@admin_required
def admin_decline_role(user_id):
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["officer_role_status"] != "pending":
            flash("No pending role request found for that user.", "warning")
        else:
            conn.execute(
                "UPDATE users SET pending_officer_role = NULL, officer_role_status = CASE WHEN officer_role IS NULL OR officer_role = '' THEN 'none' ELSE 'approved' END WHERE id = ?",
                (user_id,),
            )
            flash(f"Declined role request for {user['name']}.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/<int:user_id>/clear-role", methods=["POST"])
@admin_required
def admin_clear_user_role(user_id):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET officer_role = NULL, pending_officer_role = NULL, officer_role_status = 'none' WHERE id = ?",
            (user_id,),
        )
    flash("User officer role cleared.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if session.get("user_id") == user_id:
        session.pop("user_id", None)
    with get_db() as conn:
        conn.execute("DELETE FROM event_checkins WHERE email IN (SELECT email FROM users WHERE id = ?)", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    flash("User deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        linkedin = request.form.get("linkedin", "").strip() or None
        requested_role = request.form.get("officer_role", "").strip() or None
        picture_path = user["profile_picture"]

        if requested_role and requested_role not in ROLES:
            flash("Please select a valid officer role.", "warning")
            return redirect(url_for("profile"))

        file = request.files.get("profile_picture")
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Use a PNG, JPG, GIF, or WEBP image.", "warning")
                return redirect(url_for("profile"))
            ext = secure_filename(file.filename).rsplit(".", 1)[1].lower()
            filename = f"{uuid4().hex}.{ext}"
            file.save(UPLOAD_DIR / filename)
            picture_path = f"uploads/{filename}"

        try:
            with get_db() as conn:
                current_approved_role = user["officer_role"] if user["officer_role_status"] == "approved" else None
                if requested_role == current_approved_role:
                    pending_role = None
                    role_status = "approved" if requested_role else "none"
                    approved_role = requested_role
                    role_message = "Profile saved."
                elif requested_role:
                    pending_role = requested_role
                    role_status = "pending"
                    approved_role = current_approved_role
                    role_message = "Profile saved. Your officer role request is pending backend approval."
                else:
                    pending_role = None
                    role_status = "none"
                    approved_role = None
                    role_message = "Profile saved. Officer role cleared."

                conn.execute(
                    "UPDATE users SET name = ?, email = ?, linkedin = ?, officer_role = ?, pending_officer_role = ?, officer_role_status = ?, profile_picture = ? WHERE id = ?",
                    (name, email, linkedin, approved_role, pending_role, role_status, picture_path, user["id"]),
                )
            flash(role_message, "success")
        except sqlite3.IntegrityError:
            flash("That email is already in use.", "danger")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)


@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    user = current_user()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    if not check_password_hash(user["password_hash"], current_password):
        flash("Current password is incorrect.", "danger")
    elif len(new_password) < 6:
        flash("New password must be at least 6 characters.", "warning")
    else:
        with get_db() as conn:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), user["id"]))
        flash("Password changed.", "success")
    return redirect(url_for("profile"))


@app.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    user = current_user()
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    session.clear()
    flash("Your account has been deleted.", "info")
    return redirect(url_for("home"))


@app.route("/leadership")
def leadership():
    with get_db() as conn:
        leaders = conn.execute(
            "SELECT name, email, linkedin, officer_role, profile_picture FROM users WHERE officer_role_status = 'approved' AND officer_role IS NOT NULL AND officer_role != ''"
        ).fetchall()
    leader_map = {leader["officer_role"]: leader for leader in leaders}
    return render_template("leadership.html", leader_map=leader_map)




@app.route("/events")
def events():
    with get_db() as conn:
        events = conn.execute(
            """
            SELECT e.*, u.name AS creator_name,
                   COUNT(c.id) AS checkin_count
            FROM events e
            LEFT JOIN users u ON e.created_by = u.id
            LEFT JOIN event_checkins c ON e.id = c.event_id
            GROUP BY e.id
            ORDER BY e.event_time ASC
            """
        ).fetchall()
    return render_template("events.html", events=events)


@app.route("/events/add", methods=["GET", "POST"])
@approved_officer_required
def add_event():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        event_time = request.form.get("event_time", "").strip()
        picture_path = None
        if not title or not event_time:
            flash("Event title and time are required.", "warning")
            return redirect(url_for("add_event"))
        file = request.files.get("picture")
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Use a PNG, JPG, GIF, or WEBP image.", "warning")
                return redirect(url_for("add_event"))
            ext = secure_filename(file.filename).rsplit(".", 1)[1].lower()
            filename = f"event-{uuid4().hex}.{ext}"
            file.save(UPLOAD_DIR / filename)
            picture_path = f"uploads/{filename}"
        with get_db() as conn:
            conn.execute(
                "INSERT INTO events (title, event_time, picture, created_by) VALUES (?, ?, ?, ?)",
                (title, event_time, picture_path, current_user()["id"] if current_user() else None),
            )
        flash("Event added.", "success")
        return redirect(url_for("events"))
    return render_template("event_form.html", event=None)


@app.route("/events/<int:event_id>/edit", methods=["GET", "POST"])
@approved_officer_required
def edit_event(event_id):
    with get_db() as conn:
        event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not event:
        flash("Event not found.", "danger")
        return redirect(url_for("events"))
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        event_time = request.form.get("event_time", "").strip()
        picture_path = event["picture"]
        if not title or not event_time:
            flash("Event title and time are required.", "warning")
            return redirect(url_for("edit_event", event_id=event_id))
        file = request.files.get("picture")
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Use a PNG, JPG, GIF, or WEBP image.", "warning")
                return redirect(url_for("edit_event", event_id=event_id))
            ext = secure_filename(file.filename).rsplit(".", 1)[1].lower()
            filename = f"event-{uuid4().hex}.{ext}"
            file.save(UPLOAD_DIR / filename)
            picture_path = f"uploads/{filename}"
        with get_db() as conn:
            conn.execute(
                "UPDATE events SET title = ?, event_time = ?, picture = ? WHERE id = ?",
                (title, event_time, picture_path, event_id),
            )
        flash("Event updated.", "success")
        return redirect(url_for("events"))
    return render_template("event_form.html", event=event)


@app.route("/events/<int:event_id>/delete", methods=["POST"])
@approved_officer_required
def delete_event(event_id):
    with get_db() as conn:
        conn.execute("DELETE FROM event_checkins WHERE event_id = ?", (event_id,))
        conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
    flash("Event deleted.", "info")
    return redirect(url_for("events"))


@app.route("/events/<int:event_id>/check-in", methods=["GET", "POST"])
def check_in(event_id):
    with get_db() as conn:
        event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not event:
        flash("Event not found.", "danger")
        return redirect(url_for("events"))
    user = current_user()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        if not name or not email:
            flash("Name and email are required to check in.", "warning")
            return redirect(url_for("check_in", event_id=event_id))
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO event_checkins (event_id, name, email) VALUES (?, ?, ?)",
                    (event_id, name, email),
                )
            flash("You are checked in. Welcome!", "success")
        except sqlite3.IntegrityError:
            flash("This email is already checked in for this event.", "info")
        return redirect(url_for("events"))
    return render_template("check_in.html", event=event, user=user)


@app.route("/events/<int:event_id>/qr")
def event_qr(event_id):
    with get_db() as conn:
        event = conn.execute("SELECT id FROM events WHERE id = ?", (event_id,)).fetchone()
    if not event:
        flash("Event not found.", "danger")
        return redirect(url_for("events"))
    checkin_url = url_for("check_in", event_id=event_id, _external=True)
    img = qrcode.make(checkin_url)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return send_file(buffer, mimetype="image/png")


@app.route("/events/<int:event_id>/check-ins")
@approved_officer_required
def event_checkins(event_id):
    with get_db() as conn:
        event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        checkins = conn.execute(
            "SELECT name, email, checked_in_at FROM event_checkins WHERE event_id = ? ORDER BY checked_in_at DESC",
            (event_id,),
        ).fetchall()
    if not event:
        flash("Event not found.", "danger")
        return redirect(url_for("events"))
    return render_template("event_checkins.html", event=event, checkins=checkins)


def list_role_requests():
    with get_db() as conn:
        return conn.execute(
            "SELECT id, name, email, pending_officer_role FROM users WHERE officer_role_status = 'pending' ORDER BY created_at"
        ).fetchall()


def approve_role_request(email):
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
        if not user or user["officer_role_status"] != "pending" or not user["pending_officer_role"]:
            return False
        conn.execute(
            "UPDATE users SET officer_role = pending_officer_role, pending_officer_role = NULL, officer_role_status = 'approved' WHERE id = ?",
            (user["id"],),
        )
    return True


def decline_role_request(email):
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
        if not user or user["officer_role_status"] != "pending":
            return False
        conn.execute(
            "UPDATE users SET pending_officer_role = NULL, officer_role_status = CASE WHEN officer_role IS NULL OR officer_role = '' THEN 'none' ELSE 'approved' END WHERE id = ?",
            (user["id"],),
        )
    return True


init_db()

if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 2 and sys.argv[1] == "role-requests":
        rows = list_role_requests()
        if not rows:
            print("No pending officer role requests.")
        for row in rows:
            print(f"{row['id']}: {row['name']} <{row['email']}> requested {row['pending_officer_role']}")
    elif len(sys.argv) >= 3 and sys.argv[1] == "approve-role":
        print("Approved." if approve_role_request(sys.argv[2]) else "No pending request found for that email.")
    elif len(sys.argv) >= 3 and sys.argv[1] == "decline-role":
        print("Declined." if decline_role_request(sys.argv[2]) else "No pending request found for that email.")
    else:
        app.run(debug=True)
