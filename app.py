from xml.parsers.expat import errors

from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime
from db import close_db, init_db, get_db
from auth import authenticate, login_required, role_required, log_action
from werkzeug.security import generate_password_hash

import db

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-this"
    app.config["DATABASE"] = "requests.db"

    app.teardown_appcontext(close_db)

    @app.template_filter("pretty_datetime")
    def pretty_datetime(value):
        if not value:
            return ""
        try:
            dt = datetime.fromisoformat(value)
            return dt.strftime("%b %d, %Y %I:%M %p")
        except Exception:
            return value

    @app.cli.command("init-db")
    def init_db_command():
        init_db()
        print("Initialized the database.")

    @app.context_processor
    def inject_user():
        user = None

        if session.get("user_id"):
            db = get_db()
            user = db.execute(
                """
                SELECT id, first_name, last_name, email, role, department
                FROM users
                WHERE id = ?
                """,
                (session["user_id"],)
            ).fetchone()
        return dict(current_user=user)
    
    @app.route("/account")
    @login_required
    def account_details():
        db = get_db()
        user = db.execute(
            """
            SELECT first_name, last_name, email, role, department, created_at
            FROM users
            WHERE id = ?
            """,
            (session["user_id"],),
        ).fetchone()
        return render_template("account_details.html", user=user)    
        
    @app.route("/")
    def home():
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")

            user = authenticate(email, password)
            if user is None:
                log_action("LOGIN_FAILED")
                flash("Invalid email or password.", "error")
                return render_template("login.html")

            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["name"] = f"{user['first_name']} {user['last_name']}"
            session["department"] = user["department"]

            log_action("LOGIN_SUCCESS")
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            if user["role"] == "director":
                return redirect(url_for("director_dashboard"))
            if user["role"] == "tech":
                return redirect(url_for("tech_dashboard"))
            if user["role"] == "requestor":
                return redirect(url_for("requestor_dashboard"))
        return render_template("login.html")
    
    @app.route("/admin/all_users")
    @login_required
    @role_required("admin")
    def all_users():
        db = get_db()
        rows = db.execute(
            """
            SELECT first_name, last_name, email, department, role, is_active, created_at, id
            FROM users
            ORDER BY first_name DESC
            """
        ).fetchall()
        return render_template("all_users.html", users=rows)
    
    @app.route("/admin/all_requests")
    @login_required
    @role_required("admin")
    def all_requests():
        sort_by = request.args.get("sort_by", "submitted_at")
        sort_dir = request.args.get("sort_dir", "desc")
        filter_user_id = request.args.get("user_id", type=int)

        valid_sort_columns = {
            "id": "r.id",
            "requestor": "requestor_name",
            "camera_location": "r.camera_location",
            "start_time": "r.start_time",
            "end_time": "r.end_time",
            "status": "r.status",
            "submitted_at": "r.submitted_at",
        }

        if sort_by not in valid_sort_columns:
            sort_by = "submitted_at"
        if sort_dir not in ("asc", "desc"):
            sort_dir = "desc"

        params = []
        user_filter = ""
        if filter_user_id:
            user_filter = "AND r.requestor_id = ?"
            params.append(filter_user_id)

        db = get_db()
        requests_rows = db.execute(
            f"""
            SELECT
                r.id,
                u.first_name || ' ' || u.last_name AS requestor_name,
                u.email AS requestor_email,
                r.camera_location,
                r.start_time,
                r.end_time,
                r.reason,
                r.status,
                r.submitted_at,
                r.requestor_id
            FROM footage_requests r
            JOIN users u ON r.requestor_id = u.id
            WHERE r.status != 'Completed' {user_filter}
            ORDER BY {valid_sort_columns[sort_by]} {sort_dir}
            """,
            params,
        ).fetchall()

        users = db.execute(
            """
            SELECT id, first_name || ' ' || last_name AS name
            FROM users
            ORDER BY first_name, last_name
            """
        ).fetchall()

        return render_template(
            "all_requests.html",
            requests=requests_rows,
            users=users,
            selected_user_id=filter_user_id,
            sort_by=sort_by,
            sort_dir=sort_dir,
        )
    @app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
    @login_required
    @role_required("admin")
    def delete_user(user_id):
        return redirect(url_for("all_users"))
    
    
    @app.route("/tech/request/<int:request_id>/submit_delivery", methods=["POST"])
    @login_required
    @role_required("tech", "admin")
    def submit_delivery(request_id):
        technician_name = request.form.get("technician_name", "").strip()
        technician_employee_id = request.form.get("technician_employee_id", "").strip()
        folder_password = request.form.get("folder_password", "").strip()
        footage_location = request.form.get("footage_location", "").strip()

        if not all([technician_name, technician_employee_id, folder_password, footage_location]):
            flash("All fields are required.", "error")
            return redirect(url_for("tech_dashboard"))

        db = get_db()
        req = db.execute(
            "SELECT fr.id FROM footage_requests fr JOIN users u ON fr.requestor_id = u.id WHERE fr.id = ? AND fr.status='Approved' AND u.department = ?",
            (request_id, session.get("department")),
        ).fetchone()
        if not req:
            flash("Request not available for this tech.", "error")
            return redirect(url_for("tech_dashboard"))

        db.execute(
            "INSERT INTO footage_deliveries (request_id, technician_name, technician_employee_id, folder_password, footage_location) VALUES (?, ?, ?, ?, ?)",
            (request_id, technician_name, technician_employee_id, folder_password, footage_location),
        )
        db.execute(
            "UPDATE footage_requests SET status = 'Completed', tech_id = ?, completed_at = datetime('now') WHERE id = ?",
            (session.get("user_id"), request_id)
        )
        db.commit()

        flash("Footage delivery details saved successfully.", "success")
        return redirect(url_for("tech_dashboard"))

    @app.route("/admin/dashboard")
    @login_required
    @role_required("admin")
    def admin_dashboard():
        return render_template("admin_dashboard.html")
    
    @app.route("/tech/dashboard")
    @login_required
    @role_required("admin", "tech")
    def tech_dashboard():
        db = get_db()

        rows = db.execute(
            """
            SELECT
                fr.id,
                fr.building,
                fr.division,
                fr.job_title,
                fr.camera_location,
                fr.start_time,
                fr.end_time,
                fr.reason,
                fr.status,
                fr.submitted_at,
                u.first_name,
                u.last_name,
                u.department
            FROM footage_requests fr
            JOIN users u ON fr.requestor_id = u.id
            WHERE fr.status = 'Approved'
            ORDER BY fr.submitted_at DESC
            """
        ).fetchall()

        return render_template("tech_dashboard.html", requests=rows)

    @app.route("/create-account", methods=["GET", "POST"])
    def create_account():
        if request.method == "POST":
            first_name = request.form.get("first_name", "").strip()
            last_name = request.form.get("last_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            role = request.form.get("role", "")
            department = request.form.get("department", "")
            flash("Account created successfully!", "success")
            db = get_db()

            pw_hash = generate_password_hash(password, method="pbkdf2:sha256")

            db.execute("""
                INSERT OR IGNORE INTO users (first_name, last_name, email, password_hash, role, department)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (first_name, last_name, email, pw_hash, role, department))

            db.commit()
            return redirect(url_for("login"))
        return render_template("create_account.html")

    @app.route("/logout")
    def logout():
        log_action("LOGOUT")
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html",
            name=session.get("name"),
            role=session.get("role"),
        )
    
    # ---- Requestor routes ----
    
    @app.route("/request/new", methods=["GET", "POST"])
    @login_required
    @role_required("requestor", "admin")
    def new_request():
        if request.method == "POST":
            division = request.form.get("division", "").strip()
            job_title = request.form.get("job_title", "").strip()
            camera_location = request.form.get("camera_location", "").strip()
            start_time = request.form.get("start_time", "").strip()
            end_time = request.form.get("end_time", "").strip()
            reason = request.form.get("reason", "").strip()
            building = request.form.get("building", "").strip()

            errors = []
            if not division:
                errors.append("Division is required.")
            if not job_title:
                errors.append("Job title is required.")
            if not camera_location:
                errors.append("Camera number is required.")
            if not start_time:
                errors.append("Start time is required.")
            if not end_time:
                errors.append("End time is required.")
            if not reason:
                errors.append("Reason is required.")
            if not building:
                errors.append("Building is required.")

            try:
                start_dt = datetime.fromisoformat(start_time)
                end_dt = datetime.fromisoformat(end_time)
                if end_dt <= start_dt:
                    errors.append("End time must be after start time.")
            except Exception:
                errors.append("Invalid date/time format.")

            if errors:
                for e in errors:
                    flash(e, "error")
                return render_template("new_request.html")

            db = get_db()
            cur = db.execute(
                """
                INSERT INTO footage_requests
                    (requestor_id, division, job_title, building, camera_location, start_time, end_time, reason, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending')
                """,
                (
                    session["user_id"],
                    division,
                    job_title,
                    building,
                    camera_location,
                    start_time,
                    end_time,
                    reason,
                ),
            )
            db.commit()

            request_id = cur.lastrowid
            log_action("REQUEST_SUBMITTED", request_id=request_id)

            flash(f"Request #{request_id} submitted successfully.", "success")
            return redirect(url_for("requestor_dashboard"))

        return render_template("new_request.html")


    @app.route("/requests/mine")
    @login_required
    @role_required("requestor", "admin")
    def requestor_dashboard():
        db = get_db()
        rows = db.execute(
            """
            SELECT
                id,
                division,
                job_title,
                building,
                camera_location,
                start_time,
                end_time,
                status,
                director_comment,
                submitted_at
            FROM footage_requests
            WHERE requestor_id = ?
            ORDER BY submitted_at DESC
            """,
            (session["user_id"],),
        ).fetchall()

        for row in rows:
            print(dict(row))

        return render_template("requestor_dashboard.html", requests=rows)

    @app.route("/director/dashboard")
    @login_required
    @role_required("director", "admin")
    def director_dashboard():
        db = get_db()
        rows = db.execute(
            """
            SELECT
                fr.id,
                fr.building,
                fr.division,
                fr.job_title,
                fr.camera_location,
                fr.reason,
                fr.start_time,
                fr.end_time,
                fr.status,
                fr.director_comment,
                fr.submitted_at,
                u.first_name,
                u.last_name
            FROM footage_requests fr
            JOIN users u ON fr.requestor_id = u.id
            ORDER BY fr.submitted_at DESC
            """
        ).fetchall()
        return render_template("director_dashboard.html", requests=rows)

    @app.route("/director/request/<int:request_id>/update", methods=["POST"])
    @login_required
    @role_required("director", "admin")
    def update_request_status(request_id):
        action = request.form.get("action", "").strip().lower()
        director_comment = request.form.get("director_comment", "").strip()

        if action not in ["approve", "decline"]:
            flash("Invalid action.", "error")
            return redirect(url_for("director_dashboard"))
        if action == "decline" and not director_comment:
            flash("Director comment is required when declining a request.", "error")
            return redirect(url_for("director_dashboard"))
        
        new_status = "Approved" if action == "approve" else "Denied"

        db = get_db()

        row = db.execute(
            """
            SELECT id, status
            FROM footage_requests
            WHERE id = ?
            """,
            (request_id,)
        ).fetchone()

        if row is None:
            flash("Request not found.", "error")
            return redirect(url_for("director_dashboard"))

        if row["status"] != "Pending":
            flash("That request was already reviewed.", "error")
            return redirect(url_for("director_dashboard"))

        db.execute(
            """
            UPDATE footage_requests
            SET status = ?, director_comment = ?, director_id = ?, decided_at = datetime('now')
            WHERE id = ?
            """,
            (new_status, director_comment, session["user_id"], request_id)
        )
        db.commit()

        log_action(f"REQUEST_{new_status.upper()}", request_id=request_id)
        flash(f"Request #{request_id} {new_status.lower()} successfully.", "success")
        return redirect(url_for("director_dashboard"))
    
    # ---- RBAC test routes ----
    @app.route("/admin")
    @login_required
    @role_required("admin")
    def admin_panel():
        return f"Admin panel. Hello {session.get('name')}!"

    @app.route("/director")
    @login_required
    @role_required("director", "admin")
    def director_panel():
        return f"Director panel. Hello {session.get('name')}!"

    @app.route("/tech")
    @login_required
    @role_required("tech", "admin")
    def tech_panel():
        return f"Tech panel. Hello {session.get('name')}!"

    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)