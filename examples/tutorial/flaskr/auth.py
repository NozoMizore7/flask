import functools

from flask import Blueprint
from flask import flash
from flask import g
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

from flaskr.db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth")


def login_required(view):
    """View decorator that redirects anonymous users to the login page."""

    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))

        return view(**kwargs)

    return wrapped_view


@bp.before_app_request
def load_logged_in_user():
    """If a user id is stored in the session, load the user object from
    the database into ``g.user``."""
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        cursor = get_db().cursor()
        cursor.execute("SELECT * FROM user WHERE id = %s", (user_id,))
        g.user = cursor.fetchone()


@bp.route("/register", methods=("GET", "POST"))
def register():
    """Register a new user.

    Validates that the username is not already taken. Hashes the
    password for security.
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        error = None

        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."

        if error is None:
            try:
                db.cursor().execute(
                    "INSERT INTO user (username, password) VALUES (%s, %s)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                # The username was already taken, which caused the
                # commit to fail. Show a validation error.
                error = f"User {username} is already registered."
            else:
                # Success, go to the login page.
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template("auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    """Log in a registered user by adding the user id to the session."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        error = None
        cursor = db.cursor()
        cursor.execute(
            "SELECT * FROM user WHERE username = %s", (username,)
        )
        user = cursor.fetchone()

        if user is None:
            error = "Incorrect username."
        elif not check_password_hash(user["password"], password):
            error = "Incorrect password."

        if error is None:
            # store the user id in a new session and return to the index
            session.clear()
            session["user_id"] = user["id"]
            flash('logged in successfully.')
            return redirect(url_for("index"))

        flash(error)

    return render_template("auth/login.html")


@bp.route("/info", methods=("GET", "POST"))
def info():
    def set_password():
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        db = get_db()
        error = None
        cursor = db.cursor()
        cursor.execute(
            "SELECT * FROM user WHERE id = %s", (g.user["id"],)
        )
        user = cursor.fetchone()

        if not check_password_hash(user["password"], old_password):
            error = "Incorrect old password."
        elif not new_password:
            error = "New password is illegal."
        elif new_password == old_password:
            error = "New password must be different."
        elif new_password != confirm_password:
            error = "Inconsistent between new password and confirmation."

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.cursor().execute(
                "UPDATE user SET password = %s WHERE id = %s",
                (generate_password_hash(confirm_password), g.user["id"],)
            )
            db.commit()
            flash('password updated successfully.')

    def set_info(info_type: str, nullable: bool = True):
        info_data = request.form[info_type]
        error = None

        if not nullable and not info_data:
            error = info_type + " is illegal."

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.cursor().execute(
                "UPDATE user SET " + info_type + " = %s WHERE id = %s",
                (info_data, g.user["id"],)
            )
            db.commit()
            g.user[info_type] = info_data
            flash(info_type + ' updated successfully.')

    """change information of user"""
    ret = render_template("auth/info.html")
    if request.method == "POST":
        ret = redirect(url_for("auth.info"))
        print(request.form)
        form_id = request.args.get('form_id', 1, type=int)
        if request.form["submit"] == "Set password":
            set_password()
        elif request.form["submit"] == "Set contact name":
            set_info("contact_name")
        elif request.form["submit"] == "Set email":
            set_info("email")
        elif request.form["submit"] == "Set address":
            set_info("address1")
            set_info("address2")
            set_info("city")
            set_info("state")
            set_info("postal_code")
        else:
            flash("invalid form")

    return ret


@bp.route("/logout")
def logout():
    """Clear the current session, including the stored user id."""
    session.clear()
    return redirect(url_for("index"))
