from flask import request, redirect, url_for, render_template, session
from flask_bcrypt import Bcrypt
from models import (
    User,
)

bcrypt = Bcrypt()


def login_user(app):
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == "admin" and bcrypt.check_password_hash(
            app.config["ADMIN_PASSWORD_HASH"], password
        ):
            session["admin_logged_in"] = True
            return redirect(url_for("admin_panel"))

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session["logged_in"] = True
            return redirect(url_for("home"))

    return render_template("login.html")
