# functions/registration_functions.py
from flask import request, redirect, url_for, render_template, session, flash
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()


def register_user(users, request, bcrypt):
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        email = request.form["email"]
        phone = request.form["phone"]
        birth_date = request.form["birth_date"]

        users[username] = {
            "password": hashed_password,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "phone": phone,
            "birth_date": birth_date,
        }
        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")
