"""
Remediated sample for Week 2 secure coding practice.
The planted vulnerabilities have been fixed for Task 8.
"""

import os
import sqlite3
import subprocess

from argon2 import PasswordHasher
from flask import Flask, request

app = Flask(__name__)
ph = PasswordHasher()


# CWE-798 fix: load secrets from environment variables
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")


@app.route("/user")
def user():
    name = request.args.get("name", "")

    con = sqlite3.connect("app.db")

    # CWE-89 fix: use a parameterized query
    q = "SELECT * FROM users WHERE name = ?"
    rows = con.execute(q, (name,)).fetchall()

    con.close()
    return str(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # CWE-78 fix: do not invoke a shell; pass arguments as a list
    return subprocess.check_output(
        ["ping", "-c", "1", host],
        text=True
    )


def store_password(pw):
    # CWE-327 fix: use Argon2 for password hashing
    return ph.hash(pw)


if __name__ == "__main__":
    # CWE-489 fix: disable Flask debug mode
    app.run(debug=False)