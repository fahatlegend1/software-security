import ipaddress
import os
import re
import sqlite3
import subprocess
from flask import Flask, abort, request
from werkzeug.security import generate_password_hash

app = Flask(__name__)

# Load secrets from environment variables instead of hardcoding (CWE-798)
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")


def is_valid_host(host: str) -> bool:
    """Validate that the input is a valid IP address or standard hostname."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # Match standard domain/hostname characters (preventing flags like -c or -i)
        hostname_regex = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
        return bool(re.match(hostname_regex, host))


@app.route("/user")
def user():
    name = request.args.get("name", "")
    # Use a context manager to ensure the connection closes properly
    with sqlite3.connect("app.db") as con:
        # FIX (CWE-89): Use parameterized queries (?) instead of string formatting
        q = "SELECT * FROM users WHERE name = ?"
        results = con.execute(q, (name,)).fetchall()
    return str(results)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # FIX (CWE-78): Validate input strictly before passing to a system command
    if not is_valid_host(host):
        abort(400, description="Invalid host format")

    # FIX (CWE-78): Pass arguments as a list and disable shell=True
    output = subprocess.check_output(["ping", "-c", "1", host], text=True)
    return output


def store_password(pw: str) -> str:
    # FIX (CWE-327): Use a salted, slow password hashing function (PBKDF2/scrypt)
    return generate_password_hash(pw)


if __name__ == "__main__":
    # FIX (CWE-489): Disable debug mode by default
    app.run(debug=False)