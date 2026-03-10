"""
test_server.py — Intentionally Vulnerable Test Server
A local Flask server with deliberate security flaws for testing the scanner.

WARNING: Do NOT deploy this in a production environment!
Run with: python test_server.py
"""

from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

INDEX_HTML = """
<!DOCTYPE html>
<html>
<head><title>Test Vulnerable Site</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:2rem auto;background:#1a1a2e;color:#eee;padding:2rem;border-radius:10px">
  <h1>🔓 Vulnerable Test App</h1>
  <p style="color:#aaa">This app is intentionally vulnerable — for scanner testing only.</p>
  <hr style="border-color:#333">
  <ul>
    <li><a href="/login"  style="color:#60a5fa">Login Page</a> (SQL Injection target)</li>
    <li><a href="/search" style="color:#60a5fa">Search Page</a> (XSS target)</li>
    <li><a href="/contact" style="color:#60a5fa">Contact Form</a> (CSRF target)</li>
  </ul>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body style="font-family:sans-serif;max-width:400px;margin:2rem auto;background:#1a1a2e;color:#eee;padding:2rem;border-radius:10px">
  <h2>Login</h2>
  <form method="POST" action="/login">
    <label>Username:<br><input name="username" type="text" style="width:100%;padding:0.4rem;margin:0.5rem 0"></label><br>
    <label>Password:<br><input name="password" type="password" style="width:100%;padding:0.4rem;margin:0.5rem 0"></label><br>
    <input type="submit" value="Login" style="padding:0.5rem 1rem;background:#3b82f6;color:white;border:none;border-radius:5px;cursor:pointer">
  </form>
  {% if msg %}<p style="color:#f87171;margin-top:1rem">{{ msg }}</p>{% endif %}
  <a href="/" style="color:#60a5fa">← Back</a>
</body>
</html>
"""

SEARCH_HTML = """
<!DOCTYPE html>
<html>
<head><title>Search</title></head>
<body style="font-family:sans-serif;max-width:400px;margin:2rem auto;background:#1a1a2e;color:#eee;padding:2rem;border-radius:10px">
  <h2>Search</h2>
  <form method="GET" action="/search">
    <input name="q" type="text" placeholder="Search..." value="{{ query }}"
      style="width:100%;padding:0.4rem;margin:0.5rem 0"><br>
    <input type="submit" value="Search" style="padding:0.5rem 1rem;background:#3b82f6;color:white;border:none;border-radius:5px;cursor:pointer">
  </form>
  {% if query %}
  <p>Results for: {{ query|safe }}</p>
  {% endif %}
  <a href="/" style="color:#60a5fa">← Back</a>
</body>
</html>
"""

CONTACT_HTML = """
<!DOCTYPE html>
<html>
<head><title>Contact</title></head>
<body style="font-family:sans-serif;max-width:400px;margin:2rem auto;background:#1a1a2e;color:#eee;padding:2rem;border-radius:10px">
  <h2>Contact Us</h2>
  <form method="POST" action="/contact">
    <label>Name:<br><input name="name" type="text" style="width:100%;padding:0.4rem;margin:0.5rem 0"></label><br>
    <label>Message:<br><textarea name="message" rows="4" style="width:100%;padding:0.4rem;margin:0.5rem 0"></textarea></label><br>
    <input type="submit" value="Send" style="padding:0.5rem 1rem;background:#3b82f6;color:white;border:none;border-radius:5px;cursor:pointer">
  </form>
  {% if sent %}<p style="color:#4ade80">Message sent!</p>{% endif %}
  <a href="/" style="color:#60a5fa">← Back</a>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Intentionally vulnerable: reflects user input in a fake "SQL error"
        if "'" in username or "--" in username:
            msg = (
                f"You have an error in your SQL syntax near '{username}' "
                f"at line 1: SELECT * FROM users WHERE username='{username}'"
            )
        else:
            msg = "Invalid username or password."
    return render_template_string(LOGIN_HTML, msg=msg)


@app.route("/search", methods=["GET"])
def search():
    # Intentionally reflects query parameter without escaping (XSS)
    query = request.args.get("q", "")
    return render_template_string(SEARCH_HTML, query=query)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    # POST form without CSRF token
    sent = request.method == "POST"
    return render_template_string(CONTACT_HTML, sent=sent)


if __name__ == "__main__":
    print("🚨 Starting vulnerable test server at http://127.0.0.1:5000")
    print("   Press Ctrl+C to stop.\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
