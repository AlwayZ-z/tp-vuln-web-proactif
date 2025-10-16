# app.py -- intentionally vulnerable CTF app (for local use only)
from flask import Flask, request, jsonify, send_from_directory, abort
import sqlite3
import os
import subprocess

APP_ROOT = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(APP_ROOT, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

DB = os.path.join(APP_ROOT, "ctf.db")

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # table for SQLi
    c.execute("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, secret TEXT)")
    # insert a secret containing flag1
    c.execute("DELETE FROM secrets")
    c.execute("INSERT INTO secrets (id, secret) VALUES (1, 'FLAG{SQLI-CTF-123}')")
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return jsonify({
        "msg": "Mini CTF: 3 challenges (SQLi, Upload, Command Injection). Run locally."
    })

# --------- Challenge 1: SQL Injection (vulnerable) -------------
# WARNING: insecure string formatting for SQL query (intended)
@app.route("/sqli")
def sqli():
    # User supplies ?id=...
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # VULN: direct string formatting -> SQL Injection possible
    query = f"SELECT secret FROM secrets WHERE id = {user_id};"
    try:
        c.execute(query)
        row = c.fetchone()
        if row:
            return jsonify({"result": row[0]})
        else:
            return jsonify({"error": "no result"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        conn.close()

# --------- Challenge 2: File Upload + Insecure View (path traversal) -------------
@app.route("/upload", methods=["POST"])
def upload():
    # accepts file under form field 'file'
    f = request.files.get("file")
    if not f:
        return "No file", 400
    filename = f.filename  # intentionally not sanitized
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    f.save(save_path)
    return jsonify({"uploaded": filename, "path": f"/view?file={filename}"})

@app.route("/view")
def view_file():
    # insecure: concatenates path allowing path traversal via '..'
    fname = request.args.get("file", "")
    target = os.path.join(UPLOAD_FOLDER, fname)
    try:
        with open(target, "r", encoding="utf-8", errors="ignore") as fh:
            data = fh.read()
        return data, 200, {"Content-Type": "text/plain; charset=utf-8"}
    except FileNotFoundError:
        return "Not found", 404

# --------- Challenge 3: Command injection (vulnerable) -------------
@app.route("/ping")
def ping():
    # Executes a system ping command with user input (vulnerable)
    host = request.args.get("host", "127.0.0.1")
    # VULN: using shell in subprocess with unsanitized input
    try:
        output = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=5)
        return output.decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors="ignore"), 400
    except Exception as e:
        return str(e), 500

if __name__ == "__main__":
    init_db()
    # create a couple of container-local files with flags for challenges 2 & 3
    os.makedirs("/var/ctf", exist_ok=True)
    with open("/var/ctf/flag_upload.txt", "w") as fh:
        fh.write("FLAG{UPLOAD-CTF-456}\n")
    with open("/flag_cmd.txt", "w") as fh:
        fh.write("FLAG{CMDI-CTF-789}\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
