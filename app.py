"""
Simple Flask upload app -> CAPEv2 sandbox.

Flow: upload -> save in quarantine (random name) -> SHA-256 -> submit to CAPE
      -> status page polls CAPE -> shows verdict (malscore + signatures).

Run:
    export CAPE_URL=http://<cape-host>:8000
    export CAPE_TOKEN=<token>          # leave empty if token auth is off
    export SECRET_KEY=<random string>
    python app.py
"""
import hashlib
import os
import sqlite3
import uuid
from pathlib import Path

import requests
from flask import Flask, abort, redirect, render_template_string, request, url_for, flash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
QUARANTINE = BASE_DIR / "quarantine"
QUARANTINE.mkdir(exist_ok=True)
DB = BASE_DIR / "jobs.db"

CAPE_URL = os.environ.get("CAPE_URL", "http://127.0.0.1:8000").rstrip("/")
CAPE_TOKEN = os.environ.get("CAPE_TOKEN", "")
BLOCK_SCORE = 7.0    # malscore >= this  -> MALICIOUS
REVIEW_SCORE = 4.0   # malscore >= this  -> SUSPICIOUS (manual review)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB


# ---------- helpers ----------
def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.execute(
            """CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                filename TEXT, sha256 TEXT, stored_path TEXT,
                task_id INTEGER, status TEXT, verdict TEXT,
                malscore REAL, signatures TEXT,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""
        )


def cape_headers():
    return {"Authorization": f"Token {CAPE_TOKEN}"} if CAPE_TOKEN else {}


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def submit_to_cape(path, original_name):
    with open(path, "rb") as f:
        r = requests.post(
            f"{CAPE_URL}/apiv2/tasks/create/file/",
            headers=cape_headers(),
            files={"file": (original_name, f)},
            data={"timeout": 180, "enforce_timeout": "1"},
            timeout=60,
        )
    r.raise_for_status()
    body = r.json()
    if body.get("error"):
        raise RuntimeError(body.get("error_value") or str(body))
    return body["data"]["task_ids"][0]


def refresh_job(job):
    """Ask CAPE for status; when reported, fetch the report and set a verdict."""
    if job["verdict"] or not job["task_id"]:
        return job
    try:
        s = requests.get(
            f"{CAPE_URL}/apiv2/tasks/status/{job['task_id']}/",
            headers=cape_headers(), timeout=30,
        ).json()
        status = s.get("data", "unknown")
    except requests.RequestException:
        return job  # CAPE unreachable; keep old state, fail closed (no verdict)

    verdict, score, sigs = None, None, None
    if status == "reported":
        rep = requests.get(
            f"{CAPE_URL}/apiv2/tasks/get/report/{job['task_id']}/json/",
            headers=cape_headers(), timeout=120,
        ).json()
        score = float(rep.get("malscore", 0))
        sigs = ", ".join(x.get("name", "") for x in rep.get("signatures", [])[:30])
        verdict = ("MALICIOUS" if score >= BLOCK_SCORE
                   else "SUSPICIOUS" if score >= REVIEW_SCORE else "CLEAN")
    elif status in ("failed_analysis", "failed_processing"):
        verdict = "ERROR"  # fail closed: never treat as clean

    with db() as con:
        con.execute(
            "UPDATE jobs SET status=?, verdict=?, malscore=?, signatures=? WHERE id=?",
            (status, verdict, score, sigs, job["id"]),
        )
        return con.execute("SELECT * FROM jobs WHERE id=?", (job["id"],)).fetchone()


# ---------- templates ----------
BASE = """
<!doctype html><title>Sandbox Upload</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px}
 .box{border:1px solid #ccc;border-radius:8px;padding:20px;margin-bottom:20px}
 .CLEAN{color:#0a7d2c}.SUSPICIOUS{color:#b36b00}.MALICIOUS,.ERROR{color:#b00020}
 table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid #eee;padding:6px;text-align:left}
 .flash{background:#fff3cd;padding:8px;border-radius:6px;margin-bottom:10px}
</style>
{% with m = get_flashed_messages() %}{% for x in m %}<div class="flash">{{x}}</div>{% endfor %}{% endwith %}
"""

INDEX = BASE + """
<h1>Upload file for sandbox analysis</h1>
<div class="box">
 <form method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
  <input type="file" name="file" required>
  <button type="submit">Upload &amp; analyze</button>
 </form>
 <p><small>Max 50 MB. Files are analyzed in an isolated sandbox and are never executed on this server.</small></p>
</div>
<h2>Recent submissions</h2>
<table>
 <tr><th>File</th><th>Status</th><th>Verdict</th><th></th></tr>
 {% for j in jobs %}
 <tr><td>{{ j['filename'] }}</td><td>{{ j['status'] }}</td>
     <td class="{{ j['verdict'] }}">{{ j['verdict'] or '...' }}</td>
     <td><a href="{{ url_for('status', job_id=j['id']) }}">details</a></td></tr>
 {% endfor %}
</table>
"""

STATUS = BASE + """
{% if not job['verdict'] %}<meta http-equiv="refresh" content="10">{% endif %}
<h1>Analysis result</h1>
<div class="box">
 <p><b>File:</b> {{ job['filename'] }}</p>
 <p><b>SHA-256:</b> <code>{{ job['sha256'] }}</code></p>
 <p><b>CAPE task:</b> {{ job['task_id'] }}</p>
 <p><b>Status:</b> {{ job['status'] }}</p>
 <p><b>Verdict:</b> <span class="{{ job['verdict'] }}">{{ job['verdict'] or 'Analyzing... (page refreshes automatically)' }}</span></p>
 {% if job['malscore'] is not none %}<p><b>Malscore:</b> {{ job['malscore'] }}</p>{% endif %}
 {% if job['signatures'] %}<p><b>Signatures:</b> {{ job['signatures'] }}</p>{% endif %}
</div>
<a href="{{ url_for('index') }}">&larr; Back</a>
"""


# ---------- routes ----------
@app.route("/")
def index():
    with db() as con:
        jobs = con.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT 20").fetchall()
    return render_template_string(INDEX, jobs=jobs)


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("No file selected.")
        return redirect(url_for("index"))

    original = secure_filename(f.filename) or "upload.bin"
    job_id = uuid.uuid4().hex
    stored = QUARANTINE / job_id          # random name, no extension, not executable
    f.save(stored)
    os.chmod(stored, 0o640)

    digest = sha256_of(stored)
    try:
        task_id = submit_to_cape(stored, original)
        status = "pending"
    except Exception as e:                # fail closed
        task_id, status = None, "submit_failed"
        flash(f"Could not submit to sandbox: {e}")

    with db() as con:
        con.execute(
            "INSERT INTO jobs (id, filename, sha256, stored_path, task_id, status, verdict) "
            "VALUES (?,?,?,?,?,?,?)",
            (job_id, original, digest, str(stored), task_id, status,
             "ERROR" if task_id is None else None),
        )
    return redirect(url_for("status", job_id=job_id))


@app.route("/status/<job_id>")
def status(job_id):
    with db() as con:
        job = con.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        abort(404)
    job = refresh_job(job)
    return render_template_string(STATUS, job=job)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
