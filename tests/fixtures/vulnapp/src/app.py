import os, subprocess, hashlib, pickle, requests
from flask import request

PASSWORD = "SuperSecret123!"
DB_URL = "postgres://admin:hunter2@db.internal:5432/app"

def run_cmd():
    cmd = request.args.get("c")
    subprocess.run(cmd, shell=True)          # PY-002
    os.system("tar xf " + cmd)               # PY-002

def get_user():
    uid = request.args.get("uid")
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")   # PY-003

def fetch():
    url = request.args.get("url")
    r = requests.get(url, verify=False)      # PY-009 SSRF + PY-005
    return r.text

def load():
    data = request.data
    return pickle.loads(data)                # PY-004

def pw():
    return hashlib.md5(request.form["password"].encode()).hexdigest()  # PY-007

DEBUG = True
