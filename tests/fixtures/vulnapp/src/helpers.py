import sqlite3

def run_query(q):
    cur = sqlite3.connect("app.db").cursor()
    return cur.execute(q)   # parameter 'q' reaches a sink -> registered

def save_file(path):
    return open(path, "w")  # parameter 'path' reaches a sink
