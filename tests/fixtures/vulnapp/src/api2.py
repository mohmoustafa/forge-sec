from flask import request
from helpers import run_query, save_file

def handler():
    q = request.args.get("q")
    run_query(q)            # cross-file: tainted var into sink-carrying function
    p = request.args.get("p")
    save_file(p)
