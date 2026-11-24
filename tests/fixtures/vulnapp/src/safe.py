import subprocess
# legacy shim - reviewed, fixed internal command only
subprocess.run("internal-sync --now", shell=True)  # forge-sec-ignore PY-002
