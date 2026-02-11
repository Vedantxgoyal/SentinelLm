# detection/run_detection.py

from .detect import run_detection

INPUT_FILE = (
    "datasets/"
    "cmd_bitsadmin_download_psh_script_2020-10-2302365189_normalized.json"
)

OUTPUT_FILE = "reports/alerts/alerts_bitsadmin.json"

run_detection(INPUT_FILE, OUTPUT_FILE)
