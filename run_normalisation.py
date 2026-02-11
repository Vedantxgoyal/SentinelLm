# normalisation/run_normalisation.py

from pathlib import Path
from .normalize import normalize_file

# Project root = SentinelLm/
BASE_DIR = Path(__file__).resolve().parent.parent
DATASETS_DIR = BASE_DIR / "datasets"

# Automatically pick up all JSON datasets
DATASETS = list(DATASETS_DIR.glob("*.json"))

if not DATASETS:
    raise RuntimeError("❌ No JSON files found in datasets/")

for input_path in DATASETS:
    output_path = input_path.with_name(
        input_path.stem + "_normalized.json"
    )

    normalize_file(str(input_path), str(output_path))
