# llm/local_llm.py

import subprocess


def query_llm(prompt: str) -> str:
    process = subprocess.run(
        ["ollama", "run", "mistral"],
        input=prompt,
        text=True,
        encoding="utf-8",      # ✅ force UTF-8
        errors="ignore",       # ✅ ignore bad chars
        capture_output=True
    )

    if process.returncode != 0:
        raise RuntimeError(process.stderr)

    return process.stdout.strip()
