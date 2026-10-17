import secrets
from pathlib import Path

root = Path(__file__).resolve().parent.parent
path = root / ".env"
if not path.exists():
    names = [
        "MANAGER_PASSWORD",
        "MANAGER_SECRET",
        "VULNERABLE_SECRET",
        "FIXED_SECRET",
        "MANAGER_DB_PASSWORD",
        "VULNERABLE_DB_PASSWORD",
        "FIXED_DB_PASSWORD",
    ]
    path.write_text(
        "\n".join(f"{n}={secrets.token_hex(32)}" for n in names) + "\nREPAIRED_SERVICE=vulnerable\n",
        encoding="utf-8",
    )
    print("Generated .env; credentials not printed")
else:
    print("Existing .env preserved")
