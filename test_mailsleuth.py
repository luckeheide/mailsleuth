import subprocess
import sys
import tempfile
from pathlib import Path

message = "From: test@example.com\\nSubject: Review\\n\\nVisit http://192.0.2.1/reset"
with tempfile.TemporaryDirectory() as directory:
    source = Path(directory, "message.eml")
    source.write_text(message, encoding="utf-8")
    result = subprocess.run([sys.executable, "mailsleuth.py", source], capture_output=True, text=True, check=True)
    assert "suspicious-link" in result.stdout
