"""Pi5 preflight using the shared target checks; defaults to the Pi5 profile."""
from pathlib import Path
import runpy
import sys

if "--device" in sys.argv:
    raise SystemExit("Device is fixed to pi5 in this entry point")
sys.argv.extend(["--device", "pi5"])
runpy.run_path(str(Path(__file__).resolve().parents[1] / "pi4" / "verify_environment.py"), run_name="__main__")
