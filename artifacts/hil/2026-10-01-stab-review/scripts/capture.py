import importlib.util,sys
from pathlib import Path
root=Path(__file__).resolve().parents[4]
spec=importlib.util.spec_from_file_location('stablib',root/'artifacts/hil/2026-09-30-stab/scripts/stablib.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
h.boot_capture(sys.argv[1],float(sys.argv[2]),sys.argv[3],False)
