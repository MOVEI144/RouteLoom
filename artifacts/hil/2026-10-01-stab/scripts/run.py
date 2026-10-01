"""Run the recorded STAB bench tools with this round's evidence directory."""
import importlib.util
import pathlib
import runpy
import sys

repo = pathlib.Path(__file__).resolve().parents[4]
previous = repo / 'artifacts/hil/2026-09-30-stab/scripts'
spec = importlib.util.spec_from_file_location('stablib', previous / 'stablib.py')
h = importlib.util.module_from_spec(spec)
sys.modules['stablib'] = h
spec.loader.exec_module(h)
h.RUN = repo / 'artifacts/hil/2026-10-01-stab'
script = previous / sys.argv[1]
sys.argv = [str(script), *sys.argv[2:]]
runpy.run_path(str(script), run_name='__main__')
