"""S-ARM: Bicep build and the generated content document."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BICEP = ROOT / "packaging" / "sentinel" / "bicep"


def _compiler():
    if shutil.which("az"):
        return ["az", "bicep", "build", "--file"]
    if shutil.which("bicep"):
        return ["bicep", "build"]
    return None


def test_s_arm_01_bicep_builds(tmp_path):
    command = _compiler()
    if command is None:
        pytest.skip("neither az nor bicep is on PATH")
    for name in ("main.bicep", "content.bicep"):
        out = tmp_path / f"{name}.json"
        if command[0] == "az":
            proc = subprocess.run(command + [str(BICEP / name), "--outfile", str(out)],
                                  capture_output=True, text=True)
        else:
            proc = subprocess.run(command + [str(BICEP / name), "--outfile", str(out)],
                                  capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        combined = proc.stdout + proc.stderr
        assert "Warning" not in combined, combined
    built = json.loads((tmp_path / "main.bicep.json").read_text(encoding="utf-8"))
    blob = json.dumps(built)
    assert "3913510d-42f4-4e42-8a64-420c390055eb" in blob
    assert '"Direct"' in blob or "'Direct'" in blob


def test_s_arm_02_generated_content_matches():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "build_content", ROOT / "packaging" / "sentinel" / "tools" / "build_content.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    text = json.dumps(module.build(), indent=2, sort_keys=True) + "\n"
    assert (BICEP / "content.generated.json").read_text(encoding="utf-8") == text
