import re
from pathlib import Path
import tomllib

import yaml

ROOT = Path(__file__).resolve().parents[2]


def load_yaml(name):
    # BaseLoader retains YAML 1.2/GitHub's "on" key rather than YAML 1.1 booleans.
    return yaml.load((ROOT / name).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_security_workflow_events_history_permissions_and_failure_gate():
    workflow = load_yaml(".github/workflows/codeshield.yml")
    assert set(workflow["on"]) == {"push", "pull_request"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["security"]
    assert job["env"]["GEMINI_API_KEY"] == "" and job["env"]["CODESHIELD_AUTOMATED"] == "1"
    checkout = job["steps"][0]["with"]
    assert checkout["fetch-depth"] == "0" and checkout["persist-credentials"] == "false"
    assert "pull_request.head.sha" in checkout["ref"]
    scan = next(s for s in job["steps"] if s.get("id") == "scan")
    assert scan["continue-on-error"] == "true" and "integrations ci" in scan["run"]
    upload = next(s for s in job["steps"] if "upload-artifact@" in s.get("uses", ""))
    assert upload["if"] == "always()" and upload["with"]["if-no-files-found"] == "error"
    assert job["steps"][-1]["run"] == "exit 1" and "steps.scan.outcome" in job["steps"][-1]["if"]
    text = (ROOT / ".github/workflows/codeshield.yml").read_text()
    assert "pull_request_target" not in text and "secrets." not in text and "--allow-live" not in text


def test_workflows_pin_actions_and_cover_platforms_and_docker():
    for name in ("codeshield.yml", "tests.yml"):
        workflow = load_yaml(".github/workflows/" + name)
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    assert re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", step["uses"])
    tests = load_yaml(".github/workflows/tests.yml")["jobs"]
    assert tests["tests"]["strategy"]["matrix"] == {"os": ["ubuntu-24.04", "windows-2025"], "python": ["3.12", "3.14"]}
    assert "check_docker.py" in tests["docker"]["steps"][-1]["run"]


def test_hook_manifest_is_staged_offline_and_isolated():
    hook, = load_yaml(".pre-commit-hooks.yaml")
    assert hook["entry"] == "python -I -m codeshield.integrations hook"
    assert hook["pass_filenames"] == "false" and hook["always_run"] == "true"
    assert hook["stages"] == ["pre-commit"] and hook["language"] == "python"


def test_locks_pin_all_declared_dependencies_and_runtime_excludes_sdk():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    normalize = lambda s: s.lower().replace("_", "-")
    locks = {}
    for name in ("requirements.lock", "requirements-dev.lock"):
        text = (ROOT / name).read_text()
        pins = dict(re.findall(r"^([a-z0-9-]+)==([^\s]+) \\", text, re.M))
        assert pins and text.count("--hash=sha256:") >= len(pins)
        assert not re.search(r"https?://|^-e |@", text, re.M)
        locks[name] = pins
    dependencies = config["project"]["dependencies"]
    for item in dependencies:
        name, version = item.split("==")
        assert locks["requirements.lock"][normalize(name)] == version
    for group in config["project"]["optional-dependencies"].values():
        for item in group:
            name, version = item.split("==")
            assert locks["requirements-dev.lock"][normalize(name)] == version
    assert "google-genai" not in locks["requirements.lock"]
    assert locks["requirements-dev.lock"].items() >= locks["requirements.lock"].items()


def test_docker_build_uses_allowlisted_inputs_and_offline_nonroot_runtime():
    text = (ROOT / "Dockerfile").read_text()
    assert re.search(r"FROM python:3\.14-bookworm@sha256:[0-9a-f]{64}", text)
    assert "--require-hashes --only-binary=:all:" in text
    assert "USER 10001:10001" in text and '"-I"' in text
    assert "COPY . " not in text and "gemini" not in text.lower()
    assert (ROOT / ".dockerignore").read_text().startswith("**\n")
