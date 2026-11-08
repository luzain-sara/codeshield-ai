import math

import pytest

from codeshield.config import Config, ConfigError, load_config
from codeshield.detectors.context import code_lines
from codeshield.detectors.entropy import shannon_entropy
from codeshield.detectors.patterns import Detector, safe_path
from codeshield.errors import ScanError

# Deliberately synthetic literals; these values cannot authenticate to a service.
VALUE = "SyntheticCredentialZ9_q7!"


@pytest.mark.parametrize("source", [
    'API_KEY = "' + VALUE + '"',
    'API_KEY: str = "' + VALUE + '"',
    'const apiKey = "' + VALUE + '";',
    '{"password": "' + VALUE + '"}',
    "password: '" + VALUE + "'",
    "ACCESS_TOKEN=" + VALUE,
    'client_secret = "' + VALUE + '"',
])
def test_credential_assignments(source):
    result = Detector(Config()).find(source)
    assert len(result) == 1
    assert result[0].rule_id == "secret-assignment"
    assert VALUE not in repr(result)


@pytest.mark.parametrize("value,rule", [
    ("AKIA" + "Z" * 16, "aws-access-key"),
    ("ghp_" + "Z" * 36, "github-token"),
    ("github_pat_" + "Z" * 50, "github-token"),
    ("AIza" + "Z" * 35, "google-api-key"),
    ("sk-proj-" + "Z" * 25, "openai-api-key"),
    ("xoxb-" + "Z" * 25, "slack-token"),
    ("sk_live_" + "Z" * 25, "stripe-secret-key"),
])
def test_prefixes_win_over_assignment_and_deduplicate(value, rule):
    results = Detector(Config()).find(f'API_KEY = "{value}"')
    assert len(results) == 1
    assert results[0].rule_id == rule


@pytest.mark.parametrize("scheme", ["Bearer", "Basic"])
def test_authorization(scheme):
    result = Detector(Config()).find(f'"Authorization": "{scheme} {VALUE}"')
    assert len(result) == 1
    assert result[0].rule_id == "authorization-header"


def test_multiple_values_same_line():
    results = Detector(Config()).find(f'password="{VALUE}"; apiKey="{VALUE}Other"')
    assert len(results) == 2
    assert results[0].start < results[1].start


@pytest.mark.parametrize("source", [
    'const config = {apiKey: "' + VALUE + '"};',
    'config = {"password": "' + VALUE + '"}',
    'class Settings:\n    API_KEY = "' + VALUE + '"',
])
def test_nested_config_assignments_are_detected(source):
    detector = Detector(Config())
    assert any(detector.find(line, allow_bare=False) for line in code_lines(source, "a.py"))


@pytest.mark.parametrize("source", [
    'API_KEY="YOUR_API_KEY"', 'password="dummy_password"', 'password="changeme"',
    'apiKey="<INSERT_KEY>"', 'apiKey="${API_KEY}"', 'apiKey=os.environ["API_KEY"]',
    'apiKey=os.getenv("API_KEY")', 'const apiKey=process.env.API_KEY;',
    'password=null', 'password="short"',
    'client_id="' + VALUE + '"', 'public_key="' + VALUE + '"',
    'checksum="' + "abcdef0123456789" * 4 + '"',
    'session="' + "abcdef0123456789" * 2 + '"',
    'session="550e8400-e29b-41d4-a716-446655440000"',
    'identifier="xW7vB2mQ8zA4kT9rY6pL1sD5"',
    'apiKey="AKIAIOSFODNN7EXAMPLE"',
])
def test_false_positives(source):
    assert Detector(Config()).find(source) == []


def test_hexadecimal_value_with_explicit_password_context_is_not_assumed_hash():
    assert Detector(Config()).find('password="' + "abcdef0123456789" * 2 + '"')


def test_entropy_requires_context_and_respects_threshold():
    value = "xW7vB2mQ8zA4kT9rY6pL1sD5"
    source = f'session="{value}"'
    result = Detector(Config()).find(source)
    assert result[0].rule_id == "high-entropy-secret"
    assert result[0].severity == "medium"
    assert not Detector(Config(entropy_threshold=8)).find(source)
    assert not Detector(Config()).find('session="zzzzzzzzzzzzzzzzzzzzzzzz"')


def test_entropy_values():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert math.isclose(shannon_entropy("abcd"), 2)


@pytest.mark.parametrize("path,source", [
    ("a.py", '# password="' + VALUE + '"'),
    ("a.ts", '// password="' + VALUE + '"'),
    ("a.ts", '/*\npassword="' + VALUE + '"\n*/'),
    ("a.py", '"""\npassword="' + VALUE + '"\n"""'),
    ("a.yaml", '# password: "' + VALUE + '"'),
    ("a.py", 'password="' + VALUE + '" # codeshield: test-fixture'),
    ("a.ts", 'password="' + VALUE + '" // codeshield: test-fixture'),
])
def test_comments_docstrings_and_explicit_fixtures(path, source):
    detector = Detector(Config())
    assert not any(detector.find(line) for line in code_lines(source, path))


def test_url_and_comment_tokens_inside_string_do_not_hide_secret():
    line = 'password="https://synthetic.invalid/part#value//value" # harmless'
    assert Detector(Config()).find(code_lines(line, "a.py")[0])


def test_fixture_marker_inside_string_does_not_suppress():
    line = f'password="{VALUE}"; message="codeshield: test-fixture"'
    assert Detector(Config()).find(code_lines(line, "a.py")[0])


def test_custom_pattern(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[[patterns]]\nrule_id="internal"\nexpression="(?P<secret>INTERNAL_[A-Z]{10})"\nseverity="critical"', encoding="utf-8")
    result = Detector(load_config(path)).find('value="INTERNAL_ZZZZZZZZZZ"')
    assert result[0].rule_id == "custom-internal"
    assert result[0].severity == "critical"


@pytest.mark.parametrize("expression", ["[", "abc", "(?P<secret>.*)"])
def test_invalid_pattern_config_is_safe(tmp_path, expression):
    path = tmp_path / "config.toml"
    path.write_text(f'[[patterns]]\nrule_id="internal"\nexpression="{expression}"', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_configured_regex_timeout_fails_closed():
    config = Config(patterns=({"rule_id": "slow", "expression": "(?P<secret>(a+)+)$"},))
    with pytest.raises(ScanError, match="timed out"):
        Detector(config).find("a" * 20000 + "!")


def test_path_redaction_and_controls():
    path = "dir/" + VALUE + "/user@example.invalid/ghp_" + "Z" * 36 + "/name\n.py"
    safe = safe_path(path, (VALUE,))
    assert VALUE not in safe and "example.invalid" not in safe and "ghp_" not in safe
    assert "\n" not in safe
