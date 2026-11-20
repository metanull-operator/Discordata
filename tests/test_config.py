"""Import-time configuration: required secrets, ALLOWED_IPS parsing and LOG_LEVEL.

These run the module in a fresh interpreter, because discordata reads its
environment once, at import.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_ENV = {
    "WEBHOOK_SECRET": "s",
    "DISCORD_WEBHOOK_URL": "https://discord.example.test/hook",
}


def run_import(code, **env):
    full_env = {k: v for k, v in os.environ.items() if k not in {"WEBHOOK_SECRET", "DISCORD_WEBHOOK_URL"}}
    full_env.pop("ALLOWED_IPS", None)
    full_env.pop("LOG_LEVEL", None)
    full_env.update({k: v for k, v in env.items() if v is not None})
    return subprocess.run(
        [sys.executable, "-c", f"import discordata\n{code}"],
        cwd=REPO_ROOT,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.parametrize("missing", ["WEBHOOK_SECRET", "DISCORD_WEBHOOK_URL"])
def test_import_fails_without_required_secret(missing):
    env = dict(BASE_ENV, **{missing: None})
    result = run_import("", **env)
    assert result.returncode != 0
    assert "Missing WEBHOOK_SECRET or DISCORD_WEBHOOK_URL" in result.stderr


def test_import_succeeds_with_required_secrets():
    result = run_import("print('ok')", **BASE_ENV)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_allowed_ips_defaults_to_allow_all():
    result = run_import("print([str(n) for n in discordata.allowed_ips])", **BASE_ENV)
    assert result.stdout.strip() == "['0.0.0.0/0']"


def test_allowed_ips_parses_hosts_networks_spaces_and_blanks():
    result = run_import(
        "print([str(n) for n in discordata.allowed_ips])",
        ALLOWED_IPS=" 192.168.1.1, 10.0.0.0/24,,2001:db8::/32 ",
        **BASE_ENV,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "['192.168.1.1/32', '10.0.0.0/24', '2001:db8::/32']"


def test_invalid_allowed_ips_fails_at_import():
    result = run_import("", ALLOWED_IPS="10.0.0.0/33", **BASE_ENV)
    assert result.returncode != 0
    assert "ValueError" in result.stderr


@pytest.mark.parametrize(("value", "expected"), [(None, "INFO"), ("debug", "DEBUG"), ("WARNING", "WARNING")])
def test_log_level_is_read_from_environment(value, expected):
    result = run_import(
        "import logging; print(discordata.LOG_LEVEL, logging.getLevelName(discordata.logger.level))",
        LOG_LEVEL=value,
        **BASE_ENV,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [expected, expected]


def test_wsgi_entry_point_is_a_flask_app():
    result = run_import("from flask import Flask; print(isinstance(discordata.app, Flask))", **BASE_ENV)
    assert result.stdout.strip() == "True"
