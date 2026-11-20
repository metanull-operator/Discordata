"""Gunicorn integration: DiscordataServer, parse_args and the __main__ entry point."""

import logging
import runpy
from pathlib import Path

import pytest
from gunicorn.app.base import BaseApplication

SCRIPT = Path(__file__).resolve().parent.parent / "discordata.py"
ENV_VARS = ["HOST", "PORT", "CERT_PATH", "KEY_PATH", "WORKERS", "THREADS", "LOG_LEVEL"]


@pytest.fixture
def clean_env(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_server_applies_known_options(app_module):
    server = app_module.DiscordataServer(app_module.app, {"bind": "127.0.0.1:9999", "workers": 3, "threads": 5})
    assert server.cfg.bind == ["127.0.0.1:9999"]
    assert server.cfg.workers == 3
    assert server.cfg.threads == 5


def test_server_ignores_unknown_and_none_options(app_module):
    server = app_module.DiscordataServer(app_module.app, {"not_a_setting": 1, "certfile": None})
    assert not hasattr(server.cfg, "not_a_setting")
    assert server.cfg.certfile is None


def test_server_without_options_uses_gunicorn_defaults(app_module):
    server = app_module.DiscordataServer(app_module.app)
    assert server.options == {}
    assert server.load() is app_module.app


def test_server_loads_the_flask_app(app_module):
    server = app_module.DiscordataServer(app_module.app, {})
    assert server.load() is app_module.app


def test_parse_args_defaults(app_module, clean_env):
    clean_env.setattr("sys.argv", ["discordata.py"])
    args = app_module.parse_args()
    assert (args.host, args.port, args.workers, args.threads) == ("0.0.0.0", 1276, 2, 4)
    assert (args.cert, args.key) == ("certs/cert.pem", "certs/key.pem")
    assert args.log_level == app_module.LOG_LEVEL


def test_parse_args_reads_environment(app_module, clean_env):
    for name, value in {
        "HOST": "127.0.0.1",
        "PORT": "8443",
        "CERT_PATH": "/c.pem",
        "KEY_PATH": "/k.pem",
        "WORKERS": "6",
        "THREADS": "8",
    }.items():
        clean_env.setenv(name, value)
    clean_env.setattr("sys.argv", ["discordata.py"])
    args = app_module.parse_args()
    assert (args.host, args.port, args.cert, args.key, args.workers, args.threads) == (
        "127.0.0.1",
        8443,
        "/c.pem",
        "/k.pem",
        6,
        8,
    )


def test_command_line_overrides_environment(app_module, clean_env):
    clean_env.setenv("PORT", "8443")
    clean_env.setattr("sys.argv", ["discordata.py", "--port", "9000", "--workers", "1", "--log-level", "DEBUG"])
    args = app_module.parse_args()
    assert (args.port, args.workers, args.log_level) == (9000, 1, "DEBUG")


def test_parse_args_rejects_invalid_log_level(app_module, clean_env):
    clean_env.setattr("sys.argv", ["discordata.py", "--log-level", "LOUD"])
    with pytest.raises(SystemExit):
        app_module.parse_args()


@pytest.fixture
def preserve_logging():
    """__main__ changes logger levels; put them back so later tests see the defaults."""
    root, werkzeug = logging.getLogger(), logging.getLogger("werkzeug")
    levels = (root.level, werkzeug.level)
    yield
    root.setLevel(levels[0])
    werkzeug.setLevel(levels[1])


def test_main_starts_gunicorn_with_expected_config(clean_env, preserve_logging):
    """Run discordata.py as a script, but stop just before Gunicorn starts serving."""
    captured = {}

    def fake_run(self):
        captured["cfg"] = self.cfg
        captured["app"] = self.load()

    clean_env.setattr(BaseApplication, "run", fake_run)
    clean_env.setattr(
        "sys.argv",
        ["discordata.py", "--host", "127.0.0.1", "--port", "8443", "--cert", "/certs/cert.pem",
         "--key", "/certs/key.pem", "--workers", "3", "--threads", "2", "--log-level", "WARNING"],
    )

    namespace = runpy.run_path(str(SCRIPT), run_name="__main__")

    cfg = captured["cfg"]
    assert cfg.bind == ["127.0.0.1:8443"]
    assert cfg.certfile == "/certs/cert.pem"
    assert cfg.keyfile == "/certs/key.pem"
    assert cfg.workers == 3
    assert cfg.threads == 2
    assert cfg.timeout == namespace["REQUEST_TIMEOUT"] * 2
    assert cfg.loglevel == "warning"
    assert cfg.accesslog == "-"
    assert cfg.errorlog == "-"
    assert captured["app"] is namespace["app"]
