"""Startup configuration, checked in a fresh interpreter because discordata reads it at import."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
BASE_ENV = {"WEBHOOK_SECRET": "s", "DISCORD_WEBHOOK_URL": "https://discord.invalid/x"}


def _import(env, *argv):
    code = "import sys; sys.argv = ['discordata.py', *sys.argv[1:]]; import discordata as d; " \
           "print(d.contract_wallet_policy, d.eth_rpc_url, d.signature_message, sep='|')"
    full_env = {k: v for k, v in os.environ.items() if k not in ("CONTRACT_WALLET_POLICY", "ETH_RPC_URL",
                                                                  "SIGNATURE_MESSAGE")}
    full_env.update(BASE_ENV, **env)
    return subprocess.run([sys.executable, "-c", code, *argv], cwd=REPO, env=full_env,
                          capture_output=True, text=True, timeout=60)


def test_defaults():
    result = _import({})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "strict|None|None"


def test_settings_come_from_the_environment():
    result = _import({"CONTRACT_WALLET_POLICY": " Strict ", "ETH_RPC_URL": "http://127.0.0.1:8545",
                      "SIGNATURE_MESSAGE": "hello"})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "strict|http://127.0.0.1:8545|hello"


def test_command_line_overrides_the_environment():
    result = _import({"CONTRACT_WALLET_POLICY": "strict"}, "--contract-wallet-policy", "any_owner",
                     "--eth-rpc-url", "http://node:8545")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "any_owner|http://node:8545|None"


@pytest.mark.parametrize("value", ["yolo", "owner-review"])
def test_unknown_policy_stops_startup(value):
    result = _import({"CONTRACT_WALLET_POLICY": value})
    assert result.returncode != 0
    assert "Unknown contract wallet policy" in result.stderr


def test_missing_secrets_stop_startup():
    env = {k: v for k, v in os.environ.items() if k not in ("WEBHOOK_SECRET", "DISCORD_WEBHOOK_URL")}
    result = subprocess.run([sys.executable, "-c", "import sys; sys.argv=['x']; import discordata"], cwd=REPO,
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode != 0
    assert "Missing WEBHOOK_SECRET or DISCORD_WEBHOOK_URL" in result.stderr
