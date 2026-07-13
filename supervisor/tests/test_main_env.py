"""Regression test for the alpha.1 field failure: after dropping privileges
from root, the inherited HOME=/root made keyring stat
/root/.config/python_keyring/keyringrc.cfg -> PermissionError for the
download user. The env setup must override, not setdefault."""

from __future__ import annotations

import os

from icloudpd_supervisor.config import Config
from icloudpd_supervisor.main import _setup_process_env


def test_process_env_forced_even_when_preset(monkeypatch):
    monkeypatch.setenv("HOME", "/root")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/root/.config")
    monkeypatch.setenv("XDG_DATA_HOME", "/root/.local/share")

    _setup_process_env(Config(apple_id="user@example.com", config_dir="/config"))

    assert os.environ["HOME"] == "/tmp"
    assert os.environ["XDG_CONFIG_HOME"] == "/tmp/.config"
    assert os.environ["XDG_DATA_HOME"] == "/config"
