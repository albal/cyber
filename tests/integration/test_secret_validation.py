"""Boot-time refusal of the dev-default API_SECRET_KEY when ENV != 'dev'.

Both the backend and the worker share the same default sentinel; if either
ever loads it in production we want a hard, loud failure rather than a
silent fall-through to a publicly known key.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "apps" / "backend" / "src"))
sys.path.insert(0, str(REPO / "apps" / "worker" / "src"))


# Each test instantiates Settings() directly — pydantic-settings reads env at
# every call, so we don't need module-cache surgery (and we *must not* do
# it: clearing cyberscan_api modules from sys.modules leaves any later test
# with a stale `app` that references the old auth_dep, breaking
# monkeypatches on the freshly-imported one).


# ---------- backend -----------------------------------------------------------


def test_backend_rejects_default_secret_when_env_is_prod(monkeypatch):
    monkeypatch.setenv("ENV", "prod")
    monkeypatch.setenv("API_SECRET_KEY", "dev-secret-change-me")
    monkeypatch.setenv("SEED_ADMIN_PASSWORD", "something-real")

    from cyberscan_api.core.config import Settings

    with pytest.raises(ValueError, match="API_SECRET_KEY"):
        Settings()


def test_backend_rejects_default_seed_admin_password_in_prod(monkeypatch):
    monkeypatch.setenv("ENV", "prod")
    monkeypatch.setenv("API_SECRET_KEY", "a-real-key-of-some-length")
    monkeypatch.setenv("SEED_ADMIN_PASSWORD", "admin")

    from cyberscan_api.core.config import Settings

    with pytest.raises(ValueError, match="SEED_ADMIN_PASSWORD"):
        Settings()


def test_backend_accepts_default_secret_in_dev_env(monkeypatch):
    monkeypatch.setenv("ENV", "dev")
    monkeypatch.setenv("API_SECRET_KEY", "dev-secret-change-me")

    from cyberscan_api.core.config import Settings

    s = Settings()
    assert s.api_secret_key == "dev-secret-change-me"


def test_backend_accepts_real_secret_in_prod(monkeypatch):
    monkeypatch.setenv("ENV", "prod")
    monkeypatch.setenv("API_SECRET_KEY", "x" * 40)
    monkeypatch.setenv("SEED_ADMIN_PASSWORD", "x" * 20)

    from cyberscan_api.core.config import Settings

    s = Settings()
    assert s.env == "prod"


# ---------- worker ------------------------------------------------------------


def test_worker_rejects_default_secret_when_env_is_prod(monkeypatch):
    monkeypatch.setenv("ENV", "prod")
    monkeypatch.setenv("API_SECRET_KEY", "dev-secret-change-me")

    from cyberscan_worker.config import Settings

    with pytest.raises(ValueError, match="API_SECRET_KEY"):
        Settings()


def test_worker_accepts_default_secret_in_dev_env(monkeypatch):
    monkeypatch.setenv("ENV", "dev")
    monkeypatch.setenv("API_SECRET_KEY", "dev-secret-change-me")

    from cyberscan_worker.config import Settings

    s = Settings()
    assert s.api_secret_key == "dev-secret-change-me"
