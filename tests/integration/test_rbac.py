"""Role-rank tests for require_role()."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.core.roles import RANK, is_at_least  # noqa: E402
from cyberscan_api.models import Role  # noqa: E402


def test_role_ordering():
    assert RANK[Role.viewer] < RANK[Role.analyst]
    assert RANK[Role.analyst] < RANK[Role.admin]
    assert RANK[Role.admin] < RANK[Role.owner]


def test_role_values_complete():
    assert {r for r in Role} == set(RANK.keys())


def test_is_at_least():
    assert is_at_least(Role.owner, Role.viewer) is True
    assert is_at_least(Role.viewer, Role.analyst) is False
    assert is_at_least(Role.admin, Role.admin) is True
