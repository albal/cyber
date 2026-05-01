"""Pure-python role-rank helpers; importable without fastapi/sqlalchemy."""
from cyberscan_api.models import Role

RANK: dict[Role, int] = {
    Role.viewer: 0,
    Role.analyst: 1,
    Role.admin: 2,
    Role.owner: 3,
}


def is_at_least(user_role: Role, required: Role) -> bool:
    return RANK[user_role] >= RANK[required]
