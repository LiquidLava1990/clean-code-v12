"""Sample violating cc.shape.naming_drift: snake_case crowd, one camelCase."""


def fetch_user(user_id: int) -> dict:
    """Look up a user by id."""
    return {"id": user_id}


def update_user(user_id: int, payload: dict) -> dict:
    """Patch a user record."""
    return {"id": user_id, **payload}


def deleteUser(user_id: int) -> bool:  # camelCase outlier — drift.
    """Delete a user by id."""
    return True


def list_users() -> list[dict]:
    """Return every user."""
    return []
