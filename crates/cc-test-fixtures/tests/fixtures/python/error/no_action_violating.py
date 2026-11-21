"""Sample violating cc.error.no_action: error message has no remediation."""


class ConfigError(Exception):
    """Generic config failure."""


def load_config(path: str) -> dict:
    """Pretend to load a config — error gives no action to take."""
    if not path:
        # No verb, no recovery hint — pure description.
        raise ConfigError("invalid config")
    return {}
