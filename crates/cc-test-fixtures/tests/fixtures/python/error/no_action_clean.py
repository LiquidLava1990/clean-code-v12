"""Sample clean cc.error.no_action: error message includes remediation."""


class ConfigError(Exception):
    """Raised when config cannot be loaded."""


def load_config(path: str) -> dict:
    """Load a config file path, with an actionable error on failure."""
    if not path:
        raise ConfigError(
            "config path is empty; pass a non-empty path or "
            "set APP_CONFIG_PATH in the environment"
        )
    return {}
