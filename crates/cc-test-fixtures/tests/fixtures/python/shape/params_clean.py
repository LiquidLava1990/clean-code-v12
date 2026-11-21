"""Sample clean cc.shape.param_count: parameters bundled into a config."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RequestSpec:
    """Frozen spec capturing every knob a request needs."""

    host: str
    port: int
    path: str
    method: str
    headers: dict[str, str]
    body: bytes
    timeout: float


def build_request(spec: RequestSpec) -> dict[str, object]:
    """Render a request spec into a serialisable dict."""
    return {
        "host": spec.host,
        "port": spec.port,
        "path": spec.path,
        "method": spec.method,
        "headers": spec.headers,
        "body": spec.body,
        "timeout": spec.timeout,
    }
