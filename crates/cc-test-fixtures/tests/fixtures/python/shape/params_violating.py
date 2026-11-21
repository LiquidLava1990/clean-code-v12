"""Sample violating cc.shape.param_count: 7 positional parameters."""


def build_request(host, port, path, method, headers, body, timeout):
    # Seven positional params crosses the 5-param ceiling.
    return {
        "host": host,
        "port": port,
        "path": path,
        "method": method,
        "headers": headers,
        "body": body,
        "timeout": timeout,
    }
