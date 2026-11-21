// Package shape — sample violating cc.shape.param_count (7 params).
package shape

// BuildRequest builds a request — too many positional params.
func BuildRequest(
	host string,
	port int,
	path string,
	method string,
	headers map[string]string,
	body []byte,
	timeoutMs int,
) map[string]any {
	return map[string]any{
		"host":      host,
		"port":      port,
		"path":      path,
		"method":    method,
		"headers":   headers,
		"body":      body,
		"timeoutMs": timeoutMs,
	}
}
