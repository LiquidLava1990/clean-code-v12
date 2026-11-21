// Package shape — sample clean cc.shape.param_count (params bundled).
package shape

// RequestSpec captures every knob a request needs.
type RequestSpec struct {
	Host      string
	Port      int
	Path      string
	Method    string
	Headers   map[string]string
	Body      []byte
	TimeoutMs int
}

// BuildRequest renders a spec into a serialisable map.
func BuildRequest(spec RequestSpec) map[string]any {
	return map[string]any{
		"host":      spec.Host,
		"port":      spec.Port,
		"path":      spec.Path,
		"method":    spec.Method,
		"headers":   spec.Headers,
		"body":      spec.Body,
		"timeoutMs": spec.TimeoutMs,
	}
}
