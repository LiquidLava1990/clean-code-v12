//! Sample clean cc.shape.param_count: parameters bundled into a spec.

pub struct RequestSpec<'a> {
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub method: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    pub timeout_ms: u64,
}

pub fn build_request(spec: &RequestSpec<'_>) -> String {
    format!(
        "{} {}:{}{} headers={} body={} timeout_ms={}",
        spec.method,
        spec.host,
        spec.port,
        spec.path,
        spec.headers.len(),
        spec.body.len(),
        spec.timeout_ms,
    )
}
