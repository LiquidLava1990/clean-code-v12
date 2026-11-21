//! Sample violating cc.shape.param_count: 7 positional parameters.

pub fn build_request(
    host: &str,
    port: u16,
    path: &str,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
    timeout_ms: u64,
) -> String {
    format!(
        "{method} {host}:{port}{path} headers={hl} body={bl} timeout_ms={timeout_ms}",
        hl = headers.len(),
        bl = body.len(),
    )
}
