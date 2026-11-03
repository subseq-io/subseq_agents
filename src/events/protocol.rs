use serde_json::Value;
pub fn advertise_sse(bytes: &[u8], id: &Value) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes)?;
    let mut result = String::new();
    let mut changed = false;
    for line in text.split_inclusive('\n') {
        let clean = line.trim_end_matches(['\r', '\n']);
        if let Some(data) = clean.strip_prefix("data:") {
            if data.trim().is_empty() {
                result.push_str(line);
                continue;
            }
            let mut value: Value = serde_json::from_str(data.trim_start())?;
            if value.get("id") == Some(id) && value.get("error").is_none() {
                if let Some(capabilities) = value
                    .pointer_mut("/result/capabilities")
                    .and_then(Value::as_object_mut)
                {
                    capabilities.insert("events".into(), serde_json::json!({}));
                    result.push_str("data: ");
                    result.push_str(&serde_json::to_string(&value)?);
                    if line.ends_with("\r\n") {
                        result.push_str("\r\n");
                    } else if line.ends_with('\n') {
                        result.push('\n');
                    }
                    changed = true;
                    continue;
                }
            }
        }
        result.push_str(line);
    }
    anyhow::ensure!(
        changed,
        "Initialization response had no matching capabilities"
    );
    Ok(result.into_bytes())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initialization_preserves_priming_and_only_changes_matching_result() {
        let raw=b"data: \nid: 0\nretry: 3000\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"capabilities\":{\"tools\":{}},\"protocolVersion\":\"2025-03-26\"}}\n\n";
        let output = String::from_utf8(advertise_sse(raw, &serde_json::json!(7)).unwrap()).unwrap();
        assert!(output.starts_with("data: \nid: 0\nretry: 3000\n\n"));
        assert!(output.contains("\"events\":{}"));
        assert!(output.contains("\"tools\":{}"));
        assert!(advertise_sse(raw, &serde_json::json!(8)).is_err());
        assert!(advertise_sse(b"data: invalid\n\n", &serde_json::json!(7)).is_err());
        assert!(
            advertise_sse(b"data: {\"id\":7,\"error\":{}}\n\n", &serde_json::json!(7)).is_err()
        );
    }
}
