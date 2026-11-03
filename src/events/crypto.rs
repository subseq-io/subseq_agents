use anyhow::{Context, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::{
    aead, digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use std::collections::BTreeMap;

pub fn decode_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
    let key = STANDARD.decode(
        secret
            .strip_prefix("whsec_")
            .context("Invalid signing secret")?,
    )?;
    ensure!(
        (24..=64).contains(&key.len()),
        "Invalid signing secret length"
    );
    Ok(key)
}
pub fn sign(secret: &str, id: &str, timestamp: i64, body: &[u8]) -> anyhow::Result<String> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &decode_secret(secret)?);
    let mut context = hmac::Context::with_key(&key);
    context.update(format!("{id}.{timestamp}.").as_bytes());
    context.update(body);
    Ok(format!("v1,{}", STANDARD.encode(context.sign().as_ref())))
}
// Sort explicitly: downstream crates can enable serde_json/preserve_order globally.
fn canonical_arguments(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(object) => {
            let sorted: BTreeMap<_, _> = object.iter().collect();
            serde_json::Value::Object(
                sorted
                    .into_iter()
                    .map(|(key, value)| (key.clone(), canonical_arguments(value)))
                    .collect(),
            )
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonical_arguments).collect())
        }
        value => value.clone(),
    }
}
/// Domain-separated JSON with recursively sorted object keys and stable array order.
pub fn identity(owner: &str, name: &str, url: &str, arguments: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(&(
        "mcp-events-v1",
        owner,
        name,
        url,
        canonical_arguments(arguments),
    ))
    .expect("JSON identity");
    format!(
        "sub_{}",
        URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, &bytes).as_ref())
    )
}
pub fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    // Compare MACs with ring's constant-time verifier (including unequal input lengths).
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"mcp-events-comparison");
    hmac::verify(&key, left, hmac::sign(&key, right).as_ref()).is_ok()
}
#[derive(Clone)]
pub struct SecretBox {
    pub current: String,
    pub keys: BTreeMap<String, String>,
}
impl SecretBox {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.keys.contains_key(&self.current),
            "Current encryption key is missing"
        );
        for (id, key) in &self.keys {
            ensure!(
                !id.is_empty() && !id.contains(':'),
                "Invalid encryption key ID"
            );
            ensure!(
                STANDARD.decode(key)?.len() == 32,
                "Encryption keys must contain 32 bytes"
            );
        }
        Ok(())
    }
    fn key(&self, id: &str) -> anyhow::Result<aead::LessSafeKey> {
        let bytes = STANDARD.decode(self.keys.get(id).context("Unknown encryption key ID")?)?;
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &bytes)
            .map_err(|_| anyhow::anyhow!("Invalid encryption key"))?;
        Ok(aead::LessSafeKey::new(key))
    }
    pub fn seal(&self, context: &str, plaintext: &str) -> anyhow::Result<String> {
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| anyhow::anyhow!("Random source unavailable"))?;
        let mut body = plaintext.as_bytes().to_vec();
        self.key(&self.current)?
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(context),
                &mut body,
            )
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
        let mut envelope = nonce.to_vec();
        envelope.extend(body);
        Ok(format!("{}:{}", self.current, STANDARD.encode(envelope)))
    }
    pub fn open(&self, context: &str, ciphertext: &str) -> anyhow::Result<String> {
        let (id, encoded) = ciphertext
            .split_once(':')
            .context("Invalid encrypted secret")?;
        let mut bytes = STANDARD.decode(encoded)?;
        ensure!(bytes.len() >= 28, "Invalid encrypted secret");
        let nonce: [u8; 12] = bytes[..12].try_into()?;
        let plaintext = self
            .key(id)?
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(context),
                &mut bytes[12..],
            )
            .map_err(|_| anyhow::anyhow!("Secret authentication failed"))?;
        Ok(String::from_utf8(plaintext.to_vec())?)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signing_vector_and_secret_validation() {
        let secret = format!("whsec_{}", STANDARD.encode([1u8; 32]));
        assert_eq!(
            sign(&secret, "evt_1", 1700000000, br#"{"data":{}}"#).unwrap(),
            "v1,jvfINL0QVZDq6E+awz4IGazOYKJGzGbTdsv5n5sDPUM="
        );
        assert!(decode_secret("bad").is_err());
        assert!(decode_secret(&format!("whsec_{}", STANDARD.encode([0u8; 23]))).is_err());
    }
    #[test]
    fn encrypted_secrets_bind_owner_and_use_unique_nonces() {
        let vault = SecretBox {
            current: "k1".into(),
            keys: BTreeMap::from([("k1".into(), STANDARD.encode([2u8; 32]))]),
        };
        let a = vault.seal("owner/sub", "secret").unwrap();
        let b = vault.seal("owner/sub", "secret").unwrap();
        assert_ne!(a, b);
        assert_eq!(vault.open("owner/sub", &a).unwrap(), "secret");
        assert!(vault.open("other/sub", &a).is_err());
        assert!(!a.contains("secret"));
    }
    #[test]
    fn identity_ignores_argument_key_order_and_separates_owners() {
        let a = serde_json::json!({"project_id":"p", "run_id":"r"});
        let b = serde_json::from_str(r#"{"run_id":"r","project_id":"p"}"#).unwrap();
        assert_eq!(
            identity("u", "e", "https://example.com", &a),
            identity("u", "e", "https://example.com", &b)
        );
        assert_eq!(
            identity("u", "e", "https://example.com", &a),
            "sub_4MLw0Ai_uuoJ3b4N5C8c3tvG42ZJzLBhZScXgrbtycs"
        );
        let nested_a = serde_json::json!({"filter": [{"a": 1, "z": {"b": 2, "c": 3}}]});
        let nested_b = serde_json::from_str(r#"{"filter":[{"z":{"c":3,"b":2},"a":1}]}"#).unwrap();
        assert_eq!(
            identity("u", "e", "https://example.com", &nested_a),
            identity("u", "e", "https://example.com", &nested_b)
        );
        assert_ne!(
            identity("u", "e", "https://example.com", &a),
            identity("v", "e", "https://example.com", &a)
        );
    }
}
