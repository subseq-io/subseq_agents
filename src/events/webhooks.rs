use anyhow::{Context, ensure};
use reqwest::{StatusCode, header::HeaderMap};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    time::Duration,
};
use url::Url;

pub type EventFuture<'a, T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;
pub struct WebhookResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
}
pub trait WebhookTransport: Send + Sync {
    fn post<'a>(
        &'a self,
        url: &'a str,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> EventFuture<'a, WebhookResponse>;
}
pub struct SafeWebhookClient;
pub fn callback_url(raw: &str) -> anyhow::Result<Url> {
    let url = Url::parse(raw)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "Use an HTTPS callback without credentials or fragments."
    );
    if let Some(host) = url.host_str() {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            ensure!(public_ip(ip), "Callback address must be public.");
        }
    }
    Ok(url)
}
fn v4_prefix(ip: Ipv4Addr, network: [u8; 4], bits: u32) -> bool {
    (u32::from(ip) >> (32 - bits)) == (u32::from(Ipv4Addr::from(network)) >> (32 - bits))
}
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ![
            ([0, 0, 0, 0], 8),
            ([10, 0, 0, 0], 8),
            ([100, 64, 0, 0], 10),
            ([127, 0, 0, 0], 8),
            ([169, 254, 0, 0], 16),
            ([172, 16, 0, 0], 12),
            ([192, 0, 0, 0], 24),
            ([192, 0, 2, 0], 24),
            ([192, 88, 99, 0], 24),
            ([192, 168, 0, 0], 16),
            ([198, 18, 0, 0], 15),
            ([198, 51, 100, 0], 24),
            ([203, 0, 113, 0], 24),
            ([224, 0, 0, 0], 3),
        ]
        .iter()
        .any(|(net, bits)| v4_prefix(ip, *net, *bits)),
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && s[1] < 0x0200)
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}
pub async fn bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(bytes.len() + chunk.len() <= limit, "Response is too large");
        bytes.extend(chunk);
    }
    Ok(bytes)
}
impl WebhookTransport for SafeWebhookClient {
    fn post<'a>(
        &'a self,
        raw: &'a str,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> EventFuture<'a, WebhookResponse> {
        Box::pin(async move {
            let url = callback_url(raw)?;
            let host = url
                .host_str()
                .context("Missing callback host")?
                .trim_matches(['[', ']']);
            let port = url
                .port_or_known_default()
                .context("Missing callback port")?;
            // Resolve anew for every verification/delivery; pin the validated result to this connection.
            let addresses: Vec<_> = tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::lookup_host((host, port)),
            )
            .await??
            .collect();
            ensure!(
                !addresses.is_empty() && addresses.iter().all(|a| public_ip(a.ip())),
                "Callback address must be public."
            );
            let client = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(3))
                .resolve_to_addrs(host, &addresses)
                .build()?;
            let verification = headers
                .get("webhook-id")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("verification_"));
            let response = client.post(url).headers(headers).body(body).send().await?;
            let status = response.status();
            // Application responses need no body; verification echoes are small.
            let body = if verification && status.is_success() {
                bounded_body(response, 4096).await?
            } else {
                Vec::new()
            };
            Ok(WebhookResponse { status, body })
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn callback_policy_rejects_nonpublic_and_ambiguous_targets() {
        for raw in [
            "http://example.com",
            "https://a:b@example.com",
            "https://127.0.0.1",
            "https://[::1]",
            "https://[::ffff:127.0.0.1]",
            "https://example.com/#secret",
        ] {
            assert!(callback_url(raw).is_err(), "{raw}");
        }
        for ip in [
            "10.1.2.3",
            "100.64.0.1",
            "169.254.169.254",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "fc00::1",
            "2001:db8::1",
            "2002:7f00:1::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(public_ip("8.8.8.8".parse().unwrap()));
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
        assert!(callback_url("https://example.com/callback").is_ok());
    }
}
