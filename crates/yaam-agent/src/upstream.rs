//! Talking to the service.

/// Where and how to reach the service.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// Base URL.
    pub base_url: String,
    /// Public key the sidecar seals spool entries to.
    ///
    /// Asymmetric on purpose: the sidecar can seal but never unseal, so holding this key grants no
    /// read access to anything already stored.
    pub service_public_key: Vec<u8>,
}

impl Upstream {
    /// Signs and posts one record, distinguishing permanent rejection from transient failure.
    pub async fn post_record(&self, _agent: &str, _body: &[u8]) -> crate::Result<()> {
        todo!("hmac sign, post, map 4xx to Rejected and 5xx/429 to Spooled")
    }
}
