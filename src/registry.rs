//! Read-side access to a `unidpp-registry` instance (the 19135 item
//! service): the projector resolves profile items (lens manifests)
//! and unit items (registered unit identity) over HTTP **when a
//! registry is configured and reachable**; otherwise it falls back to
//! its deterministic built-in fixtures so the projection keeps working
//! in development and offline demos.
//!
//! This is the read-side sibling of the issuer's admin-forwarding
//! `registry` module (same three-mode doctrine): the registry owns
//! item lifecycle; the projector owns nothing — a view never claims
//! registry authority it does not have, and always reports which mode
//! served the manifest.

use std::time::Duration;

use serde_json::Value;

use crate::http::{self, Url};

/// Default fetch timeout (loopback sibling service; a slow registry
/// degrades to fixtures rather than hanging the request).
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// The subregisters the projector reads.
pub mod subregister {
    /// Profile items (lens manifests).
    pub const PROFILES: &str = "profiles";
    /// Unit items (registered unit identity).
    pub const UNITS: &str = "units";
    /// Transform items (registered Primmel packages: I8 deterministic
    /// registered transforms — the item's manifest is the package
    /// JSON).
    pub const TRANSFORMS: &str = "transforms";
}

/// The outcome of one registry read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// The registry answered 2xx; the parsed item document is carried.
    Registry(Value),
    /// The registry answered 404: no such item (an error — the
    /// projector does not paper over a live registry's negative).
    Missing,
    /// No registry URL is configured; fixtures mode.
    Fixtures,
    /// A registry URL is configured but the request failed; fixtures
    /// fallback (reported as such in the view).
    Unreachable(String),
}

impl FetchOutcome {
    /// Canonical wire token (mirrors the issuer's `RegistryMode`).
    pub fn as_str(&self) -> &'static str {
        match self {
            FetchOutcome::Registry(_) => "registry",
            FetchOutcome::Missing => "missing",
            FetchOutcome::Fixtures => "fixtures",
            FetchOutcome::Unreachable(_) => "unreachable",
        }
    }

    /// Whether the manifest served came from the built-in fixtures
    /// (`Fixtures` or `Unreachable` — the distinction is the detail).
    pub fn is_fixture_fallback(&self) -> bool {
        matches!(self, FetchOutcome::Fixtures | FetchOutcome::Unreachable(_))
    }
}

impl std::fmt::Display for FetchOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchOutcome::Registry(_) => f.write_str("registry"),
            FetchOutcome::Missing => f.write_str("missing"),
            FetchOutcome::Fixtures => f.write_str("fixtures"),
            FetchOutcome::Unreachable(d) => write!(f, "unreachable: {d}"),
        }
    }
}

/// The registry reader.
#[derive(Debug, Clone)]
pub struct RegistryClient {
    base: Option<String>,
    bearer: Option<String>,
}

impl RegistryClient {
    /// `base` is the registry root (e.g. `http://127.0.0.1:8090`);
    /// `None` disables fetching (fixtures mode).
    pub fn new(base: Option<String>, bearer: Option<String>) -> RegistryClient {
        RegistryClient { base, bearer }
    }

    /// The configured registry root, when one is (for mode dispatch
    /// in callers).
    pub fn base(&self) -> Option<&str> {
        self.base.as_deref()
    }

    /// Fetch one item from a subregister, point-in-time when `at` is
    /// given (the registry resolves the version in force at that
    /// instant). Transport failures degrade to `Unreachable`; a live
    /// 404 is `Missing`; any other non-2xx status is an error surfaced
    /// verbatim (the operator must fix the input, not retry blindly
    /// into fixtures).
    pub async fn fetch_item(
        &self,
        subregister: &str,
        item_id: &str,
        at: Option<String>,
    ) -> Result<FetchOutcome, String> {
        let Some(base) = &self.base else {
            return Ok(FetchOutcome::Fixtures);
        };
        let mut path = format!("/{}/{}", subregister, Url::encode_path_segment(item_id));
        if let Some(at) = at {
            path.push_str("?at=");
            path.push_str(&Url::encode_query_component(&at));
        }
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        Url::parse(&url).map_err(|e| format!("bad registry URL `{url}`: {e}"))?;
        let resp = match http::json_request(
            "GET",
            &url,
            None,
            self.bearer.as_deref(),
            FETCH_TIMEOUT,
        )
        .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return Ok(FetchOutcome::Unreachable(format!(
                    "registry not reachable: {e}"
                )))
            }
        };
        match resp.status {
            200..=299 => {
                let item: Value = serde_json::from_str(&resp.body_string())
                    .map_err(|e| format!("registry item `{item_id}` is not valid JSON: {e}"))?;
                Ok(FetchOutcome::Registry(item))
            }
            404 => Ok(FetchOutcome::Missing),
            other => Err(format!(
                "registry rejected the read of `{item_id}` ({}): {}",
                other,
                resp.body_string()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_tokens_and_fallback() {
        assert_eq!(FetchOutcome::Fixtures.as_str(), "fixtures");
        assert!(FetchOutcome::Fixtures.is_fixture_fallback());
        let down = FetchOutcome::Unreachable("boom".into());
        assert!(down.is_fixture_fallback());
        assert_eq!(down.to_string(), "unreachable: boom");
        assert_eq!(FetchOutcome::Missing.as_str(), "missing");
        assert!(!FetchOutcome::Missing.is_fixture_fallback());
        assert!(!FetchOutcome::Registry(Value::Null).is_fixture_fallback());
    }

    #[tokio::test]
    async fn no_base_means_fixtures() {
        let client = RegistryClient::new(None, None);
        let out = client
            .fetch_item(subregister::PROFILES, "urn:unidpp:profile:x", None)
            .await
            .unwrap();
        assert_eq!(out, FetchOutcome::Fixtures);
    }

    #[tokio::test]
    async fn unreachable_registry_degrades() {
        // Port 1 on loopback: reserved, nothing listens there.
        let client = RegistryClient::new(Some("http://127.0.0.1:1".into()), None);
        let out = client
            .fetch_item(subregister::UNITS, "unit-kwh", None)
            .await
            .unwrap();
        assert!(matches!(out, FetchOutcome::Unreachable(_)));
    }

    #[tokio::test]
    async fn bad_registry_url_is_an_error() {
        let client = RegistryClient::new(Some("not a url".into()), None);
        let err = client.fetch_item(subregister::PROFILES, "x", None).await;
        assert!(err.is_err());
    }
}
