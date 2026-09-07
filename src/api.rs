//! HTTP surface: axum router, handlers, `Config`, `TestServer`.
//!
//! Conventions (mirroring `unidpp-registry` and `unidpp-issuer`):
//! every response is as-of stamped (`x-as-of` header plus an `as_of`
//! body field); the service is read-only (no mutations, no admin
//! surface, no journal — the projector owns nothing); a view never
//! claims registry authority it does not have (`profile.source`
//! states `registry` / `fixtures` / `unreachable`, and the passport
//! block states whether the document came from the configured store
//! or the built-in fixture).
//!
//! The projection surface:
//!
//! | endpoint | purpose |
//! |---|---|
//! | `GET /view?passport=<id>&profile=<profile-item>&actor=<role>[&at=<RFC3339>]` | the deterministic projection: profile block, selected elements, transformed values, coverage report, as-of, per-element trust markers |
//! | `GET /` | service discovery (the endpoint contract) |
//! | `GET /healthz` | liveness |
//!
//! Passport documents are `unidpp/passport@1` JSON files loaded from
//! the configured store directory (`UNIDPP_PROJECTOR_PASSPORTS_DIR`),
//! matched by passport id; with no directory configured the built-in
//! two-lens demonstration fixture serves (dev/demo mode). Profile
//! manifests are fetched from the registry at `UNIDPP_REGISTRY_URL`
//! point-in-time (`?at=` forwarded); with no registry configured, or
//! one that is unreachable, the built-in EU/JP fixtures serve and the
//! view says so. Primmel rule packages (`.prml`, the deterministic
//! decision rules a lens's primmel transforms bind) resolve from the
//! operator-pinned directory `UNIDPP_PROJECTOR_PRIMMEL_DIR` first,
//! then the registry's transform subregister, then the built-in
//! fixtures — the transform output states which one served.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use unidpp_cli::passport::Passport;
use unidpp_model::{Resolution, Timestamp};

use crate::fixtures;
use crate::lens::LensManifest;
use crate::primmel::PackageSet;
use crate::project::{project, ProfileSource, RegisteredUnit};
use crate::registry::{subregister, FetchOutcome, RegistryClient};

/// Deployment configuration (environment-driven; see `main.rs`).
#[derive(Debug, Clone)]
pub struct Config {
    /// Listen address.
    pub bind: SocketAddr,
    /// Optional `unidpp-registry` base URL for profile, unit, and
    /// primmel-package reads.
    pub registry_url: Option<String>,
    /// Bearer token sent to the registry (its admin token; reads are
    /// public, this exists for consistency with the issuer).
    pub registry_token: Option<String>,
    /// Optional directory of `unidpp/passport@1` documents (the
    /// passport store). `None` = built-in fixture mode.
    pub passports_dir: Option<PathBuf>,
    /// Optional directory of `.prml` Primmel packages
    /// (`UNIDPP_PROJECTOR_PRIMMEL_DIR`): operator-pinned rule
    /// packages, served before the registry and the built-in
    /// fixtures. `None` = registry/fixtures mode.
    pub primmel_dir: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: "127.0.0.1:8092".parse().expect("static bind"),
            registry_url: None,
            registry_token: None,
            passports_dir: None,
            primmel_dir: None,
        }
    }
}

impl Config {
    /// Resolve configuration from environment variables.
    pub fn from_env() -> Config {
        let mut config = Config::default();
        if let Ok(bind) = std::env::var("UNIDPP_PROJECTOR_BIND") {
            match bind.parse() {
                Ok(addr) => config.bind = addr,
                Err(_) => {
                    eprintln!("unidpp-projector: ignoring bad UNIDPP_PROJECTOR_BIND `{bind}`")
                }
            }
        }
        if let Ok(url) = std::env::var("UNIDPP_REGISTRY_URL") {
            if !url.is_empty() {
                config.registry_url = Some(url);
            }
        }
        if let Ok(token) = std::env::var("UNIDPP_PROJECTOR_REGISTRY_TOKEN") {
            if !token.is_empty() {
                config.registry_token = Some(token);
            }
        }
        if let Ok(dir) = std::env::var("UNIDPP_PROJECTOR_PASSPORTS_DIR") {
            if !dir.is_empty() {
                config.passports_dir = Some(PathBuf::from(dir));
            }
        }
        if let Ok(dir) = std::env::var("UNIDPP_PROJECTOR_PRIMMEL_DIR") {
            if !dir.is_empty() {
                config.primmel_dir = Some(PathBuf::from(dir));
            }
        }
        config
    }
}

/// Shared application state (immutable: the projector owns nothing).
pub struct AppState {
    pub config: Config,
    pub registry: RegistryClient,
}

impl AppState {
    pub fn new(config: Config) -> AppState {
        let registry =
            RegistryClient::new(config.registry_url.clone(), config.registry_token.clone());
        AppState { config, registry }
    }
}

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(discovery))
        .route("/healthz", get(healthz))
        .route("/view", get(view))
        .with_state(app)
}

/// Run until stopped (used by `main`).
pub async fn run(config: Config) -> std::io::Result<()> {
    let bind = config.bind;
    let app = Arc::new(AppState::new(config));
    let listener = TcpListener::bind(bind).await?;
    eprintln!("unidpp-projector listening on http://{bind}");
    axum::serve(listener, router(app)).await
}

/// A spawned server on an ephemeral port (integration tests and
/// embedders). `stop()` waits for the listener to be released.
pub struct TestServer {
    /// The bound address.
    pub addr: SocketAddr,
    /// `http://host:port` base URL.
    pub base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    /// Spawn with a config (the bind address is replaced by an
    /// ephemeral loopback port).
    pub async fn spawn(config: Config) -> std::io::Result<TestServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let mut config = config;
        config.bind = addr;
        let app = Arc::new(AppState::new(config));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let serve = axum::serve(listener, router(app)).with_graceful_shutdown(async {
                let _ = rx.await;
            });
            if let Err(e) = serve.await {
                eprintln!("unidpp-projector: server task ended: {e}");
            }
        });
        Ok(TestServer {
            addr,
            base_url: format!("http://{addr}"),
            shutdown: Some(tx),
            join: Some(join),
        })
    }

    /// Stop the server and wait until its listener is released.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn discovery() -> Result<Response, Response> {
    let doc = json!({
        "service": "unidpp-projector",
        "description": "UniDPP lens projection service: render a passport under a registered profile (view + coverage report) — the EU/JP two-lens moment as a service",
        "endpoints": {
            "view": "GET /view?passport=<passport-id>&profile=<profile-item>&actor=<role>[&at=<RFC3339>]",
            "health": "GET /healthz"
        },
        "view_contract": {
            "profile": {"id": "profile item id", "version": "manifest version pin", "axes": "...", "applies": "trigger + effective window at the as-of instant", "satisfiable": "capability floor vs subject", "source": "registry | fixtures | unreachable"},
            "selected": [{"element": "register/item@version", "value": "from the passport twin state", "sourced": {"seq": 0, "occurred_at": "...", "actor_role": "...", "actor_id": "..."}, "trust": "I9 marker of the sourcing event"}],
            "transformed": [{"id": "...", "kind": "unit-conversion | classification | primmel", "input": "...", "output": "...", "trust": "marker of the input", "status": "computed | failed | missing-inputs"}],
            "coverage": {"elements_required": 0, "elements_present": 0, "missing": [{"element": "...", "reason": "absent-as-of | below-trust-floor | capability-gate"}], "complete": false, "ratio": 1.0},
            "as_of": "the projection instant (?at= or now)",
            "trust": {"<element>": "<marker>", "…": "marker per selected element"}
        },
        "selection_gates": ["capability-gate (subject class vs binding floor)", "presence (source fact on the twin state as-of)", "below-trust-floor (sourcing event marker vs binding floor)"],
        "sources": {
            "passports": "unidpp/passport@1 documents from UNIDPP_PROJECTOR_PASSPORTS_DIR, else the built-in two-lens fixture",
            "profiles": "unidpp-registry profile items at UNIDPP_REGISTRY_URL (point-in-time with at=), else built-in EU/JP fixtures",
            "units": "registry units subregister identity (ISO 80000 citation chain); conversions are exact through the local ISO 80000 seed",
            "primmel": ".prml rule packages from UNIDPP_PROJECTOR_PRIMMEL_DIR (operator pin), else the registry transform subregister, else built-in fixtures; each evaluated rule carries its clause_urn (the legal paragraph it implements)"
        },
        "as_of": {"query_parameter": "at", "response_header": "x-as-of"},
        "auth": "none (read-only service; the actor parameter is recorded, not authenticated)"
    });
    Ok(stamped(StatusCode::OK, &doc, Timestamp::now()))
}

async fn healthz() -> Result<Response, Response> {
    Ok(build_response(
        StatusCode::OK,
        vec![
            ("content-type".into(), "text/plain".into()),
            ("x-as-of".into(), Timestamp::now().to_string()),
        ],
        "ok".into(),
    ))
}

/// The parsed `GET /view` query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewQuery {
    pub passport: String,
    pub profile: String,
    pub actor: String,
    pub at: Option<Timestamp>,
}

/// Parse and validate the view query (pure; unit-tested).
fn parse_view_query(params: &HashMap<String, String>) -> Result<ViewQuery, Response> {
    let required = |key: &str| -> Result<String, Response> {
        params
            .get(key)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| bad_request(format!("`{key}` query parameter is required")))
    };
    let at = match params.get("at").map(|s| s.trim()) {
        None | Some("") => None,
        Some(raw) => Some(
            Timestamp::parse(raw)
                .map_err(|e| bad_request(format!("invalid `at` parameter: {e}")))?,
        ),
    };
    Ok(ViewQuery {
        passport: required("passport")?,
        profile: required("profile")?,
        actor: required("actor")?,
        at,
    })
}

/// Where a lens manifest came from, after the registry read.
struct ResolvedLens {
    lens: LensManifest,
    source: ProfileSource,
}

/// Resolve the lens manifest: registry first, fixtures otherwise.
async fn resolve_lens(
    app: &AppState,
    profile_id: &str,
    at: Option<Timestamp>,
) -> Result<ResolvedLens, Response> {
    let outcome = app
        .registry
        .fetch_item(subregister::PROFILES, profile_id, at.map(|t| t.to_string()))
        .await
        .map_err(|e| {
            bad_gateway(&format!(
                "registry read of profile `{profile_id}` failed: {e}"
            ))
        })?;
    match outcome {
        FetchOutcome::Registry(item) => {
            let lens = LensManifest::from_item(&item)
                .map_err(|e| bad_gateway(&format!("profile item `{profile_id}`: {e}")))?;
            Ok(ResolvedLens {
                lens,
                source: ProfileSource::registry(),
            })
        }
        FetchOutcome::Missing => Err(not_found(&format!(
            "no profile item `{profile_id}` in the registry"
        ))),
        FetchOutcome::Fixtures => match fixtures::fixture_lens(profile_id) {
            Some(lens) => Ok(ResolvedLens {
                lens,
                source: ProfileSource::fallback(
                    "fixtures",
                    Some("no registry URL configured".into()),
                ),
            }),
            None => Err(not_found(&format!(
                "no profile item `{profile_id}` and no registry configured"
            ))),
        },
        FetchOutcome::Unreachable(detail) => match fixtures::fixture_lens(profile_id) {
            Some(lens) => Ok(ResolvedLens {
                lens,
                source: ProfileSource::fallback("unreachable", Some(detail)),
            }),
            None => Err(service_unavailable(&format!(
                "registry unreachable and `{profile_id}` is not a built-in fixture: {detail}"
            ))),
        },
    }
}

/// Resolve the unit identities the lens's transforms reference.
async fn resolve_units(app: &AppState, lens: &LensManifest) -> BTreeMap<String, RegisteredUnit> {
    let mut items: Vec<String> = Vec::new();
    for transform in &lens.transforms {
        for item in transform.unit_items() {
            if !items.contains(&item) {
                items.push(item);
            }
        }
    }
    if items.is_empty() {
        return BTreeMap::new();
    }
    // Fixtures mode is uniform for the whole read; do not mix fixture
    // identities into an authoritative registry view.
    if app.registry_base().is_none() {
        let units = fixtures::fixture_units();
        return items
            .into_iter()
            .filter_map(|item| units.get(&item).cloned().map(|u| (item, u)))
            .collect();
    }
    // The registry's own seed dataset is the built-in fixture copy:
    // when the read degrades (unreachable), the unit identities
    // degrade with the lens manifest — uniformly, and the view states
    // the fallback path. A live 404 leaves the identity unresolved
    // (the view reports it); the conversion itself always stays
    // exact through the local ISO 80000 seed.
    let fallback = fixtures::fixture_units();
    let mut units = BTreeMap::new();
    for item in items {
        match app
            .registry
            .fetch_item(subregister::UNITS, &item, None)
            .await
        {
            Ok(FetchOutcome::Registry(doc)) => {
                if let Some(unit) = registered_unit_from_item(&doc) {
                    units.insert(item, unit);
                }
            }
            Ok(FetchOutcome::Unreachable(_)) => {
                if let Some(unit) = fallback.get(&item) {
                    units.insert(item, unit.clone());
                }
            }
            _ => {}
        }
    }
    units
}

/// Parse a registry unit item into its registered identity.
fn registered_unit_from_item(doc: &Value) -> Option<RegisteredUnit> {
    let identifier = doc.get("identifier").and_then(Value::as_str)?;
    let name = doc
        .get("manifest")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| doc.get("title").and_then(Value::as_str).unwrap_or(""));
    let citation = doc
        .get("manifest")
        .and_then(|m| m.get("iso_80000_citation"))
        .and_then(Value::as_str)
        .or_else(|| doc.get("notes").and_then(Value::as_str))
        .map(str::to_string);
    Some(RegisteredUnit {
        item: identifier.to_string(),
        name: name.to_string(),
        citation,
    })
}

/// Resolve the Primmel packages the lens's rule bindings reference
/// (TODO.impl C9), per package URN and in this order:
///
/// 1. the operator-pinned local directory (`.prml` files,
///    `UNIDPP_PROJECTOR_PRIMMEL_DIR`) — an explicit pin beats the
///    network;
/// 2. the registry's transform subregister (the package as a
///    registered item, manifest = the package JSON; a *live* 404
///    leaves the binding unserved — the view says the package is not
///    available rather than inventing one);
/// 3. the built-in fixtures (no registry configured, or one that is
///    unreachable — the degradation is stated per package in the
///    transform output).
async fn resolve_packages(app: &AppState, lens: &LensManifest) -> Result<PackageSet, Response> {
    let mut refs: Vec<String> = Vec::new();
    for transform in &lens.transforms {
        for r in transform.package_refs() {
            if !refs.contains(&r) {
                refs.push(r);
            }
        }
    }
    if refs.is_empty() {
        return Ok(PackageSet::empty());
    }
    // 1. Operator-pinned directory.
    let pinned = match &app.config.primmel_dir {
        Some(dir) => Some(PackageSet::from_dir(dir).map_err(|e| internal_error(&e))?),
        None => None,
    };
    let fallback = fixtures::fixture_primmel();
    let mut set = PackageSet::empty();
    for r in refs {
        if let Some((package, _)) = pinned.as_ref().and_then(|p| p.get(&r)) {
            set.insert(package.clone(), "dir");
            continue;
        }
        // 2. Registry / 3. fixtures — per the doctrine above.
        match app
            .registry
            .fetch_item(subregister::TRANSFORMS, &r, None)
            .await
        {
            Ok(FetchOutcome::Registry(doc)) => {
                let manifest = doc.get("manifest").cloned().ok_or_else(|| {
                    bad_gateway(&format!("primmel package item `{r}` carries no manifest"))
                })?;
                let package = crate::primmel::PrimmelPackage::from_json(&manifest)
                    .map_err(|e| bad_gateway(&format!("primmel package item `{r}`: {e}")))?;
                set.insert(package, "registry");
            }
            Ok(FetchOutcome::Missing) => {
                // A live negative stands: the binding will report the
                // package as unavailable.
            }
            Ok(FetchOutcome::Fixtures) | Ok(FetchOutcome::Unreachable(_)) => {
                if let Some((package, _)) = fallback.get(&r) {
                    set.insert(package.clone(), "fixtures");
                }
            }
            Err(e) => {
                return Err(bad_gateway(&format!(
                    "registry read of primmel package `{r}` failed: {e}"
                )))
            }
        }
    }
    Ok(set)
}

/// GET /view — the projection.
async fn view(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    let query = parse_view_query(&params)?;
    let as_of = query.at.unwrap_or_else(Timestamp::now);

    // 1. The passport document (store, else the built-in fixture).
    let (passport, passport_source) =
        load_passport(app.config.passports_dir.as_deref(), &query.passport).map_err(
            |e| match e {
                LoadError::NotFound(id) => not_found(&format!("no passport `{id}`")),
                LoadError::Corrupt(file, why) => internal_error(&format!(
                    "corrupt passport document `{}`: {why}",
                    file.display()
                )),
            },
        )?;

    // 2. The lens manifest (registry, else fixtures).
    let resolved = resolve_lens(&app, &query.profile, query.at).await?;
    if resolved.lens.profile.resolution == Resolution::None {
        return Err(forbidden(&format!(
            "profile `{}` is not servable (resolution `none`)",
            query.profile
        )));
    }

    // 3. Unit identities for the transforms.
    let units = resolve_units(&app, &resolved.lens).await;

    // 4. Primmel packages for the rule bindings.
    let packages = resolve_packages(&app, &resolved.lens).await?;

    // 5. Project.
    let mut doc = project(
        &passport,
        &resolved.lens,
        as_of,
        &query.actor,
        &units,
        &resolved.source,
        &packages,
    )
    .map_err(|e| internal_error(&e.to_string()))?;
    if let Some(block) = doc.pointer_mut("/passport").and_then(Value::as_object_mut) {
        block.insert("source".into(), json!(passport_source));
    }
    Ok(stamped(StatusCode::OK, &doc, as_of))
}

// ---------------------------------------------------------------------------
// Passport store
// ---------------------------------------------------------------------------

/// Why a passport could not be loaded.
#[derive(Debug)]
enum LoadError {
    NotFound(String),
    Corrupt(PathBuf, String),
}

/// Load a passport by id: the configured store directory (scanned in
/// sorted order for determinism), else the built-in fixture.
fn load_passport(
    dir: Option<&Path>,
    passport_id: &str,
) -> Result<(Passport, &'static str), LoadError> {
    match dir {
        Some(dir) => {
            let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
                Ok(entries) => entries
                    .filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "json"))
                    .collect(),
                Err(e) => {
                    return Err(LoadError::Corrupt(
                        dir.to_path_buf(),
                        format!("cannot read the passports directory: {e}"),
                    ))
                }
            };
            files.sort();
            for path in files {
                let text = match std::fs::read_to_string(&path) {
                    Ok(t) => t,
                    Err(e) => return Err(LoadError::Corrupt(path.clone(), e.to_string())),
                };
                let passport =
                    Passport::from_json(&text).map_err(|e| LoadError::Corrupt(path.clone(), e))?;
                if passport.passport_id.as_str() == passport_id {
                    return Ok((passport, "store"));
                }
            }
            Err(LoadError::NotFound(passport_id.to_string()))
        }
        None => {
            if passport_id == fixtures::DEMO_PASSPORT_ID {
                Ok((fixtures::demo_passport(), "fixture"))
            } else {
                Err(LoadError::NotFound(passport_id.to_string()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

fn build_response(status: StatusCode, headers: Vec<(String, String)>, body: String) -> Response {
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    builder
        .body(axum::body::Body::from(body))
        .expect("static response parts are valid")
}

fn stamped(status: StatusCode, body: &Value, as_of: Timestamp) -> Response {
    build_response(
        status,
        vec![
            ("content-type".into(), "application/json".into()),
            ("x-as-of".into(), as_of.to_string()),
        ],
        serde_json::to_string_pretty(body).unwrap(),
    )
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    stamped(status, &json!({ "error": msg }), Timestamp::now())
}

fn bad_request(msg: impl Into<String>) -> Response {
    error_response(StatusCode::BAD_REQUEST, &msg.into())
}

fn not_found(msg: &str) -> Response {
    error_response(StatusCode::NOT_FOUND, msg)
}

fn forbidden(msg: &str) -> Response {
    error_response(StatusCode::FORBIDDEN, msg)
}

fn bad_gateway(msg: &str) -> Response {
    error_response(StatusCode::BAD_GATEWAY, msg)
}

fn service_unavailable(msg: &str) -> Response {
    error_response(StatusCode::SERVICE_UNAVAILABLE, msg)
}

fn internal_error(msg: &str) -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

impl AppState {
    /// The configured registry base (mode dispatch).
    fn registry_base(&self) -> Option<&str> {
        self.registry.base()
    }
}

// ---------------------------------------------------------------------------
// Unit tests (handler-adjacent pure logic)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{demo_as_of, DEMO_PASSPORT_ID, EU_LENS_ID, JP_LENS_ID};
    use std::collections::BTreeSet;

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn view_query_requires_all_three_parameters() {
        let err = parse_view_query(&params(&[("passport", "p"), ("profile", "l")])).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);

        let ok = parse_view_query(&params(&[
            ("passport", " p "),
            ("profile", "l"),
            ("actor", " market-surveillance-authority "),
        ]))
        .unwrap();
        assert_eq!(ok.passport, "p");
        assert_eq!(ok.actor, "market-surveillance-authority");
        assert_eq!(ok.at, None);
    }

    #[test]
    fn view_query_parses_and_rejects_at() {
        let ok = parse_view_query(&params(&[
            ("passport", "p"),
            ("profile", "l"),
            ("actor", "customs"),
            ("at", "2027-02-11T11:00:00Z"),
        ]))
        .unwrap();
        assert_eq!(ok.at, Some(demo_as_of()));

        let err = parse_view_query(&params(&[
            ("passport", "p"),
            ("profile", "l"),
            ("actor", "customs"),
            ("at", "not-a-time"),
        ]))
        .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn fixture_mode_loads_only_the_demo_passport() {
        let (passport, source) = load_passport(None, DEMO_PASSPORT_ID).unwrap();
        assert_eq!(source, "fixture");
        assert_eq!(passport.passport_id.as_str(), DEMO_PASSPORT_ID);
        assert!(matches!(
            load_passport(None, "urn:unidpp:passport:other"),
            Err(LoadError::NotFound(_))
        ));
    }

    #[test]
    fn store_mode_scans_sorted_documents() {
        let dir = std::env::temp_dir().join(format!(
            "unidpp-projector-test-store-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let demo = crate::fixtures::demo_passport();
        let path = dir.join("laptop.json");
        std::fs::write(&path, demo.to_json().unwrap()).unwrap();
        let (loaded, source) = load_passport(Some(&dir), DEMO_PASSPORT_ID).unwrap();
        assert_eq!(source, "store");
        assert_eq!(loaded, demo);
        assert!(matches!(
            load_passport(Some(&dir), "urn:unidpp:passport:none"),
            Err(LoadError::NotFound(_))
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn store_mode_reports_corrupt_documents() {
        let dir = std::env::temp_dir().join(format!(
            "unidpp-projector-test-corrupt-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("broken.json");
        std::fs::write(&path, "{\"schema\": \"nope\"}").unwrap();
        match load_passport(Some(&dir), DEMO_PASSPORT_ID) {
            Err(LoadError::Corrupt(file, _)) => assert_eq!(file, path),
            other => panic!("expected corrupt, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn registry_base_is_visible_for_mode_dispatch() {
        let app = AppState::new(Config::default());
        assert!(app.registry_base().is_none());
        let app = AppState::new(Config {
            registry_url: Some("http://127.0.0.1:8090".into()),
            ..Config::default()
        });
        assert_eq!(app.registry_base(), Some("http://127.0.0.1:8090"));
    }

    #[test]
    fn unit_identity_parses_from_a_registry_item() {
        let doc = json!({
            "identifier": "unit-kwh",
            "title": "kilowatt hour",
            "manifest": {
                "version": "1.0.0",
                "name": "kilowatt hour",
                "iso_80000_citation": "ISO 80000-4:2006 (energy); 1 kWh = 3.6 MJ exactly"
            }
        });
        let unit = registered_unit_from_item(&doc).unwrap();
        assert_eq!(unit.item, "unit-kwh");
        assert_eq!(unit.name, "kilowatt hour");
        assert!(unit.citation.as_deref().unwrap().contains("3.6 MJ"));
        assert!(registered_unit_from_item(&json!({"title": "x"})).is_none());
    }

    #[test]
    fn two_fixture_views_disagree_the_b4_moment() {
        // The pure-engine two-lens check (the HTTP surface adds only
        // sourcing): same passport, same instant, two lenses.
        let passport = crate::fixtures::demo_passport();
        let at = demo_as_of();
        let units = crate::fixtures::fixture_units();
        let packages = crate::fixtures::fixture_primmel();
        let source = ProfileSource::fallback("fixtures", None);
        let eu = project(
            &passport,
            &crate::fixtures::eu_lens(),
            at,
            "customs",
            &units,
            &source,
            &packages,
        )
        .unwrap();
        let jp = project(
            &passport,
            &crate::fixtures::jp_lens(),
            at,
            "customs",
            &units,
            &source,
            &packages,
        )
        .unwrap();

        // EU: complete coverage, class A.
        assert_eq!(eu["profile"]["id"], json!(EU_LENS_ID));
        assert_eq!(eu["coverage"]["elements_required"], json!(3));
        assert_eq!(eu["coverage"]["elements_present"], json!(3));
        assert_eq!(eu["coverage"]["complete"], json!(true));
        let eu_class = eu["transformed"][0]["output"].as_str().unwrap();
        assert_eq!(eu_class, "A");

        // JP: missing the top-runner element, class-2 on the same
        // score, capacity converted kWh -> MJ.
        assert_eq!(jp["profile"]["id"], json!(JP_LENS_ID));
        assert_eq!(jp["coverage"]["elements_present"], json!(2));
        assert!(!jp["coverage"]["complete"].as_bool().unwrap());
        let missing = jp["coverage"]["missing"].as_array().unwrap();
        assert_eq!(missing.len(), 1);
        assert!(missing[0]["element"]
            .as_str()
            .unwrap()
            .contains("de.jp.top-runner-class"));
        assert_eq!(missing[0]["reason"], json!("absent-as-of"));
        let jp_class = jp["transformed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == json!("jp-reparability-class"))
            .unwrap()["output"]
            .as_str()
            .unwrap();
        assert_eq!(jp_class, "class-2");
        let capacity = jp["transformed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == json!("capacity-mj"))
            .unwrap();
        assert_eq!(capacity["output"]["amount"], json!("0.2592"));
        assert_eq!(capacity["output"]["unit"], json!("MJ"));
        assert_eq!(capacity["units"]["kWh"]["uom_registered"], json!(true));

        // The Primmel rules: the JP guard band decides on the
        // uncertainty-narrowed limit with its clause URN; the EU lens
        // classifies efficiency through the same package. 86.3 >= 85
        // but 86.3 - 1.8 = 84.5 < 85: not demonstrably conforming.
        let guard = jp["transformed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == json!("jp-soh-guard-band"))
            .unwrap();
        assert_eq!(guard["kind"], json!("primmel"));
        assert_eq!(guard["status"], json!("computed"));
        assert_eq!(guard["output"], json!("not-demonstrably-conforming"));
        assert_eq!(
            guard["clause_urn"],
            json!("urn:oiml:pub:r:91-2:2025#clause-6.1")
        );
        assert_eq!(guard["inputs"]["soh"]["value"], json!("86.3"));
        assert_eq!(guard["inputs"]["U"]["value"], json!("1.8"));
        assert_eq!(guard["package"]["source"], json!("fixtures"));

        let eff = eu["transformed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == json!("eu-efficiency-class"))
            .unwrap();
        assert_eq!(eff["output"], json!("B")); // 88.5 >= 85, < 92
        assert_eq!(eff["clause_urn"], json!("urn:eu:reg:2017:1369#annex-ii"));
        assert_eq!(
            eff["package"]["id"],
            json!(fixtures::BATTERY_RULES_PACKAGE_ID)
        );
    }

    #[test]
    fn both_fixture_views_share_the_same_twin_facts() {
        // The same three facts feed both lenses (single definition,
        // many constraints).
        let passport = crate::fixtures::demo_passport();
        let state = crate::twin::fold(&passport, demo_as_of());
        let paths: BTreeSet<&str> = state.facts.keys().map(String::as_str).collect();
        for path in [
            "de.dpp.operator-id",
            "de.dpp.reparability-score",
            "de.dpp.carbon-footprint",
            "de.jp.pse-mark",
            "battery.capacity-kwh",
        ] {
            assert!(paths.contains(path), "missing fact {path}");
        }
        assert!(!paths.contains("de.jp.top-runner-class"));
    }

    #[tokio::test]
    async fn package_resolution_without_primmel_bindings_is_empty() {
        // A lens with only unit/classification transforms resolves
        // no packages (no registry round-trip for them).
        let app = AppState::new(Config {
            registry_url: Some("http://127.0.0.1:1".into()), // deliberately dead
            ..Config::default()
        });
        let mut lens = crate::fixtures::eu_lens();
        lens.transforms.retain(|t| t.package_refs().is_empty());
        let set = resolve_packages(&app, &lens).await.unwrap();
        assert_eq!(set, PackageSet::empty());
    }

    #[tokio::test]
    async fn package_resolution_prefers_the_pinned_dir_then_fixtures() {
        // A pinned directory package wins over everything.
        let dir = std::env::temp_dir().join(format!(
            "unidpp-projector-primmel-api-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut pinned = crate::fixtures::battery_rules_package();
        pinned.version = "9.9.9-pinned".to_string();
        std::fs::write(
            dir.join("battery.prml"),
            serde_json::to_string_pretty(&pinned).unwrap(),
        )
        .unwrap();
        let app = AppState::new(Config {
            primmel_dir: Some(dir.clone()),
            registry_url: Some("http://127.0.0.1:1".into()), // dead registry
            ..Config::default()
        });
        let lens = crate::fixtures::jp_lens();
        let set = resolve_packages(&app, &lens).await.unwrap();
        let (pkg, source) = set.get(fixtures::BATTERY_RULES_PACKAGE_ID).unwrap();
        assert_eq!(source, "dir");
        assert_eq!(pkg.version, "9.9.9-pinned");

        // Without a dir and with an unreachable registry, the
        // built-in fixtures serve and say so.
        let app = AppState::new(Config::default());
        let set = resolve_packages(&app, &lens).await.unwrap();
        let (pkg, source) = set.get(fixtures::BATTERY_RULES_PACKAGE_ID).unwrap();
        assert_eq!(source, "fixtures");
        assert_eq!(pkg.version, "1.0.0");

        // A corrupt pinned file is an operator error, surfaced.
        std::fs::write(dir.join("broken.prml"), "{ not json").unwrap();
        let app = AppState::new(Config {
            primmel_dir: Some(dir.clone()),
            ..Config::default()
        });
        let err = resolve_packages(&app, &lens).await.unwrap_err();
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let _ = std::fs::remove_file(dir.join("battery.prml"));
        let _ = std::fs::remove_file(dir.join("broken.prml"));
        let _ = std::fs::remove_dir(&dir);
    }
}
