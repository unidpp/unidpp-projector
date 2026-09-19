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
//! | `GET /view?passport=<id>&profile=<profile-item>&actor=<role>[&at=<RFC3339>]` | the deterministic projection: profile block, selected elements, transformed values (unit conversions, classifications, Primmel rules, aggregations, localization mappings), coverage report, as-of, per-element trust markers |
//! | `GET /render?passport=<id>&profile=<profile-item>&lang=<tag>[&at=<RFC3339>]` | the consumer presentation (TODO.impl 54): the profile's data points arranged per its presentation binding — sections, localized labels, formatted values with units, links to sources, `render_metadata` (`template_ref`, `lang`, `formatting_rules`), coverage report |
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
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use unidpp_cli::passport::Passport;
use unidpp_model::{Resolution, Timestamp};

use crate::aggregate::{ChildDocuments, RollupSealer};
use crate::codelist::{CodeListMapping, MappingSet};
use crate::fixtures;
use crate::lens::LensManifest;
use crate::primmel::PackageSet;
use crate::project::{project, ProfileSource, RegisteredUnit};
use crate::registry::{subregister, FetchOutcome, RegistryClient};
use crate::render::render;
use crate::twin;

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
    /// Optional seed material for the roll-up sealing key
    /// (`UNIDPP_PROJECTOR_ROLLUP_SEED`, TODO.impl 79): when set (with
    /// an attester), aggregation entries carry a signed roll-up
    /// attestation over their committed traversal set. `None` = the
    /// keyless projector (no attestation is emitted).
    pub rollup_seed: Option<String>,
    /// The attester id the roll-up attestations name
    /// (`UNIDPP_PROJECTOR_ROLLUP_ATTESTER`); required alongside the
    /// seed (a seed without an attester is refused loudly, not armed
    /// half-way).
    pub rollup_attester: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: "127.0.0.1:8092".parse().expect("static bind"),
            registry_url: None,
            registry_token: None,
            passports_dir: None,
            primmel_dir: None,
            rollup_seed: None,
            rollup_attester: None,
        }
    }
}

impl Config {
    /// Resolve configuration from environment variables.
    /// The environment variables this service consumes. This is the
    /// deployment contract: unidpp-config renders exactly these names
    /// for the projector, and the contract document carries them as
    /// `x-unidpp-env-keys`.
    pub const ENV_KEYS: &'static [&'static str] = &[
        "UNIDPP_PROJECTOR_BIND",
        "UNIDPP_REGISTRY_URL",
        "UNIDPP_PROJECTOR_REGISTRY_TOKEN",
        "UNIDPP_PROJECTOR_PASSPORTS_DIR",
        "UNIDPP_PROJECTOR_PRIMMEL_DIR",
        "UNIDPP_PROJECTOR_ROLLUP_SEED",
        "UNIDPP_PROJECTOR_ROLLUP_ATTESTER",
    ];

    pub fn from_env() -> Config {
        let mut config = Config::default();
        let mut vars: HashMap<&str, String> = HashMap::new();
        for key in Self::ENV_KEYS {
            if let Ok(value) = std::env::var(key) {
                vars.insert(*key, value);
            }
        }
        if let Some(bind) = vars.get("UNIDPP_PROJECTOR_BIND") {
            match bind.parse() {
                Ok(addr) => config.bind = addr,
                Err(_) => {
                    eprintln!("unidpp-projector: ignoring bad UNIDPP_PROJECTOR_BIND `{bind}`")
                }
            }
        }
        if let Some(url) = vars.get("UNIDPP_REGISTRY_URL") {
            if !url.is_empty() {
                config.registry_url = Some(url.clone());
            }
        }
        if let Some(token) = vars.get("UNIDPP_PROJECTOR_REGISTRY_TOKEN") {
            if !token.is_empty() {
                config.registry_token = Some(token.clone());
            }
        }
        if let Some(dir) = vars.get("UNIDPP_PROJECTOR_PASSPORTS_DIR") {
            if !dir.is_empty() {
                config.passports_dir = Some(PathBuf::from(dir));
            }
        }
        if let Some(dir) = vars.get("UNIDPP_PROJECTOR_PRIMMEL_DIR") {
            if !dir.is_empty() {
                config.primmel_dir = Some(PathBuf::from(dir));
            }
        }
        for (var, slot) in [
            ("UNIDPP_PROJECTOR_ROLLUP_SEED", &mut config.rollup_seed),
            (
                "UNIDPP_PROJECTOR_ROLLUP_ATTESTER",
                &mut config.rollup_attester,
            ),
        ] {
            if let Some(value) = vars.get(var) {
                if !value.is_empty() {
                    *slot = Some(value.clone());
                }
            }
        }
        config
    }
}

/// Shared application state (immutable: the projector owns nothing
/// beyond its optional roll-up sealing key).
pub struct AppState {
    pub config: Config,
    pub registry: RegistryClient,
    /// The roll-up sealer derived from the configured seed (off when
    /// no key is configured, or the configuration is incomplete — the
    /// refusal is logged, never half-armed).
    pub sealer: RollupSealer,
}

impl AppState {
    pub fn new(config: Config) -> AppState {
        let registry =
            RegistryClient::new(config.registry_url.clone(), config.registry_token.clone());
        let sealer = match (&config.rollup_seed, &config.rollup_attester) {
            (Some(seed), Some(attester)) => match RollupSealer::seeded(seed, attester) {
                Ok(sealer) => sealer,
                Err(e) => {
                    eprintln!("unidpp-projector: roll-up sealing disabled ({e})");
                    RollupSealer::off()
                }
            },
            (Some(_), None) => {
                eprintln!(
                    "unidpp-projector: roll-up sealing disabled (a seed needs \
                     UNIDPP_PROJECTOR_ROLLUP_ATTESTER)"
                );
                RollupSealer::off()
            }
            _ => RollupSealer::off(),
        };
        AppState {
            config,
            registry,
            sealer,
        }
    }
}

// ---------------------------------------------------------------------------
// Interface contract
// ---------------------------------------------------------------------------

/// The routed paths, declared once. The router routes by these
/// constants, the contract document is tested against them, and no
/// route may be declared with a raw literal (the gates enforce both).
pub mod paths {
    pub const ROOT: &str = "/";
    pub const HEALTHZ: &str = "/healthz";
    pub const VIEW: &str = "/view";
    pub const RENDER: &str = "/render";
    /// The contract document itself (not an operation of the API).
    pub const CONTRACT_YAML: &str = "/openapi.yaml";
}

/// The OpenAPI model: one declaration per handler (`#[utoipa::path]`),
/// from which the served contract, the golden file and Swagger UI all
/// derive.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "UniDPP projector",
        version = env!("CARGO_PKG_VERSION"),
        description = "The presentation service: it folds the governed twin as of an instant under a profile's lens, renders the consumer presentation (JSON, HTML, speakable text — one computation, three wire formats), and seals roll-ups where a sealer is configured. Lens manifests resolve registry first, fixtures otherwise, with the source stated.",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(discovery, healthz, view, render_handler),
    tags(
        (name = "projection", description = "The twin-fold view and the consumer render"),
    )
)]
struct ApiDoc;

/// The contract document: the OpenAPI model plus the deployment keys
/// (`x-unidpp-env-keys`). Served at `/openapi.yaml` and committed as
/// the golden `openapi.yaml`.
pub fn contract_yaml() -> String {
    let mut doc = serde_json::to_value(ApiDoc::openapi()).expect("contract serializes");
    doc["info"]["x-unidpp-env-keys"] = json!(Config::ENV_KEYS);
    serde_yaml::to_string(&doc).expect("contract renders as YAML")
}

async fn openapi_yaml() -> Result<Response, Response> {
    let mut response = stamped(
        StatusCode::OK,
        &serde_json::from_str::<Value>(&contract_yaml()).expect("contract parses back"),
        Timestamp::now(),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/yaml"),
    );
    Ok(response)
}

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
        .route(paths::ROOT, get(discovery))
        .route(paths::HEALTHZ, get(healthz))
        .route(paths::VIEW, get(view))
        .route(paths::RENDER, get(render_handler))
        .route(paths::CONTRACT_YAML, get(openapi_yaml))
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

/// Serve the discovery document.
#[utoipa::path(
    get,
    path = "/",
    tag = "projection",
    responses(
        (status = 200, description = "The discovery document: the view and render query forms, the as-of semantics, the coverage honesty and the render metadata shape", body = Value, content_type = "application/json"),
    )
)]
async fn discovery() -> Result<Response, Response> {
    let doc = json!({
        "service": "unidpp-projector",
        "version": env!("CARGO_PKG_VERSION"),
        "build_id": option_env!("UNIDPP_BUILD_ID").unwrap_or("dev"),
        "description": "UniDPP lens projection service: render a passport under a registered profile (view + coverage report) — the EU/JP two-lens moment as a service",
        "endpoints": {
            "view": "GET /view?passport=<passport-id>&profile=<profile-item>&actor=<role>[&at=<RFC3339>]",
            "render": "GET /render?passport=<passport-id>&profile=<profile-item>&lang=<tag>[&at=<RFC3339>][&format=html|text|json] — JSON by default; Accept: text/html or text/plain (or the explicit format parameter, which outranks the header) serves the same render as a standalone consumer page (HTML) or as speakable text (the TTS substrate)",
            "health": "GET /healthz"
        },
        "view_contract": {
            "profile": {"id": "profile item id", "version": "manifest version pin", "axes": "...", "applies": "trigger + effective window at the as-of instant", "satisfiable": "capability floor vs subject", "source": "registry | fixtures | unreachable"},
            "selected": [{"element": "register/item@version", "value": "from the passport twin state", "sourced": {"seq": 0, "occurred_at": "...", "actor_role": "...", "actor_id": "..."}, "trust": "I9 marker of the sourcing event"}],
            "transformed": [{"id": "...", "kind": "unit-conversion | classification | primmel | aggregation | localization-mapping", "input": "...", "output": "...", "trust": "marker of the input", "status": "computed | failed | missing-inputs | missing-children | unmapped"}],
            "coverage": {"elements_required": 0, "elements_present": 0, "missing": [{"element": "...", "reason": "absent-as-of | below-trust-floor | capability-gate"}], "complete": false, "ratio": 1.0},
            "as_of": "the projection instant (?at= or now)",
            "trust": {"<element>": "<marker>", "…": "marker per selected element"}
        },
        "selection_gates": ["capability-gate (subject class vs binding floor)", "presence (source fact on the twin state as-of)", "below-trust-floor (sourcing event marker vs binding floor)"],
        "sources": {
            "passports": "unidpp/passport@1 documents from UNIDPP_PROJECTOR_PASSPORTS_DIR, else the built-in two-lens fixture",
            "children": "child passports of the traversal set (derived-issuance/combine inputs, replacements) from the same store or fixtures; aggregation transforms roll up over them and commit the input set's canonical traversal-set root (unidpp-transform's Merkle rollup definition)",
            "rollup": "signed roll-up attestations over the committed traversal set (subject = the parent passport, method_ref = the binding's method citation) when UNIDPP_PROJECTOR_ROLLUP_SEED + UNIDPP_PROJECTOR_ROLLUP_ATTESTER arm the projector's key; the field is absent otherwise, never a placeholder",
            "profiles": "unidpp-registry profile items at UNIDPP_REGISTRY_URL (point-in-time with at=), else built-in EU/JP fixtures",
            "units": "registry units subregister identity (ISO 80000 citation chain); conversions are exact through the local ISO 80000 seed",
            "primmel": ".prml rule packages from UNIDPP_PROJECTOR_PRIMMEL_DIR (operator pin), else the registry transform subregister, else built-in fixtures; each evaluated rule carries its clause_urn (the legal paragraph it implements)",
            "mappings": "code-list mapping items (class transform) from the registry transform subregister, else built-in fixtures (EU A-E class <-> JP star display); unmapped values emit the explicit `unmapped` output"
        },
        "render_contract": {
            "render_metadata": {"template_ref": "the presentation binding's template", "lang": "the requested language tag", "fallback_lang": "served when the requested language has no label", "formatting_rules": {"unit_position": "suffix | none", "decimal_digits": 1, "fallback_lang": "en"}, "as_of": "the render instant", "profile": {"id": "...", "version": "...", "source": "registry | fixtures | unreachable"}},
            "sections": [{"id": "product | repair | recycling | ...", "label": "localized section title", "label_lang": "the language that served the label", "items": [{"element": "register/item@version", "label": "localized element label", "value": "exact value", "formatted": "display string with unit and digits", "source": {"view": "/view?..."} }]}],
            "coverage": "the same coverage report shape as the view"
        },
        "as_of": {"query_parameter": "at", "response_header": "x-as-of"},
        "auth": "none (read-only service; the actor parameter is recorded, not authenticated)"
    });
    Ok(stamped(StatusCode::OK, &doc, Timestamp::now()))
}

/// Liveness probe.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "projection",
    responses(
        (status = 200, description = "The service is serving"),
    )
)]
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

/// Resolve the registered code-list mapping items the lens's
/// localization bindings reference (TODO.impl 67), per item id: the
/// registry's transform subregister when it serves the item (a *live*
/// 404 leaves the binding unserved — the transform entry says the
/// mapping is not available rather than inventing one), else the
/// built-in fixtures (no registry configured, or one that is
/// unreachable — the sourcing mode states which).
async fn resolve_mappings(app: &AppState, lens: &LensManifest) -> Result<MappingSet, Response> {
    let mut refs: Vec<String> = Vec::new();
    for transform in &lens.transforms {
        for r in transform.mapping_refs() {
            if !refs.contains(&r) {
                refs.push(r);
            }
        }
    }
    if refs.is_empty() {
        return Ok(MappingSet::empty());
    }
    let fallback = fixtures::fixture_mappings();
    let mut set = MappingSet::empty();
    for r in refs {
        match app
            .registry
            .fetch_item(subregister::TRANSFORMS, &r, None)
            .await
        {
            Ok(FetchOutcome::Registry(doc)) => {
                let mapping = CodeListMapping::from_item(&doc)
                    .map_err(|e| bad_gateway(&format!("code-list mapping item `{r}`: {e}")))?;
                set.insert(mapping, "registry");
            }
            Ok(FetchOutcome::Missing) => {
                // A live negative stands: the binding will report the
                // mapping as unavailable.
            }
            Ok(FetchOutcome::Fixtures) | Ok(FetchOutcome::Unreachable(_)) => {
                if let Some((mapping, _)) = fallback.get(&r) {
                    set.insert(mapping.clone(), "fixtures");
                }
            }
            Err(e) => {
                return Err(bad_gateway(&format!(
                    "registry read of code-list mapping `{r}` failed: {e}"
                )))
            }
        }
    }
    Ok(set)
}

/// The child passport documents of the subject's active traversal set
/// as-of the instant (aggregation inputs). Store mode resolves each
/// active child id from the configured directory; fixture mode serves
/// the built-in pack corpus. A child whose document cannot be
/// resolved is *not* an error here — the aggregation entry reports it
/// as a per-child gap.
fn load_children(dir: Option<&Path>, subject: &Passport, at: Timestamp) -> ChildDocuments {
    let ids = twin::fold(subject, at).children;
    if ids.is_empty() {
        return ChildDocuments::empty();
    }
    let mut documents = Vec::new();
    for id in ids {
        let found = match dir {
            Some(dir) => load_passport(Some(dir), &id).ok().map(|(p, _)| p),
            None => fixtures::fixture_child(&id),
        };
        if let Some(p) = found {
            documents.push(p);
        }
    }
    ChildDocuments::of(documents)
}

/// GET /view — the projection.
/// The twin-fold view of a passport under a lens, as of an instant:
/// the profile's lens manifest resolved (registry first, fixtures
/// otherwise), the data points presented with the same coverage
/// honesty the render carries, and the roll-up where a sealer is
/// configured.
#[utoipa::path(
    get,
    path = "/view",
    tag = "projection",
    params(
        ("passport" = String, Query, description = "The passport identifier"),
        ("profile" = String, Query, description = "The profile whose lens is applied"),
        ("actor" = String, Query, description = "The requesting role (the lens may gate data points on it)"),
        ("at" = Option<String>, Query, description = "An RFC 3339 instant; the twin is folded as of that instant"),
    ),
    responses(
        (status = 200, description = "The view, as-of stamped, with the coverage and provenance metadata", body = Value, content_type = "application/json"),
        (status = 400, description = "A missing required query parameter"),
        (status = 404, description = "No such passport"),
    )
)]
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

    // 5. Code-list mappings for the localization bindings.
    let mappings = resolve_mappings(&app, &resolved.lens).await?;

    // 6. Child documents of the traversal set (aggregation inputs).
    let children = load_children(app.config.passports_dir.as_deref(), &passport, as_of);

    // 7. Project.
    let mut doc = project(
        &passport,
        &resolved.lens,
        as_of,
        &query.actor,
        &units,
        &resolved.source,
        &packages,
        &mappings,
        &children,
        &app.sealer,
    )
    .map_err(|e| internal_error(&e.to_string()))?;
    if let Some(block) = doc.pointer_mut("/passport").and_then(Value::as_object_mut) {
        block.insert("source".into(), json!(passport_source));
    }
    Ok(stamped(StatusCode::OK, &doc, as_of))
}

/// The parsed `GET /render` query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderQuery {
    pub passport: String,
    pub profile: String,
    pub lang: String,
    pub at: Option<Timestamp>,
}

/// Parse and validate the render query (pure; unit-tested). `lang` is
/// required — the render is per-language by definition; an unknown
/// tag is not an error (the missing-label fallback serves what the
/// binding declares, and the metadata states both).
fn parse_render_query(params: &HashMap<String, String>) -> Result<RenderQuery, Response> {
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
    Ok(RenderQuery {
        passport: required("passport")?,
        profile: required("profile")?,
        lang: required("lang")?,
        at,
    })
}

/// GET /render — the consumer presentation (TODO.impl 54): the
/// passport's data points arranged per the lens's presentation
/// binding, localized, formatted, with links to the authoritative
/// sources and the same coverage honesty as the view.
///
/// One presentation computation, three wire formats (TODO.impl 224):
/// JSON by default; `Accept: text/html` or `text/plain` (or an
/// explicit `format` parameter, which outranks the header) serves the
/// same render document as a standalone HTML page or as speakable
/// text (the TTS substrate) — the consumer surfaces a scanned code
/// resolves to.
/// The consumer presentation: the passport's data points arranged per
/// the lens's presentation binding, localized and formatted, with
/// links to the authoritative sources. One presentation computation,
/// three wire formats — JSON by default; `Accept: text/html` or
/// `text/plain` (or an explicit `format` parameter, which outranks
/// the header) serves the same render document as a standalone HTML
/// page or as speakable text.
#[utoipa::path(
    get,
    path = "/render",
    tag = "projection",
    params(
        ("passport" = String, Query, description = "The passport identifier"),
        ("profile" = String, Query, description = "The profile whose presentation binding is applied"),
        ("lang" = String, Query, description = "The requested language tag (a fallback is served when the requested language has no label)"),
        ("at" = Option<String>, Query, description = "An RFC 3339 instant"),
        ("format" = Option<String>, Query, description = "`html`, `text` or `json`; outranks the `Accept` header"),
    ),
    responses(
        (status = 200, description = "The render, as-of stamped", body = Value, content_type = "application/json"),
        (status = 400, description = "A missing required query parameter, or an unknown `format`"),
        (status = 404, description = "No such passport"),
    )
)]
async fn render_handler(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let query = parse_render_query(&params)?;
    let format = crate::html::requested_format(
        &params,
        headers.get("accept").and_then(|v| v.to_str().ok()),
    );
    if let crate::html::Format::Invalid(other) = &format {
        return Err(bad_request(format!(
            "unknown `format` `{other}` — `html`, `text` or `json`"
        )));
    }
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

    // 2. The lens manifest (registry, else fixtures) — it must carry a
    //    presentation binding.
    let resolved = resolve_lens(&app, &query.profile, query.at).await?;
    if resolved.lens.profile.resolution == Resolution::None {
        return Err(forbidden(&format!(
            "profile `{}` is not servable (resolution `none`)",
            query.profile
        )));
    }
    if resolved.lens.presentation.is_none() {
        return Err(bad_request(format!(
            "profile `{}` carries no presentation binding — `/render` needs \
             one; `/view` serves this profile",
            query.profile
        )));
    }

    // 3. Render.
    let mut doc = render(
        &passport,
        &resolved.lens,
        as_of,
        &query.lang,
        &resolved.source,
    )
    .map_err(|e| internal_error(&e.to_string()))?;
    if let Some(block) = doc.pointer_mut("/passport").and_then(Value::as_object_mut) {
        block.insert("source".into(), json!(passport_source));
    }
    if let Some((content_type, body)) = match &format {
        crate::html::Format::Html => Some((
            "text/html; charset=utf-8",
            crate::html::document(&doc),
        )),
        crate::html::Format::Text => Some((
            "text/plain; charset=utf-8",
            crate::html::text(&doc),
        )),
        _ => None,
    } {
        return Ok(build_response(
            StatusCode::OK,
            vec![
                ("content-type".into(), content_type.into()),
                ("x-as-of".into(), as_of.to_string()),
            ],
            body,
        ));
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
    fn render_query_requires_lang_and_parses_at() {
        // lang is required — the render is per-language by definition.
        let err = parse_render_query(&params(&[
            ("passport", "p"),
            ("profile", "l"),
            ("lang", " "),
        ]))
        .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);

        let err = parse_render_query(&params(&[("passport", "p"), ("profile", "l")])).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);

        let ok = parse_render_query(&params(&[
            ("passport", " p "),
            ("profile", "l"),
            ("lang", " ja "),
            ("at", "2027-02-11T11:00:00Z"),
        ]))
        .unwrap();
        assert_eq!(ok.passport, "p");
        assert_eq!(ok.lang, "ja");
        assert_eq!(ok.at, Some(demo_as_of()));

        let err = parse_render_query(&params(&[
            ("passport", "p"),
            ("profile", "l"),
            ("lang", "ja"),
            ("at", "soon"),
        ]))
        .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn children_load_from_fixtures_and_the_store() {
        let system = crate::fixtures::pack_system();
        let at = demo_as_of();
        // Fixture mode: the pack system's three children resolve; the
        // laptop (whose child edge names a sodimm with no fixture
        // document) resolves nothing — the aggregation would report
        // the gap.
        let children = load_children(None, &system, at);
        assert_eq!(children.documents.len(), 3);
        assert!(children.get(crate::fixtures::PACK_CHILD_IDS[0]).is_some());
        let laptop = crate::fixtures::demo_passport();
        let laptop_children = load_children(None, &laptop, at);
        assert_eq!(laptop_children.documents.len(), 0);

        // Store mode: the children load from the directory.
        let dir = std::env::temp_dir().join(format!(
            "unidpp-projector-test-children-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for (i, child) in crate::fixtures::pack_children().into_iter().enumerate() {
            std::fs::write(dir.join(format!("pack-{i}.json")), child.to_json().unwrap()).unwrap();
        }
        let children = load_children(Some(&dir), &system, at);
        assert_eq!(children.documents.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn mapping_resolution_without_a_registry_uses_fixtures() {
        // No registry configured: the built-in fixtures serve and say
        // so; a lens without localization bindings resolves nothing.
        let app = AppState::new(Config::default());
        let set = resolve_mappings(&app, &crate::fixtures::pack_lens())
            .await
            .unwrap();
        let (mapping, source) = set.get(crate::fixtures::EU_CLASS_TO_JP_STAR_ID).unwrap();
        assert_eq!(source, "fixtures");
        assert_eq!(mapping.version, "1.0.0");
        assert_eq!(
            resolve_mappings(&app, &crate::fixtures::eu_lens())
                .await
                .unwrap(),
            MappingSet::empty()
        );
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
    fn the_sealer_arms_only_from_a_seed_and_an_attester() {
        // Seed + attester: armed.
        let app = AppState::new(Config {
            rollup_seed: Some("operator-seed".into()),
            rollup_attester: Some("urn:unidpp:eo:projector".into()),
            ..Config::default()
        });
        assert!(app.sealer.seals());
        // A seed without an attester is refused loudly, not armed
        // half-way (RollupAttestation::build requires the attester).
        let app = AppState::new(Config {
            rollup_seed: Some("operator-seed".into()),
            ..Config::default()
        });
        assert!(!app.sealer.seals());
        // The default projector is keyless.
        assert!(!AppState::new(Config::default()).sealer.seals());
        assert_eq!(
            RollupSealer::seeded("seed", "  ").unwrap_err().to_string(),
            "validation error: a roll-up sealer names its attester"
        );
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
            &MappingSet::empty(),
            &ChildDocuments::empty(),
            &RollupSealer::off(),
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
            &MappingSet::empty(),
            &ChildDocuments::empty(),
            &RollupSealer::off(),
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

// ---------------------------------------------------------------------------
// Contract gates
// ---------------------------------------------------------------------------

#[cfg(test)]
mod contract_gates {
    use super::*;
    use crate::http::request;
    use crate::http::Url;
    use std::time::Duration;

    const VERBS: [&str; 5] = ["get", "post", "put", "delete", "patch"];

    /// The contract paths with their documented methods.
    fn documented() -> std::collections::BTreeMap<String, Vec<String>> {
        let doc: Value = serde_yaml::from_str(&contract_yaml()).expect("contract parses");
        doc["paths"]
            .as_object()
            .expect("paths object")
            .iter()
            .map(|(path, item)| {
                let methods = VERBS
                    .iter()
                    .filter(|v| item.get(*v).is_some())
                    .map(|v| v.to_string())
                    .collect();
                (path.clone(), methods)
            })
            .collect()
    }

    #[test]
    fn the_golden_matches_the_committed_contract() {
        assert_eq!(contract_yaml(), include_str!("../openapi.yaml"));
    }

    #[test]
    #[ignore = "regenerates openapi.yaml after a route change: cargo test contract_gates -- --ignored export"]
    fn export_golden() {
        std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml"),
            contract_yaml(),
        )
        .expect("golden written");
    }

    /// Every path the router serves (the contract route itself
    /// carries no operation).
    fn routed_paths() -> Vec<&'static str> {
        vec![paths::ROOT, paths::HEALTHZ, paths::VIEW, paths::RENDER]
    }

    #[test]
    fn every_routed_path_is_documented() {
        let doc = documented();
        for path in routed_paths() {
            assert!(doc.contains_key(path), "routed but undocumented: {path}");
        }
    }

    #[test]
    fn every_documented_path_is_routed() {
        let routed: std::collections::BTreeSet<String> =
            routed_paths().into_iter().map(str::to_string).collect();
        for path in documented().keys() {
            assert!(routed.contains(path), "documented but not routed: {path}");
        }
    }

    #[test]
    fn routes_are_declared_by_constant_not_literal() {
        let flat: String = include_str!("api.rs")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let mut idx = 0;
        while let Some(pos) = flat[idx..].find(".route(") {
            let abs = idx + pos;
            if abs > 0 && flat.as_bytes()[abs - 1] == b'"' {
                idx = abs + 7;
                continue;
            }
            let after = flat[abs + 7..].trim_start();
            assert!(
                after.starts_with("paths::"),
                "route paths come from the paths:: constants: `{}`",
                &flat[abs..(abs + 60).min(flat.len())]
            );
            idx = abs + 7;
        }
    }

    /// The behavioral half: every documented operation answers
    /// anything but 405, and every undocumented method on a documented
    /// path answers 405 — on the live router.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_router_serves_the_contract_exactly() {
        let ts = TestServer::spawn(Config::default())
            .await
            .expect("test server");
        for (path, methods) in documented() {
            for verb in VERBS {
                let resp = request(
                    &verb.to_uppercase(),
                    &Url::parse(&format!("{}{path}", ts.base_url)).expect("probe url"),
                    &[],
                    if verb == "get" { None } else { Some(b"{}".as_slice()) },
                    Duration::from_secs(5),
                )
                .await
                .expect("probe answered");
                if methods.contains(&verb.to_string()) {
                    assert_ne!(
                        resp.status, 405,
                        "{verb} {path}: the contract says routed, the router says otherwise"
                    );
                } else {
                    assert_eq!(
                        resp.status, 405,
                        "{verb} {path}: served but not in the contract"
                    );
                }
            }
        }
        ts.stop().await;
    }
}
