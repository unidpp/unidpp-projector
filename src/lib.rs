//! UniDPP lens projection service (crate `unidpp-projector`).
//!
//! UniDPP `10-remaining-tasks-definitive.md` item 23 (C1): the
//! projection endpoint `view(twin, profile, actor)` with its coverage
//! report — the missing product of the lens model, showcased live as
//! the EU/JP two-lens moment (STORY.md B4: one passport, two lenses,
//! two different classifications and coverage gaps, side by side,
//! neither overriding the other).
//!
//! The service is read-only and deterministic: the same passport
//! document, the same registered profile item, and the same `as-of`
//! instant always produce the same view. Modules:
//!
//! - [`api`] — the HTTP surface (axum over tokio):
//!   `GET /view?passport=<id>&profile=<profile-item>&actor=<role>[&at=]`
//!   → `{profile: {id, version}, selected, transformed, coverage,
//!   as_of, trust}`; plus `/` (service discovery) and `/healthz`;
//! - [`twin`] — the event-log fold: replay a `unidpp/passport@1`
//!   document's append-only log as-of an instant into twin facts,
//!   each carrying the origin (sequence, time, actor, trust marker)
//!   of the event that last wrote it;
//! - [`lens`] — the lens projection model: the registered profile
//!   item's manifest (core `ProfileManifest` + data-point bindings +
//!   transform bindings), parsed from the registry item's `manifest`
//!   slot;
//! - [`project`] — the projection engine: select elements (by twin
//!   fact, provenance filter, capability gate), run transforms (exact
//!   unit conversion through the ISO 80000 unit registry; band
//!   classification tables from the manifest), and assemble the view
//!   with its coverage report (reusing `unidpp-verdict`);
//! - [`registry`] — the read-side registry client: fetch profile
//!   items and unit items from a `unidpp-registry` instance over
//!   HTTP when one is configured (`UNIDPP_REGISTRY_URL`), with
//!   deterministic built-in fixtures otherwise (the issuer's
//!   registry-forwarding pattern, read side);
//! - [`http`] — the minimal async `http://` client shared by the
//!   registry client and the integration tests (house pattern);
//! - [`fixtures`] — the two-lens demonstration corpus: one laptop
//!   passport (deterministic, fixed timestamps) and the EU/JP lens
//!   manifests.
//!
//! Division of labour (MECE): the registry owns item lifecycle
//! (profiles, units — versioned supersession, as-of resolution); the
//! issuer owns passport lifecycle; the projector owns nothing — it
//! renders a passport under a profile and states exactly what it
//! could not see. Honesty is the feature: every degradation (element
//! absent as-of, provenance below the lens floor, capability gate,
//! source fact missing for a transform, registry unreachable) is
//! reported in the view, never silently dropped.

// Handlers and parse helpers return `Result<_, Response>` with the
// ready-made error response by value — the idiomatic axum pattern;
// boxing the error would complicate every call site for no gain.
#![allow(clippy::result_large_err)]

pub mod api;
pub mod fixtures;
pub mod http;
pub mod lens;
pub mod project;
pub mod registry;
pub mod twin;

pub use api::{run, Config, TestServer};
pub use lens::{ClassBand, DataPointBinding, LensManifest, TransformBinding};
pub use project::{project, MissingReason, ProfileSource, RegisteredUnit, ViewError};
pub use registry::{FetchOutcome, RegistryClient};
pub use twin::{FactOrigin, SourcedFact, TwinState};
