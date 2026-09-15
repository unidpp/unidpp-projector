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
//!   as_of, trust}`;
//!   `GET /render?passport=<id>&profile=<profile-item>&lang=<tag>[&at=]`
//!   → the presentation JSON (`{render_metadata: {template_ref, lang,
//!   formatting_rules}, sections, coverage}`); plus `/` (service
//!   discovery) and `/healthz`;
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
//!   classification tables from the manifest; Primmel decision rules
//!   with clause-URN provenance), and assemble the view with its
//!   coverage report (reusing `unidpp-verdict`);
//! - [`primmel`] — the Primmel rule-package model (TODO.impl C9): a
//!   versioned set of deterministic decision rules, each carrying the
//!   clause URN of the legal paragraph it implements, over a small
//!   typed expression AST (comparisons/arithmetic/explicit rounding
//!   on named inputs, exact decimals — never floats), with its JSON
//!   `.prml` serialization and the deterministic evaluator;
//! - [`registry`] — the read-side registry client: fetch profile
//!   items, unit items, and primmel packages from a `unidpp-registry`
//!   instance over HTTP when one is configured
//!   (`UNIDPP_REGISTRY_URL`), with deterministic built-in fixtures
//!   otherwise (the issuer's registry-forwarding pattern, read side);
//! - [`http`] — the minimal async `http://` client shared by the
//!   registry client and the integration tests (house pattern);
//! - [`render`] — the consumer presentation render (TODO.impl 54 /
//!   T-04): a passport under a lens *as a consumer sees it* — the
//!   profile's data points arranged per its presentation binding
//!   (sections, labels in the requested language, formatted values
//!   with units, links to the authoritative sources), with the same
//!   coverage honesty as the view;
//! - [`aggregate`] — the aggregation transform class (TODO.impl 66 /
//!   T-18): cross-child roll-ups over the subject's active traversal
//!   set, methodology-bound (`method_citation`) and committed to the
//!   input set's canonical traversal-set root (the core transform
//!   crate's Merkle rollup definition, TODO.impl 79), optionally
//!   sealed with a signed roll-up attestation when the projector
//!   holds a key ([`RollupSealer`]);
//! - [`codelist`] — the localization / code-list mapping class
//!   (TODO.impl 67 / T-19): registered code-list correspondences
//!   (versioned registry items; EU A–E ↔ JP star display as the
//!   built-in fixture); unmapped values emit an explicit `unmapped`;
//! - [`fixtures`] — the two-lens demonstration corpus: one laptop
//!   passport (deterministic, fixed timestamps), the EU/JP lens
//!   manifests, the built-in battery decision-rule `.prml` package (a
//!   guard band with w = U; efficiency class bands), the consumer
//!   presentation lens, and the battery-pack roll-up corpus (a pack
//!   system over three pack children + the EU-class-to-JP-star
//!   mapping).
//!
//! Division of labour (MECE): the registry owns item lifecycle
//! (profiles, units, transform packages — versioned supersession,
//! as-of resolution); the issuer owns passport lifecycle; the
//! projector owns nothing — it renders a passport under a profile and
//! states exactly what it could not see. Honesty is the feature: every
//! degradation (element absent as-of, provenance below the lens floor,
//! capability gate, source fact missing for a transform, registry
//! unreachable) is reported in the view, never silently dropped.

// Handlers and parse helpers return `Result<_, Response>` with the
// ready-made error response by value — the idiomatic axum pattern;
// boxing the error would complicate every call site for no gain.
#![allow(clippy::result_large_err)]

pub mod aggregate;
pub mod api;
pub mod codelist;
pub mod fixtures;
pub mod html;
pub mod http;
pub mod lens;
pub mod primmel;
pub mod project;
pub mod registry;
pub mod render;
pub mod twin;

pub use aggregate::{AggregationOperation, ChildDocuments, RollupSealer};
pub use api::{run, Config, TestServer};
pub use codelist::{CodeListMapping, MappingEntry, MappingSet};
pub use html::{document as render_html, Format as RenderFormat};
pub use lens::{
    ClassBand, DataPointBinding, FormattingRules, LensManifest, PresentationBinding,
    PresentationSection, TransformBinding, UnitPosition,
};
pub use primmel::{PackageSet, PrimmelPackage, PrimmelRule};
pub use project::{project, MissingReason, ProfileSource, RegisteredUnit, ViewError};
pub use registry::{FetchOutcome, RegistryClient};
pub use render::render;
pub use twin::{FactOrigin, SourcedFact, TwinState};
