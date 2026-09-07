//! The projection engine: render a passport under a lens at an
//! instant — select, transform, cover.
//!
//! Deterministic by construction: the same passport document, lens
//! manifest, and `as-of` instant produce the same view bytes (the
//! B4 border moment as a service: an offline terminal re-projects and
//! gets the same answer). Selection applies the manifest's
//! data-point bindings in three named gates, reported honestly when
//! they fail:
//!
//! 1. **capability gate** — the subject's capability class must meet
//!    the binding's floor (the silent-object lesson: an S0 subject
//!    cannot attest what it has no means to attest);
//! 2. **presence** — the source fact must exist on the twin state
//!    as-of the instant;
//! 3. **provenance filter** — the sourcing event's trust marker must
//!    meet the binding's floor (I9 ladder).
//!
//! Transforms run in manifest order through the exact machinery of
//! the core crates (unit conversion via the ISO 80000 unit registry:
//! kWh -> MJ is x 3.6 exactly; band classification from the
//! manifest's own table), and every derived value carries the trust
//! marker of its input — a derived value is never more trustworthy
//! than what it was computed from. Primmel decision-rule transforms
//! (TODO.impl C9) evaluate their package's rule deterministically over
//! the bound twin facts and carry the rule's `clause_urn` — the legal
//! paragraph the decision implements — in the output. Aggregation
//! transforms (TODO.impl 66) roll the input element up over the
//! subject's active child set, citing the method standard; code-list
//! mapping transforms (TODO.impl 67) translate a code value through a
//! registered correspondence item, emitting `unmapped` for values the
//! table does not carry.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use unidpp_cli::passport::Passport;
use unidpp_model::{CapabilityClass, Decimal, FactValue, PassportId, Timestamp, TrustMarker};
use unidpp_transform::quantity::{Quantity, UnitRegistry};
use unidpp_verdict::CoverageReport;

use crate::aggregate::{aggregation_json, ChildDocuments, RollupSealer};
use crate::codelist::{MappingSet, UNMAPPED};
use crate::lens::{ClassBand, DataPointBinding, LensManifest, TransformBinding};
use crate::primmel::{EvalError, PackageSet};
use crate::twin::{self, SourcedFact};

/// Why an element is missing from a view.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "reason", rename_all = "kebab-case")]
pub enum MissingReason {
    /// The source fact does not exist on the twin state as-of the
    /// view instant.
    AbsentAsOf,
    /// The sourcing event's trust marker is below the binding floor.
    BelowTrustFloor { floor: TrustMarker },
    /// The subject's capability class is below the binding floor.
    CapabilityGate { floor: CapabilityClass },
}

impl MissingReason {
    /// The human phrasing of the reason (shared by the view and the
    /// presentation render).
    pub(crate) fn detail(&self) -> String {
        match self {
            MissingReason::AbsentAsOf => {
                "no event wrote this fact at or before the as-of instant".to_string()
            }
            MissingReason::BelowTrustFloor { floor } => {
                format!("sourcing event below the lens trust floor `{floor}`")
            }
            MissingReason::CapabilityGate { floor } => {
                format!("subject capability below the element gate `{floor}`")
            }
        }
    }
}

/// A registered unit identity resolved from the registry's units
/// subregister (item id, name, ISO 80000 citation chain).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegisteredUnit {
    pub item: String,
    pub name: String,
    pub citation: Option<String>,
}

/// Where the lens manifest came from (honesty field of the view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSource {
    /// `registry` | `fixtures` | `unreachable` (the fallback modes).
    pub mode: String,
    /// Extra detail for fallback modes; `None` when authoritative.
    pub detail: Option<String>,
}

impl ProfileSource {
    /// Authoritative registry mode.
    pub fn registry() -> ProfileSource {
        ProfileSource {
            mode: "registry".to_string(),
            detail: None,
        }
    }

    /// Fixture fallback mode with its explanation.
    pub fn fallback(mode: &str, detail: Option<String>) -> ProfileSource {
        ProfileSource {
            mode: mode.to_string(),
            detail,
        }
    }
}

/// Projection failures that make a view impossible (structural, not
/// data, problems — data problems are reported *in* the view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewError {
    /// The lens manifest is unusable (should have been caught at
    /// parse; the engine never renders an invalid lens).
    Invalid(String),
}

impl std::fmt::Display for ViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViewError::Invalid(m) => write!(f, "invalid lens: {m}"),
        }
    }
}

impl std::error::Error for ViewError {}

/// Render the view. `actor` names the requesting role (recorded, not
/// authenticated — identity is the issuer's concern); `units` maps
/// registry unit item ids to their resolved identities (absent when
/// the registry could not serve them); `source` reports where the
/// manifest came from; `packages` holds the Primmel packages the
/// lens's rule bindings may consult (empty when the lens has none);
/// `mappings` holds the registered code-list mapping items the lens's
/// localization bindings reference; `children` holds the child
/// passport documents of the traversal set (empty when the subject
/// has no aggregation bindings or no resolvable children); `sealer`
/// is the projector's roll-up sealing identity
/// ([`RollupSealer::off`] when it holds no key — aggregation entries
/// then carry no attestation).
#[allow(clippy::too_many_arguments)]
pub fn project(
    passport: &Passport,
    lens: &LensManifest,
    at: Timestamp,
    actor: &str,
    units: &BTreeMap<String, RegisteredUnit>,
    source: &ProfileSource,
    packages: &PackageSet,
    mappings: &MappingSet,
    children: &ChildDocuments,
    sealer: &RollupSealer,
) -> Result<Value, ViewError> {
    lens.validate().map_err(ViewError::Invalid)?;
    let state = twin::fold(passport, at);
    let core_facts = state.to_core_facts();

    // --- selection -----------------------------------------------------
    let mut selected: Vec<Value> = Vec::new();
    let mut missing: Vec<(String, MissingReason)> = Vec::new();
    let mut trust: BTreeMap<String, String> = BTreeMap::new();
    let mut provided: Vec<String> = Vec::new();
    for dp in &lens.profile.data_points {
        let element = dp.to_string();
        let binding = lens
            .bindings
            .iter()
            .find(|b| b.element == element)
            .ok_or_else(|| ViewError::Invalid(format!("data point `{element}` has no binding")))?;
        match select(passport, &state, binding) {
            Selection::Blocked(reason) => missing.push((element, reason)),
            Selection::Found(fact) => {
                provided.push(element.clone());
                trust.insert(element.clone(), fact.origin.trust.to_string());
                selected.push(selected_json(&element, binding, fact));
            }
        }
    }

    // --- transforms ----------------------------------------------------
    let unit_registry = UnitRegistry::iso80000();
    let mut transformed: Vec<Value> = Vec::new();
    for binding in &lens.transforms {
        transformed.push(transform_json(
            binding,
            &passport.passport_id,
            &state,
            lens,
            &unit_registry,
            units,
            at,
            packages,
            mappings,
            children,
            sealer,
        ));
    }

    // --- coverage (reusing the verdict crate's report) ------------------
    let provided_set: BTreeSet<String> = provided.iter().cloned().collect();
    let report = CoverageReport::from_profile(&lens.profile, &provided_set);
    let missing_json: Vec<Value> = missing
        .iter()
        .map(|(element, reason)| {
            let mut m = Map::new();
            m.insert("element".into(), json!(element));
            if let Value::Object(fields) = serde_json::to_value(reason).unwrap() {
                for (k, v) in fields {
                    m.insert(k, v);
                }
            }
            m.insert("detail".into(), json!(reason.detail()));
            Value::Object(m)
        })
        .collect();

    // --- profile block -------------------------------------------------
    let mut profile = Map::new();
    profile.insert("id".into(), json!(lens.profile.id.as_str()));
    profile.insert("version".into(), json!(lens.version));
    profile.insert("axes".into(), json!(lens.profile.axes.to_string()));
    profile.insert("trigger".into(), json!(lens.profile.trigger.describe()));
    profile.insert(
        "freshness".into(),
        json!(lens.profile.freshness.to_string()),
    );
    profile.insert(
        "min_capability".into(),
        json!(lens.profile.min_capability.to_string()),
    );
    profile.insert(
        "applies".into(),
        json!(lens.profile.applies_to(&core_facts, at)),
    );
    profile.insert(
        "satisfiable".into(),
        json!(lens.profile.is_satisfiable_by(passport.capability)),
    );
    profile.insert(
        "resolution".into(),
        json!(lens.profile.resolution.to_string()),
    );
    profile.insert("source".into(), json!(source.mode));
    if let Some(d) = &source.detail {
        profile.insert("source_detail".into(), json!(d));
    }

    // --- passport block --------------------------------------------------
    let mut passport_block = Map::new();
    passport_block.insert("id".into(), json!(passport.passport_id.as_str()));
    passport_block.insert("product_id".into(), json!(passport.product_id.to_string()));
    passport_block.insert("capability".into(), json!(passport.capability.to_string()));
    passport_block.insert("status".into(), json!(state.status.to_string()));
    if let Some(c) = &state.custodian {
        passport_block.insert("custodian".into(), json!(c));
    }
    passport_block.insert("events".into(), json!(state.event_count));
    if let Some(head) = passport.log.state_hash_at(at) {
        passport_block.insert("log_head".into(), json!(head.hex()));
    }
    passport_block.insert(
        "validity".into(),
        json!({
            "from": passport.validity.from.to_string(),
            "to": passport.validity.to.map(|t| t.to_string()),
            "contains_as_of": passport.validity.contains(at),
        }),
    );

    let mut view = Map::new();
    view.insert("service".into(), json!("unidpp-projector"));
    view.insert("actor".into(), json!(actor));
    view.insert("as_of".into(), json!(at.to_string()));
    view.insert("passport".into(), Value::Object(passport_block));
    view.insert("profile".into(), Value::Object(profile));
    view.insert("selected".into(), Value::Array(selected));
    view.insert("transformed".into(), Value::Array(transformed));
    view.insert(
        "coverage".into(),
        json!({
            "elements_required": report.required.len(),
            "elements_present": report.present.len(),
            "missing": missing_json,
            "complete": report.is_complete(),
            "ratio": report.ratio(),
        }),
    );
    view.insert("trust".into(), serde_json::to_value(trust).unwrap());
    Ok(Value::Object(view))
}

/// The outcome of evaluating one binding (shared with the
/// presentation render — one selection model, two surfaces).
pub(crate) enum Selection<'a> {
    Found(&'a SourcedFact),
    Blocked(MissingReason),
}

pub(crate) fn select<'a>(
    passport: &Passport,
    state: &'a twin::TwinState,
    binding: &DataPointBinding,
) -> Selection<'a> {
    // Gate 1: capability (a property of the subject, not the value).
    if passport.capability < binding.min_capability {
        return Selection::Blocked(MissingReason::CapabilityGate {
            floor: binding.min_capability,
        });
    }
    // Gate 2: presence on the twin state (already folded as-of).
    let Some(fact) = state.get(&binding.source) else {
        return Selection::Blocked(MissingReason::AbsentAsOf);
    };
    // Gate 3: provenance floor.
    if !fact.origin.trust.meets(binding.min_trust) {
        return Selection::Blocked(MissingReason::BelowTrustFloor {
            floor: binding.min_trust,
        });
    }
    Selection::Found(fact)
}

fn selected_json(element: &str, binding: &DataPointBinding, fact: &SourcedFact) -> Value {
    let mut m = Map::new();
    m.insert("element".into(), json!(element));
    m.insert("value".into(), fact_value_json(&fact.value));
    m.insert("kind".into(), json!(fact.value.type_name()));
    if let Some(u) = &binding.declared_unit {
        m.insert("declared_unit".into(), json!(u));
    }
    m.insert(
        "sourced".into(),
        json!({
            "seq": fact.origin.seq,
            "occurred_at": fact.origin.occurred_at.to_string(),
            "actor_role": fact.origin.actor_role,
            "actor_id": fact.origin.actor_id,
        }),
    );
    m.insert("trust".into(), json!(fact.origin.trust.to_string()));
    Value::Object(m)
}

/// A fact value as plain JSON: decimals stay exact strings, booleans
/// and lists are native, strings are strings (shared with the
/// presentation render).
pub(crate) fn fact_value_json(value: &FactValue) -> Value {
    match value {
        FactValue::Str(s) => json!(s),
        FactValue::Num(d) => json!(d.to_string()),
        FactValue::Bool(b) => json!(b),
        FactValue::List(l) => json!(l),
    }
}

#[allow(clippy::too_many_arguments)]
fn transform_json(
    binding: &TransformBinding,
    subject: &PassportId,
    state: &twin::TwinState,
    lens: &LensManifest,
    unit_registry: &UnitRegistry,
    units: &BTreeMap<String, RegisteredUnit>,
    at: Timestamp,
    packages: &PackageSet,
    mappings: &MappingSet,
    children: &ChildDocuments,
    sealer: &RollupSealer,
) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), json!(binding.id()));
    let kind = match binding {
        TransformBinding::UnitConversion { .. } => "unit-conversion",
        TransformBinding::Classification { .. } => "classification",
        TransformBinding::Primmel { .. } => "primmel",
        TransformBinding::Aggregation { .. } => "aggregation",
        TransformBinding::LocalizationMapping { .. } => "localization-mapping",
    };
    m.insert("kind".into(), json!(kind));
    // Aggregation entries render their own source line (the input
    // element fanned out over children) and evaluate through the
    // aggregate module.
    if let TransformBinding::Aggregation {
        operation,
        input_element,
        weight_element,
        method_citation,
        ..
    } = binding
    {
        // Unreachable after validate(): the element is a data point
        // and every data point is bound — but the engine still states
        // the gap rather than panicking.
        let (input_binding, weight_binding) = match (
            lens.binding_for(input_element),
            weight_element.as_deref().and_then(|w| lens.binding_for(w)),
        ) {
            (Some(i), w) => (i, w),
            (None, _) => {
                let mut failed = Map::new();
                failed.insert("id".into(), json!(binding.id()));
                failed.insert("kind".into(), json!("aggregation"));
                failed.insert("status".into(), json!("failed"));
                failed.insert(
                    "error".into(),
                    json!(format!(
                        "aggregation `{}` input element `{input_element}` \
                         has no binding",
                        binding.id()
                    )),
                );
                return Value::Object(failed);
            }
        };
        return aggregation_json(
            binding.id(),
            *operation,
            input_binding,
            weight_binding,
            method_citation,
            subject,
            state,
            children,
            unit_registry,
            sealer,
            at,
        );
    }
    m.insert("source".into(), json!(binding.source()));
    if let TransformBinding::Primmel {
        package_ref,
        rule_id,
        inputs,
        ..
    } = binding
    {
        // Primmel rules own their JSON shape: inputs, decision,
        // provenance. (The generic input/trust fields below are
        // covered by the per-input block this branch emits.)
        m.insert("package_ref".into(), json!(package_ref));
        m.insert("rule_id".into(), json!(rule_id));
        // The full set of fact paths this rule consumes (deterministic
        // input-name order), not just the first one.
        let paths: Vec<&str> = inputs.values().map(String::as_str).collect();
        m.insert("source".into(), json!(paths.join(",")));
        let entry = primmel_json(package_ref, rule_id, inputs, state, packages, at);
        if let Value::Object(fields) = entry {
            for (k, v) in fields {
                m.insert(k, v);
            }
        }
        return Value::Object(m);
    }
    if let TransformBinding::LocalizationMapping { mapping_ref, .. } = binding {
        // Localization mappings own their JSON shape: the mapped
        // output (or the explicit `unmapped`), the mapping item's
        // identity and citation. (The generic input/trust fields below
        // are covered by the block this branch emits.)
        let entry = mapping_json(mapping_ref, binding.source(), state, mappings, at);
        if let Value::Object(fields) = entry {
            for (k, v) in fields {
                m.insert(k, v);
            }
        }
        return Value::Object(m);
    }
    let fact = state.get(binding.source());
    let computed: Option<Value> = match binding {
        TransformBinding::UnitConversion {
            from_unit,
            to_unit,
            from_item,
            to_item,
            ..
        } => fact.and_then(|fact| match &fact.value {
            FactValue::Num(amount) => unit_conversion_json(
                amount,
                from_unit,
                to_unit,
                from_item,
                to_item,
                unit_registry,
                units,
            ),
            _ => None,
        }),
        TransformBinding::Classification { bands, .. } => {
            fact.and_then(|fact| match &fact.value {
                FactValue::Num(v) => Some(match classify(bands, v) {
                    Some(band) => json!({
                        "output": band.label,
                        "band": {"label": band.label, "min": band.min.to_string()},
                    }),
                    // Below the lowest band: explicit, never silent.
                    None => json!({
                        "output": "unclassified",
                        "below_lowest_band": bands
                            .iter()
                            .map(|b| b.min.to_string())
                            .min()
                            .unwrap_or_default(),
                    }),
                }),
                _ => None,
            })
        }
        // Primmel and localization-mapping bindings render their own
        // entries (early returns above); aggregation evaluates in the
        // aggregate module (early return above).
        TransformBinding::Primmel { .. }
        | TransformBinding::Aggregation { .. }
        | TransformBinding::LocalizationMapping { .. } => None,
    };
    // The input travels with the transform whatever happens (so a
    // failed transform still states what it was asked to compute).
    if let Some(fact) = fact {
        m.insert("input".into(), fact_value_json(&fact.value));
        m.insert("trust".into(), json!(fact.origin.trust.to_string()));
    }
    match computed {
        Some(fields) => {
            if let Value::Object(extra) = fields {
                for (k, v) in extra {
                    m.insert(k, v);
                }
            }
            m.insert("status".into(), json!("computed"));
        }
        None => {
            let error = if fact.is_none() {
                format!("source fact `{}` is absent as-of {}", binding.source(), at)
            } else {
                match binding {
                    TransformBinding::UnitConversion {
                        from_unit, to_unit, ..
                    } => format!(
                        "cannot convert source value from `{from_unit}` to `{to_unit}` \
                         (dimension mismatch or unregistered unit)"
                    ),
                    TransformBinding::Classification { .. } => {
                        "classification source is not a numeric fact".to_string()
                    }
                    TransformBinding::Primmel { .. } => "primmel rule could not run".to_string(),
                    // Unreachable: aggregation and localization
                    // mappings early-return their own entries.
                    TransformBinding::Aggregation { .. } => "aggregation could not run".to_string(),
                    TransformBinding::LocalizationMapping { .. } => {
                        "localization mapping could not run".to_string()
                    }
                }
            };
            m.insert("status".into(), json!("failed"));
            m.insert("error".into(), json!(error));
        }
    }
    Value::Object(m)
}

/// Evaluate one Primmel rule binding and render its transform entry:
/// the decision label, the rule's clause-URN provenance (the legal
/// paragraph it implements), the resolved inputs with their values and
/// trust, and the package identity. Failure paths follow the honesty
/// doctrine: absent inputs are a *coverage* gap (`missing-inputs`,
/// per-input reasons); a package the projector does not hold, a rule
/// the package lacks, or a non-numeric input is a failure with its
/// reason — never a guessed label.
#[allow(clippy::too_many_arguments)]
fn primmel_json(
    package_ref: &str,
    rule_id: &str,
    inputs: &BTreeMap<String, String>,
    state: &twin::TwinState,
    packages: &PackageSet,
    at: Timestamp,
) -> Value {
    let mut m = Map::new();
    let Some((package, package_source)) = packages.get(package_ref) else {
        m.insert("status".into(), json!("failed"));
        m.insert(
            "error".into(),
            json!(format!(
                "primmel package `{package_ref}` is not available to this \
                 projector (rule `{rule_id}` cannot run)"
            )),
        );
        return Value::Object(m);
    };
    let mut package_block = Map::new();
    package_block.insert("id".into(), json!(package.id));
    package_block.insert("version".into(), json!(package.version));
    package_block.insert("source".into(), json!(package_source));
    m.insert("package".into(), Value::Object(package_block));
    let Some(rule) = package.rule(rule_id) else {
        m.insert("status".into(), json!("failed"));
        m.insert(
            "error".into(),
            json!(format!(
                "primmel package `{package_ref}` has no rule `{rule_id}` \
                 (it holds: {})",
                package
                    .rules
                    .iter()
                    .map(|r| r.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        );
        return Value::Object(m);
    };

    // Resolve the rule's named inputs against the twin state: each
    // binding maps a rule input name to a fact path. A missing input
    // is reported per input — coverage, not error.
    let mut values: BTreeMap<String, Decimal> = BTreeMap::new();
    let mut input_block = Map::new();
    let mut missing_inputs: Vec<Value> = Vec::new();
    let mut weakest_trust: Option<TrustMarker> = None;
    for (name, path) in inputs {
        let mut entry = Map::new();
        entry.insert("path".into(), json!(path));
        match state.get(path) {
            None => {
                missing_inputs.push(json!({
                    "input": name,
                    "path": path,
                    "reason": "absent-as-of",
                    "detail": format!(
                        "no event wrote fact `{path}` at or before the \
                         as-of instant {at}"
                    ),
                }));
            }
            Some(fact) => match &fact.value {
                FactValue::Num(v) => {
                    values.insert(name.clone(), *v);
                    entry.insert("value".into(), json!(v.to_string()));
                    entry.insert("trust".into(), json!(fact.origin.trust.to_string()));
                    entry.insert("sourced_seq".into(), json!(fact.origin.seq));
                    weakest_trust = Some(match weakest_trust {
                        None => fact.origin.trust,
                        // The derived decision is never more
                        // trustworthy than its weakest input.
                        Some(floor) if fact.origin.trust.grade() < floor.grade() => {
                            fact.origin.trust
                        }
                        Some(floor) => floor,
                    });
                }
                other => {
                    missing_inputs.push(json!({
                        "input": name,
                        "path": path,
                        "reason": "not-numeric",
                        "detail": format!(
                            "fact `{path}` is a {} fact; the rule needs a \
                             numeric measurand",
                            other.type_name()
                        ),
                    }));
                }
            },
        }
        input_block.insert(name.clone(), Value::Object(entry));
    }
    m.insert("inputs".into(), Value::Object(input_block));

    if !missing_inputs.is_empty() {
        // The rule's paragraph stands even when the facts do not: the
        // clause URN is emitted with the coverage gap.
        m.insert("clause_urn".into(), json!(rule.clause_urn));
        m.insert("status".into(), json!("missing-inputs"));
        m.insert("missing_inputs".into(), Value::Array(missing_inputs));
        return Value::Object(m);
    }
    match rule.evaluate(&values) {
        Ok(outcome) => {
            m.insert("clause_urn".into(), json!(rule.clause_urn));
            m.insert("output".into(), json!(outcome.label));
            if let Some(arm) = outcome.matched_arm {
                m.insert("matched_arm".into(), json!(arm));
            } else {
                m.insert("matched_arm".into(), Value::Null);
            }
            if let Some(t) = weakest_trust {
                m.insert("trust".into(), json!(t.to_string()));
            }
            m.insert("status".into(), json!("computed"));
        }
        Err(EvalError::MissingInput { input }) => {
            // The binding did not map every input the rule names.
            m.insert("status".into(), json!("missing-inputs"));
            m.insert(
                "missing_inputs".into(),
                json!([{
                    "input": input,
                    "path": inputs.get(&input).map(String::as_str).unwrap_or(""),
                    "reason": "not-bound",
                    "detail": format!(
                        "rule `{rule_id}` consumes input `{input}`, which \
                         the binding does not map to a twin fact path"
                    ),
                }]),
            );
        }
        Err(e) => {
            m.insert("status".into(), json!("failed"));
            m.insert("error".into(), json!(format!("rule `{rule_id}`: {e}")));
        }
    }
    Value::Object(m)
}

/// Evaluate one localization-mapping binding and render its transform
/// entry (TODO.impl 67): the input code value, the mapping item's
/// identity/version/schemes/citation and sourcing mode, and the target
/// value — or the explicit [`UNMAPPED`] output when the table carries
/// no correspondence for the input. Honesty doctrine: a missing fact
/// as-of or an unavailable mapping item is a failure with its reason;
/// a *present but unmapped* value is the `unmapped` output, never a
/// silent pass-through.
fn mapping_json(
    mapping_ref: &str,
    source: &str,
    state: &twin::TwinState,
    mappings: &MappingSet,
    at: Timestamp,
) -> Value {
    let mut m = Map::new();
    let input = state.get(source);
    let Some(fact) = input else {
        m.insert("status".into(), json!("failed"));
        m.insert(
            "error".into(),
            json!(format!("source fact `{source}` is absent as-of {at}")),
        );
        return Value::Object(m);
    };
    m.insert("input".into(), fact_value_json(&fact.value));
    m.insert("trust".into(), json!(fact.origin.trust.to_string()));
    // Code values are strings (or numeric codes, looked up by their
    // exact decimal spelling).
    let code = match &fact.value {
        FactValue::Str(s) => s.clone(),
        FactValue::Num(n) => n.to_string(),
        other => {
            m.insert("status".into(), json!("failed"));
            m.insert(
                "error".into(),
                json!(format!(
                    "mapping source `{source}` is a {} fact; the table \
                     keys on code values",
                    other.type_name()
                )),
            );
            return Value::Object(m);
        }
    };
    let Some((mapping, mapping_source)) = mappings.get(mapping_ref) else {
        m.insert("status".into(), json!("failed"));
        m.insert(
            "error".into(),
            json!(format!(
                "code-list mapping item `{mapping_ref}` is not available \
                 to this projector"
            )),
        );
        return Value::Object(m);
    };
    let mut block = Map::new();
    block.insert("id".into(), json!(mapping.id));
    block.insert("version".into(), json!(mapping.version));
    block.insert("source".into(), json!(mapping_source));
    block.insert("source_scheme".into(), json!(mapping.source_scheme));
    block.insert("target_scheme".into(), json!(mapping.target_scheme));
    if let Some(c) = &mapping.citation {
        block.insert("citation".into(), json!(c));
    }
    block.insert("entries".into(), json!(mapping.table.len()));
    m.insert("mapping".into(), Value::Object(block));
    match mapping.lookup(&code) {
        Some(entry) => {
            m.insert("output".into(), json!(entry.target_value));
            if let Some(note) = &entry.note {
                m.insert("note".into(), json!(note));
            }
            m.insert("status".into(), json!("computed"));
        }
        None => {
            // A value the registered table does not carry: explicit,
            // never a silent pass of the source value.
            m.insert("output".into(), json!(UNMAPPED));
            m.insert(
                "detail".into(),
                json!(format!(
                    "value `{code}` of {} has no correspondence in `{}` \
                     ({} -> {})",
                    mapping.source_scheme, mapping.id, mapping.source_scheme, mapping.target_scheme
                )),
            );
            m.insert("status".into(), json!(UNMAPPED));
        }
    }
    Value::Object(m)
}

/// The exact conversion and the resolved unit identities. `None` when
/// the source is not a numeric fact in a registered unit — the caller
/// reports the failure with its reason.
fn unit_conversion_json(
    amount: &Decimal,
    from_unit: &str,
    to_unit: &str,
    from_item: &Option<String>,
    to_item: &Option<String>,
    unit_registry: &UnitRegistry,
    units: &BTreeMap<String, RegisteredUnit>,
) -> Option<Value> {
    let input = Quantity::parse(&amount.to_string(), from_unit, unit_registry).ok()?;
    let target = unit_registry.unit(to_unit).ok()?;
    let output = input.convert_to(&target, unit_registry).ok()?;
    let mut fields = Map::new();
    fields.insert(
        "input".into(),
        json!({"amount": amount.to_string(), "unit": from_unit}),
    );
    fields.insert(
        "output".into(),
        json!({"amount": output.amount.to_string(), "unit": to_unit}),
    );
    fields.insert("exact".into(), json!(true));
    let mut units_block = Map::new();
    units_block.insert(from_unit.to_string(), unit_identity_json(from_item, units));
    units_block.insert(to_unit.to_string(), unit_identity_json(to_item, units));
    fields.insert("units".into(), Value::Object(units_block));
    Some(Value::Object(fields))
}

/// The band the value falls into: the highest `min` the value meets;
/// below the lowest band the value is `unclassified` (`None` here).
fn classify<'a>(bands: &'a [ClassBand], value: &Decimal) -> Option<&'a ClassBand> {
    let mut ordered: Vec<&ClassBand> = bands.iter().collect();
    ordered.sort_by_key(|band| std::cmp::Reverse(band.min));
    ordered.into_iter().find(|band| value >= &band.min)
}

fn unit_identity_json(item: &Option<String>, units: &BTreeMap<String, RegisteredUnit>) -> Value {
    match item.as_deref().and_then(|id| units.get(id)) {
        Some(u) => json!({
            "uom_registered": true,
            "item": u.item,
            "name": u.name,
            "citation": u.citation,
        }),
        None => match item {
            Some(id) => json!({
                "uom_registered": false,
                "item": id,
                "note": "unit item not resolvable from the registry as-of this view",
            }),
            None => json!({"uom_registered": false}),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregate::AggregationOperation;
    use crate::lens::{ClassBand, DataPointBinding};
    use unidpp_event::{EventLog, EventPayload, TypedEvent};
    use unidpp_model::{
        CapabilityClass, DataPointRef, FreshnessRequirement, Interval, PassportId, ProfileAxes,
        ProfileManifest, Resolution, SignatureSuite, Traversal, TriggerPredicate, VisibilityClass,
    };

    fn at() -> Timestamp {
        Timestamp::from_secs(1_800_000_000)
    }

    fn event(seq: u64, payload: EventPayload, trust: TrustMarker) -> TypedEvent {
        TypedEvent::new(
            seq,
            Timestamp::from_secs(1_700_000_000 + seq as i64),
            "economic operator",
            "urn:unidpp:actor:test",
            payload.event_type(),
            payload,
            trust,
        )
        .unwrap()
    }

    fn passport_with(capability: CapabilityClass, events: Vec<TypedEvent>) -> Passport {
        let mut log = EventLog::new(PassportId::new("urn:unidpp:passport:test-subject").unwrap());
        for e in events {
            log.append(e, None, None).unwrap();
        }
        Passport {
            schema: unidpp_cli::passport::SCHEMA.to_string(),
            passport_id: PassportId::new("urn:unidpp:passport:test-subject").unwrap(),
            product_id: unidpp_model::ProductIdentifier::parse("gtin:4006381333931").unwrap(),
            type_ref: None,
            capability,
            eo_id: "urn:unidpp:actor:test".to_string(),
            resolver_uri: "https://resolver.unidpp.org/x".to_string(),
            validity: Interval::starting(Timestamp::from_secs(0)),
            created_at: Timestamp::from_secs(1_700_000_000),
            log,
            event_signatures: Vec::new(),
        }
    }

    /// A rich passport: an attested milestone (score, capacity), an
    /// unsigned correction (weak fact), a self-declared correction.
    fn rich_passport() -> Passport {
        passport_with(
            CapabilityClass::PassiveAuth,
            vec![
                event(
                    0,
                    EventPayload::MilestoneRecord {
                        counters: [
                            ("score".to_string(), "8.1".parse().unwrap()),
                            ("capacity-kwh".to_string(), "5".parse().unwrap()),
                            ("low-grade".to_string(), "3.9".parse().unwrap()),
                        ]
                        .into_iter()
                        .collect(),
                    },
                    TrustMarker::Attested,
                ),
                event(
                    1,
                    EventPayload::Correction {
                        field: "weak".into(),
                        prior_value: String::new(),
                        new_value: "weak-value".into(),
                        reason: "unsigned declaration".into(),
                    },
                    TrustMarker::Unsigned,
                ),
            ],
        )
    }

    fn lens_with(
        bindings: Vec<DataPointBinding>,
        transforms: Vec<TransformBinding>,
    ) -> LensManifest {
        let lens = LensManifest {
            version: "1.0.0".into(),
            profile: ProfileManifest {
                id: unidpp_model::ProfileId::new("urn:unidpp:profile:test").unwrap(),
                axes: ProfileAxes::jurisdiction("EU"),
                trigger: TriggerPredicate::Any,
                min_capability: CapabilityClass::Silent,
                freshness: FreshnessRequirement::Static,
                effective: Interval::starting(Timestamp::from_secs(0)),
                data_points: bindings.iter().map(|b| data_point_of(&b.element)).collect(),
                crypto_suites: vec![SignatureSuite::EcdsaP256],
                confidential: false,
                resolution: Resolution::Public,
                edge_visibility: VisibilityClass::Public,
                traversal: Traversal::Public,
            },
            bindings,
            transforms,
            presentation: None,
        };
        lens
    }

    /// The data-point reference whose canonical string is `element`
    /// (`register/item@version`).
    fn data_point_of(element: &str) -> DataPointRef {
        let (reg_item, version) = element.rsplit_once('@').expect("element carries @version");
        let (register, item) = reg_item.split_once('/').expect("element carries register/");
        DataPointRef {
            register: register.to_string(),
            item: item.to_string(),
            version: Some(version.to_string()),
        }
    }

    fn binding(element: &str, source: &str) -> DataPointBinding {
        DataPointBinding {
            element: element.into(),
            source: source.into(),
            min_trust: TrustMarker::Unsigned,
            min_capability: CapabilityClass::Silent,
            declared_unit: None,
        }
    }

    fn render(passport: &Passport, lens: &LensManifest) -> Value {
        render_with(passport, lens, &crate::fixtures::fixture_primmel())
    }

    fn render_with(passport: &Passport, lens: &LensManifest, packages: &PackageSet) -> Value {
        project(
            passport,
            lens,
            at(),
            "market-surveillance-authority",
            &BTreeMap::new(),
            &ProfileSource::registry(),
            packages,
            &MappingSet::empty(),
            &ChildDocuments::empty(),
            &RollupSealer::off(),
        )
        .unwrap()
    }

    /// A one-binding lens with the fixture Primmel package available
    /// (the guard-band rule of the demo corpus).
    fn primmel_lens(package_ref: &str, rule_id: &str, inputs: Vec<(&str, &str)>) -> LensManifest {
        lens_with(
            vec![binding("ferin:eu/score@1", "score")],
            vec![TransformBinding::Primmel {
                id: "rule".into(),
                package_ref: package_ref.into(),
                rule_id: rule_id.into(),
                inputs: inputs
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }],
        )
    }

    #[test]
    fn primmel_rule_evaluates_with_clause_urn_provenance() {
        let lens = primmel_lens(
            "urn:primmel:pkg:battery-rules",
            "soh-guard-band",
            vec![("soh", "score"), ("U", "capacity-kwh")],
        );
        // score 8.1 - capacity 5 = 3.1 < 85: the else arm — the
        // decision, its arm, and the paragraph it implements.
        let view = render(&rich_passport(), &lens);
        let t = &view["transformed"][0];
        assert_eq!(t["kind"], json!("primmel"));
        assert_eq!(t["status"], json!("computed"));
        assert_eq!(t["output"], json!("not-demonstrably-conforming"));
        assert_eq!(t["matched_arm"], json!(1));
        assert_eq!(
            t["clause_urn"],
            json!("urn:oiml:pub:r:91-2:2025#clause-6.1")
        );
        assert_eq!(t["package"]["id"], json!("urn:primmel:pkg:battery-rules"));
        assert_eq!(t["package"]["version"], json!("1.0.0"));
        assert_eq!(t["package"]["source"], json!("fixtures"));
        assert_eq!(t["rule_id"], json!("soh-guard-band"));
        assert_eq!(t["inputs"]["soh"]["value"], json!("8.1"));
        assert_eq!(t["inputs"]["soh"]["trust"], json!("attested"));
        // Both inputs are attested: the decision inherits that marker.
        assert_eq!(t["trust"], json!("attested"));
    }

    #[test]
    fn primmel_decision_carries_the_weakest_input_trust() {
        // A passport whose SoH comes from an attested milestone and
        // whose uncertainty from a self-declared correction: the
        // decision is never more trustworthy than its weakest input.
        let passport = passport_with(
            CapabilityClass::PassiveAuth,
            vec![
                event(
                    0,
                    EventPayload::MilestoneRecord {
                        counters: [("soh".to_string(), "90.5".parse().unwrap())]
                            .into_iter()
                            .collect(),
                    },
                    TrustMarker::Attested,
                ),
                event(
                    1,
                    EventPayload::Correction {
                        field: "soh-u".into(),
                        prior_value: String::new(),
                        new_value: "0.5".into(),
                        reason: "declared uncertainty".into(),
                    },
                    TrustMarker::SelfDeclared,
                ),
            ],
        );
        let lens = primmel_lens(
            "urn:primmel:pkg:battery-rules",
            "soh-guard-band",
            vec![("soh", "soh"), ("U", "soh-u")],
        );
        let view = render(&passport, &lens);
        let t = &view["transformed"][0];
        // 90.5 - 0.5 = 90 >= 85: conforming, but graded self-declared.
        assert_eq!(t["output"], json!("conforming"));
        assert_eq!(t["inputs"]["soh"]["trust"], json!("attested"));
        assert_eq!(t["inputs"]["U"]["trust"], json!("self-declared"));
        assert_eq!(t["trust"], json!("self-declared"));
    }

    #[test]
    fn primmel_with_absent_input_reports_missing_coverage_not_error() {
        // The rule's inputs do not exist as-of the instant (and one
        // resolves to a string fact): a coverage gap with per-input
        // reasons, never a crash and never a guessed label.
        let lens = primmel_lens(
            "urn:primmel:pkg:battery-rules",
            "soh-guard-band",
            vec![("soh", "ghost"), ("U", "weak")],
        );
        let view = render(&rich_passport(), &lens);
        let t = &view["transformed"][0];
        assert_eq!(t["status"], json!("missing-inputs"));
        assert_eq!(
            t["clause_urn"],
            json!("urn:oiml:pub:r:91-2:2025#clause-6.1")
        );
        let missing = t["missing_inputs"].as_array().unwrap();
        assert_eq!(missing.len(), 2);
        // Input names resolve by identity (map order is by input
        // name, not assertion order); one gap per reason.
        let soh = missing.iter().find(|m| m["input"] == json!("soh")).unwrap();
        assert_eq!(soh["reason"], json!("absent-as-of"));
        assert!(soh["detail"].as_str().unwrap().contains("ghost"));
        let u = missing.iter().find(|m| m["input"] == json!("U")).unwrap();
        assert_eq!(u["reason"], json!("not-numeric"));
        assert!(u["detail"].as_str().unwrap().contains("numeric measurand"));
        assert_eq!(t["inputs"]["soh"]["path"], json!("ghost"));
        assert!(t.get("output").is_none());
    }

    #[test]
    fn primmel_with_unmapped_rule_input_reports_the_binding_gap() {
        // The binding maps `U` but the rule also wants `soh`: the gap
        // names the unmapped input.
        let lens = primmel_lens(
            "urn:primmel:pkg:battery-rules",
            "soh-guard-band",
            vec![("U", "capacity-kwh")],
        );
        let view = render(&rich_passport(), &lens);
        let t = &view["transformed"][0];
        assert_eq!(t["status"], json!("missing-inputs"));
        let missing = t["missing_inputs"].as_array().unwrap();
        assert_eq!(missing[0]["input"], json!("soh"));
        assert_eq!(missing[0]["reason"], json!("not-bound"));
    }

    #[test]
    fn primmel_with_non_numeric_input_fails_with_reason() {
        let lens = primmel_lens(
            "urn:primmel:pkg:battery-rules",
            "efficiency-class",
            vec![("eff", "weak")],
        );
        let view = render(&rich_passport(), &lens);
        let t = &view["transformed"][0];
        // A string fact is a type gap on the input, reported per
        // input like any other missing measurand.
        assert_eq!(t["status"], json!("missing-inputs"));
        let missing = t["missing_inputs"].as_array().unwrap();
        assert_eq!(missing[0]["reason"], json!("not-numeric"));
        assert!(missing[0]["detail"]
            .as_str()
            .unwrap()
            .contains("numeric measurand"));
    }

    #[test]
    fn primmel_without_the_package_or_rule_fails_honestly() {
        // Package the projector does not hold.
        let lens = primmel_lens(
            "urn:primmel:pkg:nowhere",
            "soh-guard-band",
            vec![("soh", "score")],
        );
        let view = render(&rich_passport(), &lens);
        assert_eq!(view["transformed"][0]["status"], json!("failed"));
        assert!(view["transformed"][0]["error"]
            .as_str()
            .unwrap()
            .contains("not available"));

        // Package held, rule id not in it.
        let lens = primmel_lens(
            "urn:primmel:pkg:battery-rules",
            "no-such-rule",
            vec![("soh", "score")],
        );
        let view = render(&rich_passport(), &lens);
        assert_eq!(view["transformed"][0]["status"], json!("failed"));
        let error = view["transformed"][0]["error"].as_str().unwrap();
        assert!(
            error.contains("no rule") && error.contains("soh-guard-band"),
            "{error}"
        );
    }

    #[test]
    fn primmel_evaluation_is_deterministic() {
        let lens = primmel_lens(
            "urn:primmel:pkg:battery-rules",
            "soh-guard-band",
            vec![("soh", "score"), ("U", "capacity-kwh")],
        );
        let first = render(&rich_passport(), &lens);
        let second = render(&rich_passport(), &lens);
        assert_eq!(first["transformed"], second["transformed"]);
    }

    #[test]
    fn selection_binds_elements_to_facts_with_provenance() {
        let lens = lens_with(vec![binding("ferin:eu/score@1", "score")], vec![]);
        let view = render(&rich_passport(), &lens);
        let selected = view["selected"].as_array().unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0]["element"], json!("ferin:eu/score@1"));
        assert_eq!(selected[0]["value"], json!("8.1"));
        assert_eq!(selected[0]["kind"], json!("num"));
        assert_eq!(selected[0]["sourced"]["seq"], json!(0));
        assert_eq!(selected[0]["trust"], json!("attested"));
        // The trust map carries the marker per element.
        assert_eq!(view["trust"]["ferin:eu/score@1"], json!("attested"));
        assert_eq!(view["actor"], json!("market-surveillance-authority"));
    }

    #[test]
    fn absent_elements_are_missing_with_reason() {
        let lens = lens_with(
            vec![
                binding("ferin:eu/score@1", "score"),
                binding("ferin:eu/ghost@1", "ghost"),
            ],
            vec![],
        );
        let view = render(&rich_passport(), &lens);
        assert_eq!(view["coverage"]["elements_required"], json!(2));
        assert_eq!(view["coverage"]["elements_present"], json!(1));
        let missing = view["coverage"]["missing"].as_array().unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0]["element"], json!("ferin:eu/ghost@1"));
        assert_eq!(missing[0]["reason"], json!("absent-as-of"));
        assert!(!view["coverage"]["complete"].as_bool().unwrap());
        // 1 of 2.
        assert!((view["coverage"]["ratio"].as_f64().unwrap() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn provenance_floor_blocks_below_grade_facts() {
        let mut b = binding("ferin:eu/weak@1", "weak");
        b.min_trust = TrustMarker::SelfDeclared;
        let lens = lens_with(vec![b], vec![]);
        let view = render(&rich_passport(), &lens);
        let missing = view["coverage"]["missing"].as_array().unwrap();
        assert_eq!(missing[0]["reason"], json!("below-trust-floor"));
        assert_eq!(missing[0]["floor"], json!("self-declared"));
        assert_eq!(view["selected"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn capability_gate_blocks_below_class_subjects() {
        let mut b = binding("ferin:eu/score@1", "score");
        b.min_capability = CapabilityClass::Connected;
        let lens = lens_with(vec![b], vec![]);
        // The rich passport is S1; the gate demands S3.
        let view = render(&rich_passport(), &lens);
        let missing = view["coverage"]["missing"].as_array().unwrap();
        assert_eq!(missing[0]["reason"], json!("capability-gate"));
        assert_eq!(missing[0]["floor"], json!("connected"));
    }

    #[test]
    fn unit_conversion_is_exact_kwh_to_mj() {
        let lens = lens_with(
            vec![binding("ferin:eu/score@1", "score")],
            vec![TransformBinding::UnitConversion {
                id: "mj".into(),
                source: "capacity-kwh".into(),
                from_unit: "kWh".into(),
                to_unit: "MJ".into(),
                from_item: None,
                to_item: None,
            }],
        );
        let view = render(&rich_passport(), &lens);
        let t = &view["transformed"][0];
        assert_eq!(t["status"], json!("computed"));
        assert_eq!(t["output"]["amount"], json!("18")); // 5 kWh = 18 MJ exactly
        assert_eq!(t["output"]["unit"], json!("MJ"));
        assert_eq!(t["input"]["amount"], json!("5"));
        assert_eq!(t["exact"], json!(true));
        assert_eq!(t["trust"], json!("attested"));
    }

    #[test]
    fn unit_conversion_dimension_mismatch_fails_visibly() {
        let lens = lens_with(
            vec![binding("ferin:eu/score@1", "score")],
            vec![TransformBinding::UnitConversion {
                id: "nonsense".into(),
                source: "capacity-kwh".into(),
                from_unit: "kWh".into(),
                to_unit: "kg".into(),
                from_item: None,
                to_item: None,
            }],
        );
        let view = render(&rich_passport(), &lens);
        let t = &view["transformed"][0];
        assert_eq!(t["status"], json!("failed"));
        assert!(t["error"].as_str().unwrap().contains("dimension mismatch"));
    }

    #[test]
    fn classification_bands_and_unclassified() {
        let class_of = |value_source: &str, bands: Vec<ClassBand>| {
            let lens = lens_with(
                vec![binding("ferin:eu/score@1", "score")],
                vec![TransformBinding::Classification {
                    id: "cl".into(),
                    source: value_source.into(),
                    bands,
                }],
            );
            let view = render(&rich_passport(), &lens);
            (
                view["transformed"][0]["output"].clone(),
                view["transformed"][0]["status"].clone(),
            )
        };
        let eu_bands = |min: &str| ClassBand {
            label: "pass".into(),
            min: min.parse().unwrap(),
        };
        // 8.1 >= 8.0 -> pass.
        assert_eq!(class_of("score", vec![eu_bands("8.0")]).0, json!("pass"));
        // 3.9 < 4.0 -> unclassified (explicit, never silent).
        assert_eq!(
            class_of("low-grade", vec![eu_bands("4.0")]).0,
            json!("unclassified")
        );
        // The highest matching band wins regardless of declaration order.
        let bands = vec![eu_bands("6.0"), eu_bands("8.0")];
        assert_eq!(class_of("score", bands.clone()).0, json!("pass"));
    }

    #[test]
    fn classification_of_non_numeric_fact_fails() {
        let lens = lens_with(
            vec![binding("ferin:eu/score@1", "score")],
            vec![TransformBinding::Classification {
                id: "cl".into(),
                source: "weak".into(),
                bands: vec![ClassBand {
                    label: "x".into(),
                    min: "1".parse().unwrap(),
                }],
            }],
        );
        let view = render(&rich_passport(), &lens);
        assert_eq!(view["transformed"][0]["status"], json!("failed"));
    }

    #[test]
    fn transform_with_absent_source_fails_and_states_the_instant() {
        let lens = lens_with(
            vec![binding("ferin:eu/score@1", "score")],
            vec![TransformBinding::Classification {
                id: "cl".into(),
                source: "ghost".into(),
                bands: vec![ClassBand {
                    label: "x".into(),
                    min: "0".parse().unwrap(),
                }],
            }],
        );
        let view = render(&rich_passport(), &lens);
        let t = &view["transformed"][0];
        assert_eq!(t["status"], json!("failed"));
        let error = t["error"].as_str().unwrap();
        assert!(
            error.contains("ghost") && error.contains("absent as-of"),
            "{error}"
        );
    }

    #[test]
    fn unresolvable_unit_items_are_reported_not_invented() {
        let lens = lens_with(
            vec![binding("ferin:eu/score@1", "score")],
            vec![TransformBinding::UnitConversion {
                id: "mj".into(),
                source: "capacity-kwh".into(),
                from_unit: "kWh".into(),
                to_unit: "MJ".into(),
                from_item: Some("unit-kwh".into()),
                to_item: None,
            }],
        );
        let view = render(&rich_passport(), &lens);
        let units = &view["transformed"][0]["units"];
        assert_eq!(units["kWh"]["uom_registered"], json!(false));
        assert_eq!(units["kWh"]["item"], json!("unit-kwh"));
        // The conversion is still exact (local seed).
        assert_eq!(view["transformed"][0]["output"]["amount"], json!("18"));
    }

    #[test]
    fn declared_unit_travels_with_selected_elements() {
        let mut b = binding("ferin:eu/cap@1", "capacity-kwh");
        b.declared_unit = Some("kWh".into());
        let lens = lens_with(vec![b], vec![]);
        let view = render(&rich_passport(), &lens);
        assert_eq!(view["selected"][0]["declared_unit"], json!("kWh"));
    }

    #[test]
    fn passport_block_carries_status_and_validity() {
        let lens = lens_with(vec![binding("ferin:eu/score@1", "score")], vec![]);
        let view = render(&rich_passport(), &lens);
        assert_eq!(view["passport"]["capability"], json!("passive-auth"));
        assert_eq!(view["passport"]["status"], json!("issued"));
        assert_eq!(view["passport"]["events"], json!(2));
        assert_eq!(view["passport"]["validity"]["contains_as_of"], json!(true));
        assert!(view["passport"]["log_head"].as_str().unwrap().len() >= 16);
        assert_eq!(view["as_of"], json!(at().to_string()));
        assert_eq!(view["profile"]["source"], json!("registry"));
    }

    #[test]
    fn fact_values_render_as_plain_json() {
        let mut events = vec![event(
            0,
            EventPayload::Correction {
                field: "flag".into(),
                prior_value: String::new(),
                new_value: "true".into(),
                reason: "test".into(),
            },
            TrustMarker::Attested,
        )];
        events.push(event(
            1,
            EventPayload::Correction {
                field: "list".into(),
                prior_value: String::new(),
                new_value: "a,b".into(),
                reason: "test".into(),
            },
            TrustMarker::Attested,
        ));
        let passport = passport_with(CapabilityClass::Silent, events);
        let lens = lens_with(
            vec![
                binding("ferin:eu/flag@1", "flag"),
                binding("ferin:eu/list@1", "list"),
            ],
            vec![],
        );
        let view = render(&passport, &lens);
        let selected = view["selected"].as_array().unwrap();
        assert_eq!(selected[0]["value"], json!(true));
        assert_eq!(selected[0]["kind"], json!("bool"));
        assert_eq!(selected[1]["value"], json!("a,b"));
    }

    // --- aggregation (TODO.impl 66) -------------------------------------

    /// The pack roll-up scenario: the fixture pack system over its
    /// three children, rendered through the fixture lens.
    fn pack_view() -> Value {
        let children = ChildDocuments::of(crate::fixtures::pack_children());
        project(
            &crate::fixtures::pack_system(),
            &crate::fixtures::pack_lens(),
            at(),
            "customs",
            &BTreeMap::new(),
            &ProfileSource::registry(),
            &PackageSet::empty(),
            &MappingSet::empty(),
            &children,
            &RollupSealer::off(),
        )
        .unwrap()
    }

    fn pack_transform<'a>(view: &'a Value, id: &str) -> &'a Value {
        view["transformed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"].as_str() == Some(id))
            .unwrap_or(&Value::Null)
    }

    #[test]
    fn aggregation_sum_over_three_children_with_method_citation() {
        let view = pack_view();
        let rollup = pack_transform(&view, "carbon-rollup");
        assert_eq!(rollup["kind"], json!("aggregation"));
        assert_eq!(rollup["operation"], json!("sum"));
        assert_eq!(rollup["method_citation"], json!("ISO 14067:2018"));
        assert_eq!(rollup["status"], json!("computed"));
        // 31.5 + 33.0 + 25.5 = 90 kgCO2e exactly.
        assert_eq!(rollup["output"], json!({"amount": "90", "unit": "kgCO2e"}));
        assert_eq!(rollup["children_required"], json!(3));
        assert_eq!(rollup["children_provided"], json!(3));
        // The committed input set's root hash travels with the output.
        assert_eq!(rollup["input_set_root"].as_str().unwrap().len(), 64);
        // Every input states its passport, value, trust and log head.
        let inputs = rollup["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs[0]["value"], json!("31.5"));
        assert_eq!(inputs[0]["trust"], json!("attested"));
        assert!(inputs[0]["log_head"].as_str().unwrap().len() >= 16);
        // The roll-up inherits the weakest input trust.
        assert_eq!(rollup["trust"], json!("attested"));
    }

    #[test]
    fn aggregation_weighted_average_is_exact() {
        let view = pack_view();
        let average = pack_transform(&view, "soh-weighted-average");
        assert_eq!(average["operation"], json!("weighted-average"));
        assert_eq!(average["method_citation"], json!("IEC 62660-1:2018"));
        // (91.2*12.5 + 88.4*15.5 + 86.9*12.0) / (12.5+15.5+12.0)
        // = 3553 / 40 = 88.825 exactly.
        assert_eq!(average["output"], json!({"amount": "88.825", "unit": "%"}));
        assert_eq!(
            average["weight_element"],
            json!("ferin:eu/pack.mass-kg@1.0.0")
        );
        assert_eq!(average["status"], json!("computed"));
    }

    #[test]
    fn aggregation_count_counts_the_providing_children() {
        let lens = lens_with(
            vec![binding("ferin:eu/score@1", "score")],
            vec![TransformBinding::Aggregation {
                id: "count".into(),
                operation: AggregationOperation::Count,
                input_element: "ferin:eu/score@1".into(),
                weight_element: None,
                method_citation: "ISO 14067:2018".into(),
            }],
        );
        // Build a subject over two children providing `score`, and one
        // that does not: the count is 2, the missing child a gap.
        let mut children: Vec<Passport> = Vec::new();
        for (i, provides) in [(0, true), (1, true), (2, false)] {
            let mut child = passport_with(
                CapabilityClass::PassiveAuth,
                vec![event(
                    0,
                    EventPayload::MilestoneRecord {
                        counters: if provides {
                            [("score".to_string(), "1".parse().unwrap())]
                                .into_iter()
                                .collect()
                        } else {
                            BTreeMap::new()
                        },
                    },
                    TrustMarker::Attested,
                )],
            );
            child.passport_id = PassportId::new(&format!("urn:unidpp:passport:child-{i}")).unwrap();
            children.push(child);
        }
        let mut subject = rich_passport();
        subject.passport_id = PassportId::new("urn:unidpp:passport:parent").unwrap();
        let inputs: Vec<unidpp_transform::InputReference> = children
            .iter()
            .map(|c| unidpp_transform::InputReference {
                input: c.passport_id.clone(),
                quantity: unidpp_transform::Quantity::new(
                    Decimal::one(),
                    unidpp_transform::quantity::Unit::new("kg", "urn:iso:std:iso:80000-4").unwrap(),
                ),
                as_of_state_hash: c.log.state_hash_at(at()).expect("child state hash exists"),
            })
            .collect();
        subject.log = {
            let mut log = EventLog::new(subject.passport_id.clone());
            log.append(
                TypedEvent::new(
                    0,
                    Timestamp::from_secs(1_600_000_000),
                    "issuing authority",
                    "urn:unidpp:actor:test",
                    unidpp_event::EventType::Issuance,
                    EventPayload::Issuance {
                        derived: true,
                        inputs,
                    },
                    TrustMarker::Attested,
                )
                .unwrap(),
                None,
                None,
            )
            .unwrap();
            log
        };
        let view = project(
            &subject,
            &lens,
            at(),
            "customs",
            &BTreeMap::new(),
            &ProfileSource::registry(),
            &PackageSet::empty(),
            &MappingSet::empty(),
            &ChildDocuments::of(children),
            &RollupSealer::off(),
        )
        .unwrap();
        let count = &view["transformed"][0];
        assert_eq!(count["status"], json!("missing-children"));
        assert_eq!(count["output"]["amount"], json!("2"));
        let missing = count["missing_children"].as_array().unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0]["passport"], json!("urn:unidpp:passport:child-2"));
        assert_eq!(missing[0]["reason"], json!("absent-as-of"));
    }

    #[test]
    fn aggregation_missing_child_is_a_coverage_gap_not_an_error() {
        // Drop one child document: the roll-up computes over the two
        // provided children and reports the third as a gap — the
        // method citation and committed set root still travel.
        let all = crate::fixtures::pack_children();
        let two: Vec<Passport> = all.into_iter().take(2).collect();
        let children = ChildDocuments::of(two);
        let view = project(
            &crate::fixtures::pack_system(),
            &crate::fixtures::pack_lens(),
            at(),
            "customs",
            &BTreeMap::new(),
            &ProfileSource::registry(),
            &PackageSet::empty(),
            &MappingSet::empty(),
            &children,
            &RollupSealer::off(),
        )
        .unwrap();
        let rollup = pack_transform(&view, "carbon-rollup");
        assert_eq!(rollup["status"], json!("missing-children"));
        // 31.5 + 33.0 over the two provided children.
        assert_eq!(rollup["output"]["amount"], json!("64.5"));
        let missing = rollup["missing_children"].as_array().unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(
            missing[0]["passport"],
            json!(crate::fixtures::PACK_CHILD_IDS[2])
        );
        assert_eq!(missing[0]["reason"], json!("document-unavailable"));
        assert_eq!(rollup["method_citation"], json!("ISO 14067:2018"));
    }

    #[test]
    fn aggregation_without_a_traversal_set_fails_visibly() {
        let lens = lens_with(
            vec![binding("ferin:eu/score@1", "score")],
            vec![TransformBinding::Aggregation {
                id: "rollup".into(),
                operation: AggregationOperation::Sum,
                input_element: "ferin:eu/score@1".into(),
                weight_element: None,
                method_citation: "ISO 14067:2018".into(),
            }],
        );
        // The rich passport's part replacement gives it one active
        // child edge... whose document does not resolve here; fold the
        // log to check the actual traversal set semantics instead: a
        // passport with no edges at all.
        let mut subject = rich_passport();
        subject.log = EventLog::new(subject.passport_id.clone());
        let view = project(
            &subject,
            &lens,
            at(),
            "customs",
            &BTreeMap::new(),
            &ProfileSource::registry(),
            &PackageSet::empty(),
            &MappingSet::empty(),
            &ChildDocuments::empty(),
            &RollupSealer::off(),
        )
        .unwrap();
        let rollup = &view["transformed"][0];
        assert_eq!(rollup["status"], json!("failed"));
        let error = rollup["error"].as_str().unwrap();
        assert!(
            error.contains("no active child edges") && error.contains("traversal set"),
            "{error}"
        );
    }

    #[test]
    fn aggregation_is_deterministic() {
        assert_eq!(pack_view(), pack_view());
    }

    // --- localization mapping (TODO.impl 67) ----------------------------

    #[test]
    fn localization_mapping_translates_the_code_value() {
        let mappings = crate::fixtures::fixture_mappings();
        let view = pack_view_with_mappings(&mappings);
        let stars = pack_transform(&view, "jp-star-display");
        assert_eq!(stars["kind"], json!("localization-mapping"));
        assert_eq!(stars["status"], json!("computed"));
        assert_eq!(stars["input"], json!("B"));
        assert_eq!(stars["output"], json!("★★★★"));
        assert_eq!(stars["trust"], json!("attested"));
        // The registered item's identity, version, schemes and
        // citation travel with the mapped value.
        let mapping = &stars["mapping"];
        assert_eq!(
            mapping["id"],
            json!(crate::fixtures::EU_CLASS_TO_JP_STAR_ID)
        );
        assert_eq!(mapping["version"], json!("1.0.0"));
        assert_eq!(mapping["source"], json!("fixtures"));
        assert_eq!(
            mapping["source_scheme"],
            json!("urn:eu:reg:2017:1369#annex-ii-class")
        );
        assert_eq!(mapping["target_scheme"], json!("urn:jp:meti:star-rating"));
        assert_eq!(mapping["entries"], json!(5));
        assert!(mapping["citation"].as_str().unwrap().contains("2017/1369"));
    }

    #[test]
    fn localization_mapping_of_an_unmapped_value_is_explicit() {
        // The subject's class is changed to one outside the registered
        // table: the output is the explicit `unmapped`, never a silent
        // pass of the source value.
        let mut system = crate::fixtures::pack_system();
        let mut log = system.log.clone();
        log.append(
            TypedEvent::new(
                system.log.len() as u64,
                at(),
                "economic operator",
                "urn:unidpp:actor:oem-batteriewerke",
                unidpp_event::EventType::Correction,
                EventPayload::Correction {
                    field: crate::fixtures::facts::ENERGY_LABEL.to_string(),
                    prior_value: "B".into(),
                    new_value: "G".into(),
                    reason: "re-graded to the bottom class".into(),
                },
                TrustMarker::Attested,
            )
            .unwrap(),
            None,
            None,
        )
        .unwrap();
        system.log = log;
        let mappings = crate::fixtures::fixture_mappings();
        let view = project(
            &system,
            &crate::fixtures::pack_lens(),
            at(),
            "customs",
            &BTreeMap::new(),
            &ProfileSource::registry(),
            &PackageSet::empty(),
            &mappings,
            &ChildDocuments::of(crate::fixtures::pack_children()),
            &RollupSealer::off(),
        )
        .unwrap();
        let stars = pack_transform(&view, "jp-star-display");
        assert_eq!(stars["status"], json!("unmapped"));
        assert_eq!(stars["output"], json!("unmapped"));
        assert_eq!(stars["input"], json!("G"));
        assert!(stars["detail"].as_str().unwrap().contains("`G`"));
    }

    #[test]
    fn localization_mapping_round_trips_through_the_reverse_item() {
        // EU B -> JP four stars (forward item), then the four-star
        // value back to EU B through the reverse item: the projector
        // evaluates both registered correspondences.
        let mappings = crate::fixtures::fixture_mappings();
        let view = pack_view_with_mappings(&mappings);
        let stars = pack_transform(&view, "jp-star-display")["output"]
            .as_str()
            .unwrap()
            .to_string();
        let mut lens = crate::fixtures::pack_lens();
        lens.transforms = vec![TransformBinding::LocalizationMapping {
            id: "reverse".into(),
            source: crate::fixtures::facts::ENERGY_LABEL.into(),
            mapping_ref: crate::fixtures::JP_STAR_TO_EU_CLASS_ID.into(),
        }];
        // Re-key the lens to the star value: a corrected class fact
        // holding the star string.
        let mut system = crate::fixtures::pack_system();
        let mut log = system.log.clone();
        log.append(
            TypedEvent::new(
                system.log.len() as u64,
                at(),
                "economic operator",
                "urn:unidpp:actor:oem-batteriewerke",
                unidpp_event::EventType::Correction,
                EventPayload::Correction {
                    field: crate::fixtures::facts::ENERGY_LABEL.to_string(),
                    prior_value: "B".into(),
                    new_value: stars.clone(),
                    reason: "the JP star display of the system class".into(),
                },
                TrustMarker::Attested,
            )
            .unwrap(),
            None,
            None,
        )
        .unwrap();
        system.log = log;
        let view = project(
            &system,
            &lens,
            at(),
            "customs",
            &BTreeMap::new(),
            &ProfileSource::registry(),
            &PackageSet::empty(),
            &mappings,
            &ChildDocuments::empty(),
            &RollupSealer::off(),
        )
        .unwrap();
        let back = &view["transformed"][0];
        assert_eq!(back["status"], json!("computed"));
        assert_eq!(back["input"], json!(stars));
        assert_eq!(back["output"], json!("B"));

        // The acceptance round trip itself: EU A -> JP five stars
        // through the forward item, back to A through the reverse.
        let forward = mappings
            .get(crate::fixtures::EU_CLASS_TO_JP_STAR_ID)
            .unwrap()
            .0;
        let reverse = mappings
            .get(crate::fixtures::JP_STAR_TO_EU_CLASS_ID)
            .unwrap()
            .0;
        let five = forward.lookup("A").unwrap().target_value.clone();
        assert_eq!(five, "★★★★★");
        assert_eq!(reverse.lookup(&five).unwrap().target_value, "A");
    }

    #[test]
    fn localization_mapping_without_the_item_or_fact_fails_honestly() {
        // The projector holds no mapping: the binding says so.
        let view = pack_view_with_mappings(&MappingSet::empty());
        let stars = pack_transform(&view, "jp-star-display");
        assert_eq!(stars["status"], json!("failed"));
        assert!(stars["error"].as_str().unwrap().contains("not available"));

        // Before the grading correction, the fact does not exist
        // as-of: absent source, stated.
        let early = Timestamp::from_secs(1_760_000_000); // 2025-10-09ish
        let mappings = crate::fixtures::fixture_mappings();
        let view = project(
            &crate::fixtures::pack_system(),
            &crate::fixtures::pack_lens(),
            early,
            "customs",
            &BTreeMap::new(),
            &ProfileSource::registry(),
            &PackageSet::empty(),
            &mappings,
            &ChildDocuments::empty(),
            &RollupSealer::off(),
        )
        .unwrap();
        let stars = pack_transform(&view, "jp-star-display");
        assert_eq!(stars["status"], json!("failed"));
        assert!(stars["error"].as_str().unwrap().contains("absent as-of"));
    }

    /// The pack view with an explicit mapping set (default: fixtures).
    fn pack_view_with_mappings(mappings: &MappingSet) -> Value {
        project(
            &crate::fixtures::pack_system(),
            &crate::fixtures::pack_lens(),
            at(),
            "customs",
            &BTreeMap::new(),
            &ProfileSource::registry(),
            &PackageSet::empty(),
            mappings,
            &ChildDocuments::of(crate::fixtures::pack_children()),
            &RollupSealer::off(),
        )
        .unwrap()
    }

    #[test]
    fn invalid_lens_is_refused() {
        let mut lens = lens_with(vec![binding("ferin:eu/score@1", "score")], vec![]);
        lens.bindings.clear();
        assert!(matches!(
            project(
                &rich_passport(),
                &lens,
                at(),
                "customs",
                &BTreeMap::new(),
                &ProfileSource::registry(),
                &PackageSet::empty(),
                &MappingSet::empty(),
                &ChildDocuments::empty(),
                &RollupSealer::off(),
            ),
            Err(ViewError::Invalid(_))
        ));
    }
}
