//! The aggregation transform class (TODO.impl 66 / T-18): cross-child
//! roll-ups, methodology-bound.
//!
//! PLAN.md transform taxonomy (3): "aggregation — cross-child roll-ups,
//! methodology-bound (cites the method standard, e.g. ISO 14067; never
//! invents one)". A lens manifest's [`Aggregation` binding]
//! (`crate::lens::TransformBinding::Aggregation`) names an *input
//! element*; the projector selects that element's value from every
//! passport in the subject's **active traversal set** (the child edges
//! its own log records — derived issuance inputs, combine inputs,
//! part/consumable replacements minus removals and consumed parts,
//! replayed as-of the view instant), applies the declared operation
//! exactly (never floats), and emits the aggregated output together
//! with:
//!
//! - `method_citation` — the method standard the roll-up follows
//!   (mandatory, validated non-empty at manifest parse);
//! - `input_set_root` — the deterministic root hash of the committed
//!   child set (sha-256 over the children's ids and log heads in
//!   passport-id order), so a roll-up names exactly the input set it
//!   aggregated;
//! - per-child inputs with their values, units, trust markers and log
//!   heads — and per-child *gaps* when a child is missing the element:
//!   a coverage gap, never an error.
//!
//! Division (weighted average) is exact-or-refused: the decimal domain
//! holds no repeating fractions, and the projector never rounds
//! silently — an inexact quotient is reported as a failure with its
//! reason, not a quietly truncated value.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};
use unidpp_cli::passport::Passport;
use unidpp_model::{digest::sha256, Decimal, Timestamp};

use crate::lens::DataPointBinding;
use crate::twin::{self, SourcedFact};

/// The roll-up operations a binding may declare (wire: kebab-case).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AggregationOperation {
    /// Σ values across the children providing the element.
    Sum,
    /// Σ(value × weight) / Σ(weight) — exact, or refused.
    WeightedAverage,
    /// The number of children providing the element.
    Count,
}

impl std::fmt::Display for AggregationOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let wire = match self {
            AggregationOperation::Sum => "sum",
            AggregationOperation::WeightedAverage => "weighted-average",
            AggregationOperation::Count => "count",
        };
        f.write_str(wire)
    }
}

/// The child passport documents available to a projection, keyed by
/// passport id (the traversal set's resolvable members). The projector
/// resolves documents; the engine reports ids it could not resolve as
/// per-child gaps.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChildDocuments {
    /// Child documents by passport id.
    pub documents: BTreeMap<String, Passport>,
}

impl ChildDocuments {
    /// An empty set (no children resolvable — lenses without
    /// aggregation bindings pass this).
    pub fn empty() -> ChildDocuments {
        ChildDocuments::default()
    }

    /// Build from documents (keyed by their own passport ids).
    pub fn of(documents: impl IntoIterator<Item = Passport>) -> ChildDocuments {
        ChildDocuments {
            documents: documents
                .into_iter()
                .map(|p| (p.passport_id.as_str().to_string(), p))
                .collect(),
        }
    }

    /// Look up one child document.
    pub fn get(&self, id: &str) -> Option<&Passport> {
        self.documents.get(id)
    }

    /// The deterministic root hash of a committed child set: sha-256
    /// over each active child (passport-id order) — id, then the
    /// child's log head as-of the instant (or the marker `∅` when the
    /// document is not resolvable, so the root still commits to the
    /// *set*, not to what happened to be loadable).
    pub fn root_hash(&self, active_ids: &[String], at: Timestamp) -> String {
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(active_ids.len() * 2);
        for id in active_ids {
            parts.push(id.as_bytes().to_vec());
            let head = self
                .documents
                .get(id)
                .and_then(|p| p.log.state_hash_at(at))
                .map(|h| h.hex())
                .unwrap_or_else(|| "\u{2205}".to_string());
            parts.push(head.into_bytes());
        }
        let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        sha256(&slices).hex()
    }
}

/// The per-child outcome of fetching the input element's selected
/// value through the profile's own binding gates.
struct ChildValue {
    value: Decimal,
    fact: SourcedFact,
}

/// Why a child contributed no value to the roll-up (a coverage gap,
/// never an error).
struct ChildGap {
    passport: String,
    reason: &'static str,
    detail: String,
}

impl ChildGap {
    /// The wire form of one gap (the `missing_children` entries).
    fn json(&self) -> Value {
        json!({
            "passport": self.passport,
            "reason": self.reason,
            "detail": self.detail,
        })
    }
}

/// Exact decimal division: `n / d`, or `None` when the quotient does
/// not terminate within the decimal domain (the weighted average then
/// fails visibly instead of rounding silently). Mirrors the core
/// decimal crate's exact-ratio doctrine.
fn div_exact(n: &Decimal, d: &Decimal) -> Option<Decimal> {
    if d.is_zero() {
        return None;
    }
    for k in 0i32..=18 {
        let factor = 10i128.checked_pow(k as u32)?;
        let Some(scaled) = n.mant.checked_mul(factor) else {
            break;
        };
        if scaled % d.mant == 0 {
            return Decimal::new(scaled / d.mant, n.exp - d.exp - k).ok();
        }
    }
    None
}

/// Select one element's value from one child through the binding's
/// gates — the *same* selection model the subject view applies
/// (`project::select`); a blocked child becomes a per-child gap with
/// the view's own reason taxonomy, a non-numeric fact a type gap.
fn child_value(
    child: &Passport,
    state: &twin::TwinState,
    binding: &DataPointBinding,
) -> Result<ChildValue, ChildGap> {
    let gap = |reason: &'static str, detail: String| ChildGap {
        passport: child.passport_id.as_str().to_string(),
        reason,
        detail,
    };
    match crate::project::select(child, state, binding) {
        crate::project::Selection::Blocked(reason) => Err(gap(
            match reason {
                crate::project::MissingReason::AbsentAsOf => "absent-as-of",
                crate::project::MissingReason::BelowTrustFloor { .. } => "below-trust-floor",
                crate::project::MissingReason::CapabilityGate { .. } => "capability-gate",
            },
            format!(
                "child `{}`: {}",
                child.passport_id.as_str(),
                reason.detail()
            ),
        )),
        crate::project::Selection::Found(fact) => match &fact.value {
            unidpp_model::FactValue::Num(v) => Ok(ChildValue {
                value: *v,
                fact: fact.clone(),
            }),
            other => Err(gap(
                "not-numeric",
                format!(
                    "child `{}`: fact `{}` is a {} fact; the roll-up needs a \
                     numeric measurand",
                    child.passport_id.as_str(),
                    binding.source,
                    other.type_name()
                ),
            )),
        },
    }
}

/// The weighted average over the contributed children:
/// Σ(value × weight) / Σ(weight), exact or `None` (see [`div_exact`]
/// for the refusal doctrine).
fn weighted_average(values: &[(Decimal, Option<Decimal>, SourcedFact)]) -> Option<Decimal> {
    let mut numerator = Decimal::zero();
    let mut denominator = Decimal::zero();
    for (v, w, _) in values {
        let weight = w.expect("weighted children carry weights");
        numerator = numerator.add(&v.mul(&weight).ok()?).ok()?;
        denominator = denominator.add(&weight).ok()?;
    }
    div_exact(&numerator, &denominator)
}

/// Evaluate one aggregation binding over the traversal set and render
/// its transform entry. `active_ids` is the subject's active child set
/// (sorted); `children` the resolvable documents; `at` the instant.
#[allow(clippy::too_many_arguments)]
pub fn aggregation_json(
    id: &str,
    operation: AggregationOperation,
    input_binding: &DataPointBinding,
    weight_binding: Option<&DataPointBinding>,
    method_citation: &str,
    subject_state: &twin::TwinState,
    children: &ChildDocuments,
    at: Timestamp,
) -> Value {
    let active: Vec<String> = subject_state.children.iter().cloned().collect();
    let mut m = Map::new();
    m.insert("id".to_string(), json!(id));
    m.insert("kind".to_string(), json!("aggregation"));
    m.insert("operation".to_string(), json!(operation.to_string()));
    m.insert("input_element".to_string(), json!(input_binding.element));
    if let Some(w) = weight_binding {
        m.insert("weight_element".to_string(), json!(w.element));
    }
    m.insert("method_citation".to_string(), json!(method_citation));
    m.insert("children_required".to_string(), json!(active.len()));
    m.insert(
        "input_set_root".to_string(),
        json!(children.root_hash(&active, at)),
    );

    if active.is_empty() {
        m.insert("status".to_string(), json!("failed"));
        m.insert(
            "error".to_string(),
            json!(format!(
                "the subject carries no active child edges as-of {at} — \
                 there is no traversal set to aggregate"
            )),
        );
        return Value::Object(m);
    }

    let mut inputs: Vec<Value> = Vec::with_capacity(active.len());
    let mut gaps: Vec<ChildGap> = Vec::new();
    let mut values: Vec<(Decimal, Option<Decimal>, SourcedFact)> = Vec::new();
    for child_id in &active {
        let Some(child) = children.get(child_id) else {
            gaps.push(ChildGap {
                passport: child_id.clone(),
                reason: "document-unavailable",
                detail: "the child document is not resolvable from this \
                         projector's passport store"
                    .to_string(),
            });
            continue;
        };
        let state = twin::fold(child, at);
        match child_value(child, &state, input_binding) {
            Err(gap) => gaps.push(gap),
            Ok(found) => {
                let weight = match weight_binding {
                    None => None,
                    Some(wb) => match child_value(child, &state, wb) {
                        Ok(w) if !w.value.is_negative() && !w.value.is_zero() => Some(w.value),
                        Ok(_) => {
                            gaps.push(ChildGap {
                                passport: child_id.clone(),
                                reason: "weight-not-positive",
                                detail: format!(
                                    "weight fact `{}` is not a positive \
                                     quantity",
                                    wb.source
                                ),
                            });
                            continue;
                        }
                        Err(gap) => {
                            gaps.push(ChildGap {
                                passport: child_id.clone(),
                                reason: "weight-missing",
                                detail: gap.detail,
                            });
                            continue;
                        }
                    },
                };
                let head = child
                    .log
                    .state_hash_at(at)
                    .map(|h| h.hex())
                    .unwrap_or_default();
                inputs.push(json!({
                    "passport": child_id,
                    "value": found.value.to_string(),
                    "trust": found.fact.origin.trust.to_string(),
                    "sourced_seq": found.fact.origin.seq,
                    "log_head": head,
                }));
                values.push((found.value, weight, found.fact));
            }
        }
    }
    m.insert("inputs".to_string(), Value::Array(inputs));

    // The roll-up is never more trustworthy than its weakest input.
    let weakest = values
        .iter()
        .map(|(_, _, f)| f.origin.trust)
        .min_by_key(|t| t.grade());
    if let Some(t) = weakest {
        m.insert("trust".to_string(), json!(t.to_string()));
    }

    if values.is_empty() {
        // Every child is a gap: coverage, not error — the citation and
        // the committed set still travel with the entry.
        m.insert("status".to_string(), json!("missing-children"));
        m.insert(
            "missing_children".to_string(),
            Value::Array(gaps.iter().map(ChildGap::json).collect()),
        );
        return Value::Object(m);
    }

    let unit = input_binding.declared_unit.clone();
    let computed: Result<Decimal, String> = match operation {
        AggregationOperation::Sum => values
            .iter()
            .map(|(v, _, _)| *v)
            .try_fold(Decimal::zero(), |acc, v| acc.add(&v))
            .map_err(|e| e.to_string()),
        AggregationOperation::Count => Ok(Decimal::from_i64(values.len() as i64)),
        AggregationOperation::WeightedAverage => match weighted_average(&values) {
            Some(amount) => Ok(amount),
            None => Err(format!(
                "the weighted average over {} children is not exactly \
                 representable in the decimal domain (weight it or restate \
                 the inputs) — the projector never rounds silently",
                values.len()
            )),
        },
    };

    match computed {
        Ok(amount) => {
            let mut output = Map::new();
            output.insert("amount".to_string(), json!(amount.to_string()));
            if let Some(u) = &unit {
                output.insert("unit".to_string(), json!(u));
            }
            m.insert("output".to_string(), Value::Object(output));
            m.insert("children_provided".to_string(), json!(values.len()));
            if gaps.is_empty() {
                m.insert("status".to_string(), json!("computed"));
            } else {
                m.insert("status".to_string(), json!("missing-children"));
                m.insert(
                    "missing_children".to_string(),
                    Value::Array(gaps.iter().map(ChildGap::json).collect()),
                );
            }
        }
        Err(why) => {
            m.insert("status".to_string(), json!("failed"));
            m.insert("error".to_string(), json!(why));
        }
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn division_is_exact_or_refused() {
        let d = |s: &str| s.parse::<Decimal>().unwrap();
        // Exact quotients.
        assert_eq!(
            div_exact(&d("289.5"), &d("10")).unwrap().to_string(),
            "28.95"
        );
        assert_eq!(div_exact(&d("90"), &d("3")).unwrap().to_string(), "30");
        assert_eq!(div_exact(&d("-6"), &d("3")).unwrap().to_string(), "-2");
        assert_eq!(div_exact(&d("1"), &d("8")).unwrap().to_string(), "0.125");
        // 1/3 does not terminate in the decimal domain: refused, never
        // silently rounded.
        assert!(div_exact(&d("1"), &d("3")).is_none());
        assert!(div_exact(&d("96.4"), &d("0")).is_none());
    }

    #[test]
    fn root_hash_is_deterministic_and_order_stable() {
        let children = ChildDocuments::of(vec![
            crate::fixtures::pack_child(2),
            crate::fixtures::pack_child(0),
            crate::fixtures::pack_child(1),
        ]);
        let at = crate::fixtures::demo_as_of();
        let ids: Vec<String> = children.documents.keys().cloned().collect();
        let first = children.root_hash(&ids, at);
        let second = children.root_hash(&ids, at);
        assert_eq!(first, second);
        assert_eq!(first.len(), 64, "sha-256 hex");
        // A different set hashes differently.
        let truncated = &ids[..2];
        assert_ne!(children.root_hash(truncated, at), first);
        // An unresolvable child commits the set with the marker, and
        // differs from a set where it is resolvable.
        let empty = ChildDocuments::empty();
        assert_ne!(empty.root_hash(&ids, at), first);
    }

    #[test]
    fn child_documents_key_by_their_own_ids() {
        let children = crate::fixtures::pack_children();
        let set = ChildDocuments::of(children.iter().cloned());
        for id in crate::fixtures::PACK_CHILD_IDS {
            assert!(set.get(id).is_some(), "{id} resolvable");
        }
        assert!(set.get("urn:unidpp:passport:none-such").is_none());
    }
}
