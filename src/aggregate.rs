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
//! - `input_set_root` — the canonical commitment to the child set:
//!   [`unidpp_transform::rollup::TraversalSet::root`] (the core's
//!   Merkle root — one definition of the concept, the transform
//!   crate's), over one member per active child: passport id,
//!   document version, log head as-of the instant. A child whose
//!   head is not resolvable is carried by a sentinel hash, so the
//!   root commits to the *set*, not to what happened to be loadable;
//! - `rollup` — the signed
//!   [`unidpp_transform::rollup::RollupAttestation`] over exactly
//!   that traversal set ([`RollupSealer`]): present only when the
//!   projector holds a key, never a placeholder, so deep-graph views
//!   are verifiably sealed;
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
use unidpp_model::{sha256, Decimal, Hash, PassportId, Timestamp};
use unidpp_signatif::rollup::sign_rollup;
use unidpp_signatif::sign::Suite;
use unidpp_signatif::{KeyPair, PublicKey, SignatifError};
use unidpp_transform::quantity::UnitRegistry;
use unidpp_transform::rollup::{RollupAttestation, TraversalMember, TraversalSet};
use unidpp_transform::TransformError;

use crate::lens::DataPointBinding;
use crate::twin::{self, SourcedFact};

/// The passport-document version a traversal member carries. The
/// projector's store serves `unidpp/passport@1` documents — one
/// document version — so every member is version 1.
const PASSPORT_DOCUMENT_VERSION: u64 = 1;

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

    /// The canonical traversal set over the active children (the
    /// core's [`TraversalSet`]: one member per active child, passport
    /// -id order, Merkle-committed by [`TraversalSet::root`]). Each
    /// member carries the child's passport id, the document version,
    /// and its log head as-of the instant; a child whose head is not
    /// resolvable is carried by [`unresolved_head`], so the root
    /// commits to the *set*, not to what happened to be loadable. A
    /// child id that is not a valid passport id is refused: the
    /// projector will not commit to a set it cannot even name.
    pub fn traversal_set(
        &self,
        active_ids: &[String],
        at: Timestamp,
    ) -> Result<TraversalSet, TransformError> {
        let members = active_ids
            .iter()
            .map(|id| {
                Ok(TraversalMember {
                    passport: PassportId::new(id)
                        .map_err(|e| TransformError::Provenance(format!("child id `{id}`: {e}")))?,
                    version: PASSPORT_DOCUMENT_VERSION,
                    state_hash: self
                        .documents
                        .get(id)
                        .and_then(|p| p.log.state_hash_at(at))
                        .unwrap_or_else(unresolved_head),
                    quantities: BTreeMap::new(),
                })
            })
            .collect::<Result<Vec<_>, TransformError>>()?;
        TraversalSet::new(members)
    }
}

/// The state hash carried for a child with no resolvable log head
/// (document missing from this projector's store, or a log with no
/// event at or before the instant): a domain-tagged digest that names
/// the absence — distinct from any real head, identical for every
/// such child (the passport id in the member's own leaf bytes keeps
/// members distinct).
fn unresolved_head() -> Hash {
    sha256(&[b"UNIDPP/PROJECTOR/UNRESOLVED-LOG-HEAD"])
}

/// The projector's roll-up sealing identity: a seeded signing key and
/// the attester id its attestations name. The projector is otherwise
/// keyless — a deployment that wants verifiably sealed roll-ups
/// configures one (`UNIDPP_PROJECTOR_ROLLUP_SEED` with
/// `UNIDPP_PROJECTOR_ROLLUP_ATTESTER`); [`RollupSealer::off`] is the
/// keyless default, and aggregation entries then carry no `rollup`
/// field at all.
pub struct RollupSealer {
    key: Option<(KeyPair, String)>,
}

impl std::fmt::Debug for RollupSealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never formats the key material (secrets are held, not
        // printed); the identity shape is what debugging needs.
        match &self.key {
            Some((_, attester)) => f
                .debug_struct("RollupSealer")
                .field("attester", attester)
                .finish_non_exhaustive(),
            None => f.write_str("RollupSealer(off)"),
        }
    }
}

impl RollupSealer {
    /// The keyless projector (no attestation is emitted).
    pub fn off() -> RollupSealer {
        RollupSealer { key: None }
    }

    /// Derive the sealing key from seed material (signatif's doctrine
    /// for operator-configured service identities: deterministic
    /// derivation, P-256 — the suite that maps onto the core carrier
    /// slot) and pin the attester id its attestations name.
    pub fn seeded(seed: &str, attester: &str) -> Result<RollupSealer, SignatifError> {
        let attester = attester.trim().to_string();
        if attester.is_empty() {
            return Err(SignatifError::Validation(
                "a roll-up sealer names its attester".to_string(),
            ));
        }
        Ok(RollupSealer {
            key: Some((
                KeyPair::seeded(Suite::EcdsaP256, seed.as_bytes())?,
                attester,
            )),
        })
    }

    /// Whether this projector seals roll-up attestations.
    pub fn seals(&self) -> bool {
        self.key.is_some()
    }

    /// The public anchor a verifier pins against this sealer's
    /// attestations (`None` for the keyless projector).
    pub fn public(&self) -> Option<&PublicKey> {
        self.key.as_ref().map(|(key, _)| key.public())
    }

    /// Build and sign the roll-up attestation over the committed set:
    /// subject the parent passport, method the binding's citation,
    /// attester this sealer's identity; the serialized shape is the
    /// transform crate's serde shape. `None` when keyless; a build or
    /// signing failure is reported by the `Err` (never swallowed,
    /// never a placeholder).
    fn seal(
        &self,
        subject: &PassportId,
        set: &TraversalSet,
        method_ref: &str,
        registry: &UnitRegistry,
    ) -> Option<Result<Value, String>> {
        let (key, attester) = self.key.as_ref()?;
        let sealed = || -> Result<Value, String> {
            let (mut attestation, _) =
                RollupAttestation::build(subject.clone(), set, method_ref, attester, registry)
                    .map_err(|e| e.to_string())?;
            sign_rollup(key, &mut attestation).map_err(|e| e.to_string())?;
            serde_json::to_value(&attestation).map_err(|e| e.to_string())
        };
        Some(sealed())
    }
}

/// Attach the signed roll-up attestation to an aggregation entry when
/// the projector holds a key (the field is absent otherwise; a
/// signing failure is stated in the entry, never swallowed).
fn seal_into(
    m: &mut Map<String, Value>,
    sealer: &RollupSealer,
    subject: &PassportId,
    set: &TraversalSet,
    method_citation: &str,
    unit_registry: &UnitRegistry,
) {
    match sealer.seal(subject, set, method_citation, unit_registry) {
        None => {}
        Some(Ok(attestation)) => {
            m.insert("rollup".to_string(), attestation);
        }
        Some(Err(why)) => {
            m.insert("rollup_error".to_string(), json!(why));
        }
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
/// its transform entry. The subject's active child set comes from
/// `subject_state`; `children` the resolvable documents; `subject` the
/// parent passport (the roll-up's subject when one is sealed);
/// `sealer` the projector's sealing identity ([`RollupSealer::off`]
/// when it holds no key); `at` the instant.
#[allow(clippy::too_many_arguments)]
pub fn aggregation_json(
    id: &str,
    operation: AggregationOperation,
    input_binding: &DataPointBinding,
    weight_binding: Option<&DataPointBinding>,
    method_citation: &str,
    subject: &PassportId,
    subject_state: &twin::TwinState,
    children: &ChildDocuments,
    unit_registry: &UnitRegistry,
    sealer: &RollupSealer,
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

    if active.is_empty() {
        m.insert("status".to_string(), json!("failed"));
        m.insert(
            "error".to_string(),
            json!(format!(
                "the subject carries no active child edges as-of {at} — \
                 there is no traversal set to aggregate"
            )),
        );
        // An empty set has no canonical root (the core refuses it) —
        // the entry states the failure instead of inventing one.
        return Value::Object(m);
    }

    // The committed input set — one canonical definition (the core's),
    // consumed by both the root the entry carries and the attestation
    // a keyed projector seals over it.
    let set = match children.traversal_set(&active, at) {
        Ok(set) => set,
        Err(why) => {
            m.insert("status".to_string(), json!("failed"));
            m.insert(
                "error".to_string(),
                json!(format!("the traversal set cannot be committed: {why}")),
            );
            return Value::Object(m);
        }
    };
    m.insert("input_set_root".to_string(), json!(set.root().hex()));

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
        seal_into(
            &mut m,
            sealer,
            subject,
            &set,
            method_citation,
            unit_registry,
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
    // The attestation commits to the traversal set (root, member
    // count) and the cited method — meaningful whatever the entry's
    // computation status, including partial roll-ups over gaps.
    seal_into(
        &mut m,
        sealer,
        subject,
        &set,
        method_citation,
        unit_registry,
    );
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
    fn traversal_set_commits_the_children_canonically() {
        let children = ChildDocuments::of(vec![
            crate::fixtures::pack_child(2),
            crate::fixtures::pack_child(0),
            crate::fixtures::pack_child(1),
        ]);
        let at = crate::fixtures::demo_as_of();
        let ids: Vec<String> = children.documents.keys().cloned().collect();
        let first = children.traversal_set(&ids, at).unwrap();
        let second = children.traversal_set(&ids, at).unwrap();
        assert_eq!(first.root().hex().len(), 64, "sha-256 hex");
        assert_eq!(first.root(), second.root(), "deterministic");
        // A different set hashes differently.
        let truncated = children.traversal_set(&ids[..2], at).unwrap();
        assert_ne!(truncated.root(), first.root());
        // An unresolvable child commits the set with the sentinel
        // head, and differs from a set where it is resolvable.
        let unresolved = ChildDocuments::empty().traversal_set(&ids, at).unwrap();
        assert_ne!(unresolved.root(), first.root());
        for member in unresolved.members() {
            assert_eq!(member.state_hash, unresolved_head());
        }
        // A child id that is not a valid passport id cannot be
        // committed: refused with its reason.
        let malformed = vec!["not a passport id".to_string()];
        assert!(children.traversal_set(&malformed, at).is_err());
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

    // --- the canonical commitment (TODO.impl 79) -----------------------

    use unidpp_signatif::rollup::check_rollup_signature;
    use unidpp_transform::rollup::{verify_rollup, RollupVerdict};

    /// The carbon roll-up binding of the fixture pack lens: its input
    /// element's data-point binding and its method citation.
    fn carbon_binding() -> (crate::lens::DataPointBinding, String) {
        let lens = crate::fixtures::pack_lens();
        let (element, citation) = lens
            .transforms
            .iter()
            .find_map(|t| match t {
                crate::lens::TransformBinding::Aggregation {
                    id,
                    input_element,
                    method_citation,
                    ..
                } if id == "carbon-rollup" => {
                    Some((input_element.clone(), method_citation.clone()))
                }
                _ => None,
            })
            .expect("the fixture lens carries the carbon roll-up");
        (lens.binding_for(&element).unwrap().clone(), citation)
    }

    /// The canonical traversal set over the fixture pack children,
    /// built straight from the core types (version 1, log heads
    /// as-of, no labelled quantities): the independent oracle the
    /// entry's `input_set_root` and the sealed attestation must both
    /// commit to.
    fn canonical_pack_set(at: Timestamp) -> TraversalSet {
        let members = crate::fixtures::pack_children()
            .iter()
            .map(|child| TraversalMember {
                passport: child.passport_id.clone(),
                version: 1,
                state_hash: child.log.state_hash_at(at).expect("pack heads as-of"),
                quantities: BTreeMap::new(),
            })
            .collect();
        TraversalSet::new(members).unwrap()
    }

    /// The carbon roll-up entry over the fixture pack corpus.
    fn carbon_entry(sealer: &RollupSealer) -> Value {
        let (binding, citation) = carbon_binding();
        let subject = crate::fixtures::pack_system();
        let at = crate::fixtures::demo_as_of();
        aggregation_json(
            "carbon-rollup",
            AggregationOperation::Sum,
            &binding,
            None,
            &citation,
            &subject.passport_id,
            &twin::fold(&subject, at),
            &ChildDocuments::of(crate::fixtures::pack_children()),
            &UnitRegistry::iso80000(),
            sealer,
            at,
        )
    }

    #[test]
    fn input_set_root_is_the_canonical_traversal_root() {
        let entry = carbon_entry(&RollupSealer::off());
        let set = canonical_pack_set(crate::fixtures::demo_as_of());
        assert_eq!(entry["status"], json!("computed"));
        assert_eq!(
            entry["input_set_root"].as_str().unwrap(),
            set.root().hex(),
            "one definition of the commitment: the core's"
        );
    }

    #[test]
    fn identical_aggregations_are_identical_bytes() {
        // Determinism without a sealer: the whole entry — root,
        // inputs, output — is byte-identical across runs. (A sealed
        // entry's roots are equally stable; its signatures differ by
        // their attested moments, by design.)
        assert_eq!(
            carbon_entry(&RollupSealer::off()),
            carbon_entry(&RollupSealer::off())
        );
    }

    #[test]
    fn keyless_aggregations_carry_no_rollup_field() {
        let entry = carbon_entry(&RollupSealer::off());
        assert!(entry.get("rollup").is_none());
        assert!(entry.get("rollup_error").is_none());
    }

    #[test]
    fn sealed_rollup_verifies_and_tampering_breaks_it() {
        let sealer = RollupSealer::seeded("projector-test", "urn:unidpp:eo:projector").unwrap();
        let entry = carbon_entry(&sealer);
        let set = canonical_pack_set(crate::fixtures::demo_as_of());
        let attestation: RollupAttestation =
            serde_json::from_value(entry["rollup"].clone()).unwrap();
        // The attestation is over exactly the committed set: the same
        // root the entry carries, subject the parent passport, method
        // the binding's citation.
        assert_eq!(attestation.traversal_set_root, set.root());
        assert_eq!(
            attestation.traversal_set_root.hex(),
            entry["input_set_root"].as_str().unwrap()
        );
        assert_eq!(
            attestation.subject,
            crate::fixtures::pack_system().passport_id
        );
        assert_eq!(attestation.method_ref, carbon_binding().1);
        assert_eq!(attestation.member_count, set.members().len());

        let registry = UnitRegistry::iso80000();
        let anchor = sealer.public().unwrap();
        let verdict = verify_rollup(&attestation, &set, &registry, |slot, body| {
            check_rollup_signature(slot, body, anchor)
        });
        assert_eq!(verdict, RollupVerdict::Verified);

        // Tampering the attestation breaks the signature: the seal
        // covers the canonical body, method citation included.
        let mut forged = attestation.clone();
        forged.method_ref = "urn:unidpp:transform:someone-elses-method".to_string();
        let verdict = verify_rollup(&forged, &set, &registry, |slot, body| {
            check_rollup_signature(slot, body, anchor)
        });
        assert!(matches!(verdict, RollupVerdict::SignatureRejected(_)));

        // Tampering the underlying set breaks the root commitment:
        // the attestation no longer covers the set it is presented
        // against, before any signature is even checked.
        let mut members: Vec<TraversalMember> = set.members().to_vec();
        members[1].state_hash = sha256(&[b"tampered"]);
        let tampered_set = TraversalSet::new(members).unwrap();
        let verdict = verify_rollup(&attestation, &tampered_set, &registry, |slot, body| {
            check_rollup_signature(slot, body, anchor)
        });
        assert_eq!(verdict, RollupVerdict::RootMismatch);
    }
}
