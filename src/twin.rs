//! The twin-state fold: replay a passport's append-only event log
//! as-of an instant into testimonial facts, each carrying the origin
//! of the event that last wrote it.
//!
//! The twin state is *derived*, never stored: the passport document
//! (`unidpp/passport@1`, supplied by `unidpp-cli`) is the authority,
//! and this fold is the deterministic projection of its log. The
//! event-to-fact mapping is:
//!
//! | event | fact effect |
//! |---|---|
//! | `MilestoneRecord` | every counter `k` becomes fact `k` (numeric) |
//! | `Correction` | fact `field` := typed `new_value` (decimal, then bool, then string) |
//! | `SoftwareUpdate` | fact `software.<slot>` := version string |
//! | `CustodyTransfer` | fact `custody.custodian` := `to`; custodian tracked |
//! | `RefurbishRemanufacture` | fact `subject.condition-grade` := grade |
//! | `ProductModify` | fact `subject.type` := derived type (when one spawns) |
//! | `StatusChange` | status tracked |
//!
//! Later events overwrite earlier same-path facts (append-only log,
//! last write wins as-of); the origin (sequence, time, actor role and
//! id, trust marker) travels with the value so the projection can
//! state *who measured what and under which trust marker*.

use std::collections::BTreeMap;

use unidpp_cli::passport::Passport;
use unidpp_event::{EventPayload, Status};
use unidpp_model::{FactValue, Timestamp, TrustMarker, TwinFacts};

/// Where a fact came from: the event that last wrote it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FactOrigin {
    /// Sequence number of the sourcing event.
    pub seq: u64,
    /// When the sourcing event occurred.
    pub occurred_at: Timestamp,
    /// Role the acting party declared.
    pub actor_role: String,
    /// Identifier of the acting party.
    pub actor_id: String,
    /// Trust marker carried by the sourcing event (I9).
    pub trust: TrustMarker,
}

impl FactOrigin {
    /// The origin of an event, for the fold.
    fn of(seq: u64, event: &unidpp_event::TypedEvent) -> FactOrigin {
        FactOrigin {
            seq,
            occurred_at: event.occurred_at,
            actor_role: event.actor_role.clone(),
            actor_id: event.actor_id.clone(),
            trust: event.trust,
        }
    }
}

/// A fact together with its origin.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SourcedFact {
    pub value: FactValue,
    pub origin: FactOrigin,
}

/// The testimonial twin state at an instant, with per-fact provenance.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TwinState {
    /// Facts keyed by path (sorted: `BTreeMap`).
    pub facts: BTreeMap<String, SourcedFact>,
    /// Passport status as-of (status machine replay).
    pub status: Status,
    /// Current custodian as-of, when a custody transfer is recorded.
    pub custodian: Option<String>,
    /// Events counted into this state (the as-of prefix length).
    pub event_count: usize,
    /// When the last counted event occurred.
    pub last_event_at: Option<Timestamp>,
}

impl TwinState {
    /// Look up a fact.
    pub fn get(&self, path: &str) -> Option<&SourcedFact> {
        self.facts.get(path)
    }

    /// The bare core-model twin facts (trigger-predicate evaluation,
    /// profile applicability): values only, origins stripped.
    pub fn to_core_facts(&self) -> TwinFacts {
        TwinFacts {
            facts: self
                .facts
                .iter()
                .map(|(k, sf)| (k.clone(), sf.value.clone()))
                .collect(),
            born_on: None,
        }
    }
}

/// Replay the passport's log up to `at` (inclusive: events that
/// occurred at or before `at`) into the twin state.
pub fn fold(passport: &Passport, at: Timestamp) -> TwinState {
    let mut state = TwinState {
        facts: BTreeMap::new(),
        status: Status::Issued,
        custodian: None,
        event_count: 0,
        last_event_at: None,
    };
    for sealed in passport.log.as_of(at) {
        let event = &sealed.event;
        let origin = FactOrigin::of(event.seq, event);
        match &event.payload {
            EventPayload::Issuance { .. } => {
                // Identity is never re-minted; the skeleton already
                // carries it. Nothing to fold.
            }
            EventPayload::MilestoneRecord { counters } => {
                for (k, v) in counters {
                    state.facts.insert(
                        k.clone(),
                        SourcedFact {
                            value: FactValue::Num(*v),
                            origin: origin.clone(),
                        },
                    );
                }
            }
            EventPayload::Correction {
                field, new_value, ..
            } => {
                state.facts.insert(
                    field.clone(),
                    SourcedFact {
                        value: typed_value(new_value),
                        origin,
                    },
                );
            }
            EventPayload::SoftwareUpdate { versions, .. } => {
                for (slot, version) in versions {
                    state.facts.insert(
                        format!("software.{slot}"),
                        SourcedFact {
                            value: FactValue::Str(version.clone()),
                            origin: origin.clone(),
                        },
                    );
                }
            }
            EventPayload::CustodyTransfer { to, .. } => {
                state.facts.insert(
                    "custody.custodian".to_string(),
                    SourcedFact {
                        value: FactValue::Str(to.clone()),
                        origin: origin.clone(),
                    },
                );
                state.custodian = Some(to.clone());
            }
            EventPayload::RefurbishRemanufacture {
                condition_grade, ..
            } => {
                state.facts.insert(
                    "subject.condition-grade".to_string(),
                    SourcedFact {
                        value: FactValue::Str(condition_grade.clone()),
                        origin,
                    },
                );
            }
            EventPayload::ProductModify {
                derived_type: Some(t),
                ..
            } => {
                state.facts.insert(
                    "subject.type".to_string(),
                    SourcedFact {
                        value: FactValue::Str(t.clone()),
                        origin,
                    },
                );
            }
            EventPayload::StatusChange { to, .. } => {
                state.status = *to;
            }
            EventPayload::Split {
                parent_consumed, ..
            } => {
                if *parent_consumed {
                    state.status = Status::Transformed;
                }
            }
            EventPayload::Decompose { .. } => {
                state.status = Status::Transformed;
            }
            EventPayload::EndOfWaste { .. } => {
                state.status = Status::EndOfWaste;
            }
            _ => {
                // Structural events (install edges, replacements,
                // recalls, flags, stamps) do not write scalar facts;
                // the view reports the log separately.
            }
        }
        state.event_count += 1;
        state.last_event_at = Some(event.occurred_at);
    }
    state
}

/// Type a correction's new value: exact decimal when it parses as
/// one, boolean for the canonical spellings, else string.
fn typed_value(raw: &str) -> FactValue {
    let trimmed = raw.trim();
    if let Ok(d) = trimmed.parse::<unidpp_model::Decimal>() {
        return FactValue::Num(d);
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "true" => FactValue::Bool(true),
        "false" => FactValue::Bool(false),
        _ => FactValue::Str(raw.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{self, demo_as_of, facts};
    use unidpp_event::{EventType, TypedEvent};

    fn fold_at(at: Timestamp) -> TwinState {
        fold(&fixtures::demo_passport(), at)
    }

    #[test]
    fn milestone_counters_become_facts_with_provenance() {
        let state = fold_at(demo_as_of());
        let fact = state.get(facts::CARBON).unwrap();
        assert_eq!(
            fact.value,
            FactValue::Num("96.4".parse::<unidpp_model::Decimal>().unwrap())
        );
        // The milestone event is seq 6, attested, by the OEM.
        assert_eq!(fact.origin.seq, 6);
        assert_eq!(fact.origin.trust, TrustMarker::Attested);
        assert_eq!(fact.origin.actor_role, "economic operator");
    }

    #[test]
    fn correction_values_are_typed() {
        let state = fold_at(demo_as_of());
        let operator = state.get(facts::OPERATOR_ID).unwrap();
        assert_eq!(
            operator.value,
            FactValue::Str("urn:unidpp:actor:oem-nordwave".into())
        );
        // Booleans and decimals type through the same rule.
        assert_eq!(
            typed_value("8.1"),
            FactValue::Num("8.1".parse::<unidpp_model::Decimal>().unwrap())
        );
        assert_eq!(typed_value(" TRUE "), FactValue::Bool(true));
        assert_eq!(typed_value("false"), FactValue::Bool(false));
        assert_eq!(
            typed_value("pse-square-95"),
            FactValue::Str("pse-square-95".into())
        );
    }

    #[test]
    fn as_of_cut_excludes_later_events() {
        // Before the milestone (2027-01-12) the score is absent.
        let early = Timestamp::parse("2027-01-05T00:00:00Z").unwrap();
        let state = fold_at(early);
        assert!(state.get(facts::CARBON).is_none());
        assert!(state.get(facts::REPARABILITY).is_none());
        // The corrections through 2026-12-02 are already in (six
        // events); the milestone (2027-01-12) is not.
        assert!(state.get(facts::OPERATOR_ID).is_some());
        assert!(state.get(facts::PSE_MARK).is_some());
        assert_eq!(state.event_count, 6);
    }

    #[test]
    fn last_write_wins_with_its_origin() {
        let passport = fixtures::demo_passport();
        let later = Timestamp::parse("2027-03-01T00:00:00Z").unwrap();
        let mut doc = passport.clone();
        let correction = TypedEvent::new(
            doc.log.len() as u64,
            later,
            "regulator",
            "urn:unidpp:actor:reg-eu",
            EventType::Correction,
            EventPayload::Correction {
                field: facts::CARBON.to_string(),
                prior_value: "96.4".into(),
                new_value: "94.9".into(),
                reason: "operator restatement after audit".into(),
            },
            TrustMarker::MultiSigned,
        )
        .unwrap();
        doc.log.append(correction, None, None).unwrap();
        let state = fold(&doc, later);
        let fact = state.get(facts::CARBON).unwrap();
        assert_eq!(
            fact.value,
            FactValue::Num("94.9".parse::<unidpp_model::Decimal>().unwrap())
        );
        assert_eq!(fact.origin.seq, 8);
        assert_eq!(fact.origin.trust, TrustMarker::MultiSigned);
    }

    #[test]
    fn custody_and_software_are_tracked() {
        let state = fold_at(demo_as_of());
        assert_eq!(state.custodian.as_deref(), Some("consumer-anon-1"));
        assert_eq!(
            state.get("custody.custodian").unwrap().value,
            FactValue::Str("consumer-anon-1".into())
        );
        assert_eq!(
            state.get("software.system-firmware").unwrap().value,
            FactValue::Str("1.07".into())
        );
        assert_eq!(state.status, Status::Issued);
        assert_eq!(state.event_count, 8);
    }

    #[test]
    fn core_facts_stay_compatible_with_trigger_predicates() {
        use unidpp_model::TriggerPredicate;
        let state = fold_at(demo_as_of());
        let core = state.to_core_facts();
        let on_jp_market = TriggerPredicate::FactContains {
            path: facts::MARKETS.to_string(),
            needle: "JP".into(),
        };
        assert!(on_jp_market.eval(&core, demo_as_of()));
    }
}
