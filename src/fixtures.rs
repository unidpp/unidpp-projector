//! The two-lens demonstration corpus (STORY.md B4/B3 as a service):
//! one laptop passport and the EU/JP lens manifests.
//!
//! One neutral core, two jurisdiction lenses: EU ESPR electronics
//! (effective 2027-01-01) and JP METI PSE (effective 2026-10-01,
//! predicate-triggered on the JP market fact). No region is the
//! universal envelope — the lenses constrain and transform the same
//! twin state and disagree auditable: the EU view is complete and
//! grades the reparability score `A`, the JP view is missing the
//! top-runner-class data point and grades the *same* score
//! `class-2`.
//!
//! Determinism: every timestamp is fixed and the passport is built
//! structurally (never through `Passport::mint`, which reads the
//! wall clock). Identities and timestamps are ported from the core
//! demo fixture `unidpp-core/crates/unidpp-demo/src/laptop.rs` and
//! its TypeScript ancestor.

use unidpp_cli::passport::{Passport, SCHEMA};
use unidpp_event::{EventLog, EventPayload, EventType, TypedEvent};
use unidpp_model::{
    CapabilityClass, DataPointRef, FreshnessRequirement, Interval, PassportId, ProductIdentifier,
    ProfileAxes, ProfileId, ProfileManifest, Resolution, SignatureSuite, Timestamp, Traversal,
    TriggerPredicate, TrustMarker, VisibilityClass,
};

use crate::lens::{ClassBand, DataPointBinding, LensManifest, TransformBinding};
use crate::project::RegisteredUnit;

/// The demo passport id (one laptop instance, ISO/IEC 15459).
pub const DEMO_PASSPORT_ID: &str = "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345";

/// The EU lens item id.
pub const EU_LENS_ID: &str = "urn:unidpp:profile:eu-espr-electronics";

/// The JP lens item id.
pub const JP_LENS_ID: &str = "urn:unidpp:profile:jp-meti-pse";

/// The canonical demonstration instant (after every demo event).
pub const DEMO_AS_OF: &str = "2027-02-11T11:00:00Z";

/// Twin-fact paths used by the demo bindings.
pub mod facts {
    pub const OPERATOR_ID: &str = "de.dpp.operator-id";
    pub const REPARABILITY: &str = "de.dpp.reparability-score";
    pub const CARBON: &str = "de.dpp.carbon-footprint";
    pub const PSE_MARK: &str = "de.jp.pse-mark";
    pub const TOP_RUNNER: &str = "de.jp.top-runner-class";
    pub const CAPACITY_KWH: &str = "battery.capacity-kwh";
    pub const MARKETS: &str = "subject.markets";
}

use facts as f;

fn pid(s: &str) -> PassportId {
    PassportId::new(s).expect("valid passport id")
}

fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("fixed fixture timestamp parses")
}

/// The demo passport: the neutral-core laptop document.
pub fn demo_passport() -> Passport {
    let passport_id = pid(DEMO_PASSPORT_ID);
    let mut log = EventLog::new(passport_id.clone());
    let events: Vec<TypedEvent> = vec![
        event(
            0,
            "2026-08-03T09:15:00Z",
            "issuing authority",
            "urn:unidpp:actor:oem-nordwave",
            EventType::Issuance,
            EventPayload::Issuance {
                derived: false,
                inputs: vec![],
            },
            TrustMarker::Attested,
        ),
        event(
            1,
            "2026-08-20T14:02:00Z",
            "custodian",
            "urn:unidpp:actor:retailer-kyoto-denshi",
            EventType::CustodyTransfer,
            EventPayload::CustodyTransfer {
                from: "urn:unidpp:actor:oem-nordwave".into(),
                to: "consumer-anon-1".into(),
                counterparty_signed: true,
            },
            TrustMarker::SelfDeclared,
        ),
        event(
            2,
            "2026-11-05T02:30:00Z",
            "economic operator",
            "urn:unidpp:actor:oem-nordwave",
            EventType::SoftwareUpdate,
            EventPayload::SoftwareUpdate {
                versions: [("system-firmware".to_string(), "1.07".to_string())]
                    .into_iter()
                    .collect(),
                unlocked_features: vec![],
            },
            TrustMarker::SelfDeclared,
        ),
        event(
            3,
            "2026-12-01T08:00:00Z",
            "economic operator",
            "urn:unidpp:actor:oem-nordwave",
            EventType::Correction,
            EventPayload::Correction {
                field: f::MARKETS.into(),
                prior_value: String::new(),
                new_value: "EU,JP".into(),
                reason: "market placement declaration (EU, JP)".into(),
            },
            TrustMarker::SelfDeclared,
        ),
        event(
            4,
            "2026-12-01T08:05:00Z",
            "economic operator",
            "urn:unidpp:actor:oem-nordwave",
            EventType::Correction,
            EventPayload::Correction {
                field: f::OPERATOR_ID.into(),
                prior_value: String::new(),
                new_value: "urn:unidpp:actor:oem-nordwave".into(),
                reason: "EU/JP DPP operator identifier".into(),
            },
            TrustMarker::Attested,
        ),
        event(
            5,
            "2026-12-02T10:00:00Z",
            "conformity assessment body",
            "urn:unidpp:actor:cab-meti-licensed",
            EventType::Correction,
            EventPayload::Correction {
                field: f::PSE_MARK.into(),
                prior_value: String::new(),
                new_value: "pse-square-95".into(),
                reason: "METI PSE conformity declaration".into(),
            },
            TrustMarker::Attested,
        ),
        event(
            6,
            "2027-01-12T09:00:00Z",
            "economic operator",
            "urn:unidpp:actor:oem-nordwave",
            EventType::MilestoneRecord,
            EventPayload::MilestoneRecord {
                counters: [
                    (f::REPARABILITY.to_string(), "8.1".parse().unwrap()),
                    (f::CARBON.to_string(), "96.4".parse().unwrap()),
                    (f::CAPACITY_KWH.to_string(), "0.072".parse().unwrap()),
                ]
                .into_iter()
                .collect(),
            },
            TrustMarker::Attested,
        ),
        event(
            7,
            "2027-02-11T10:44:00Z",
            "repairer",
            "urn:unidpp:actor:repair-shibuya",
            EventType::PartReplace,
            EventPayload::PartReplace {
                removed: pid("urn:unidpp:passport:sodimm-16g-aa117-0042"),
                added: pid("urn:unidpp:passport:sodimm-32g-aa119-0007"),
                like_for_like: false,
            },
            TrustMarker::Attested,
        ),
    ];
    for e in events {
        log.append(e, None, None)
            .expect("fixture events append cleanly");
    }
    Passport {
        schema: SCHEMA.to_string(),
        passport_id,
        product_id: ProductIdentifier::parse(
            "cpid:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
        )
        .expect("fixture product identifier parses"),
        type_ref: Some("laptop-hw-rev-b".to_string()),
        capability: CapabilityClass::PassiveAuth,
        eo_id: "urn:unidpp:actor:oem-nordwave".to_string(),
        resolver_uri: "https://dpp.unidpp.org/r/84120099012345".to_string(),
        validity: Interval {
            from: ts("2026-08-03T09:15:00Z"),
            to: Some(ts("2036-08-03T09:15:00Z")),
        },
        created_at: ts("2026-08-03T09:15:00Z"),
        log,
        event_signatures: Vec::new(),
    }
}

fn event(
    seq: u64,
    at: &str,
    role: &str,
    actor: &str,
    event_type: EventType,
    payload: EventPayload,
    trust: TrustMarker,
) -> TypedEvent {
    TypedEvent::new(seq, ts(at), role, actor, event_type, payload, trust)
        .expect("fixture event is well-formed")
}

/// The EU ESPR electronics lens: complete coverage, classifies the
/// reparability score on the EU bands.
pub fn eu_lens() -> LensManifest {
    let lens = LensManifest {
        version: "1.0.0".to_string(),
        profile: ProfileManifest {
            id: ProfileId::new(EU_LENS_ID).unwrap(),
            axes: ProfileAxes::jurisdiction("EU").with_sector("electronics"),
            trigger: TriggerPredicate::Any,
            min_capability: CapabilityClass::Silent,
            freshness: FreshnessRequirement::Static,
            effective: Interval::starting(ts("2027-01-01T00:00:00Z")),
            data_points: vec![
                DataPointRef::new("ferin:eu", "de.dpp.operator-id", Some("1.0.0")).unwrap(),
                DataPointRef::new("ferin:eu", "de.dpp.reparability-score", Some("1.1.0")).unwrap(),
                DataPointRef::new("ferin:eu", "de.dpp.carbon-footprint", Some("1.2.0")).unwrap(),
            ],
            crypto_suites: vec![SignatureSuite::EcdsaP256, SignatureSuite::Sm2],
            confidential: false,
            resolution: Resolution::Public,
            edge_visibility: VisibilityClass::Blind,
            traversal: Traversal::RoleScoped,
        },
        bindings: vec![
            DataPointBinding {
                element: "ferin:eu/de.dpp.operator-id@1.0.0".into(),
                source: f::OPERATOR_ID.into(),
                min_trust: TrustMarker::Attested,
                min_capability: CapabilityClass::Silent,
                declared_unit: None,
            },
            DataPointBinding {
                element: "ferin:eu/de.dpp.reparability-score@1.1.0".into(),
                source: f::REPARABILITY.into(),
                min_trust: TrustMarker::SelfDeclared,
                min_capability: CapabilityClass::Silent,
                declared_unit: None,
            },
            DataPointBinding {
                element: "ferin:eu/de.dpp.carbon-footprint@1.2.0".into(),
                source: f::CARBON.into(),
                min_trust: TrustMarker::SelfDeclared,
                min_capability: CapabilityClass::Silent,
                declared_unit: Some("kgCO2e".into()),
            },
        ],
        transforms: vec![TransformBinding::Classification {
            id: "eu-reparability-class".into(),
            source: f::REPARABILITY.into(),
            bands: vec![
                ClassBand {
                    label: "A".into(),
                    min: "8.0".parse().unwrap(),
                },
                ClassBand {
                    label: "B".into(),
                    min: "6.0".parse().unwrap(),
                },
                ClassBand {
                    label: "C".into(),
                    min: "4.0".parse().unwrap(),
                },
                ClassBand {
                    label: "D".into(),
                    min: "0".parse().unwrap(),
                },
            ],
        }],
    };
    lens.validate().expect("EU lens validates");
    lens
}

/// The JP METI PSE lens: predicate-triggered on the JP market fact,
/// missing the top-runner-class data point (the auditable divergence),
/// converts battery capacity kWh -> MJ, and classifies the same
/// reparability score on the JP bands.
pub fn jp_lens() -> LensManifest {
    let lens = LensManifest {
        version: "1.0.0".to_string(),
        profile: ProfileManifest {
            id: ProfileId::new(JP_LENS_ID).unwrap(),
            axes: ProfileAxes::jurisdiction("JP").with_sector("electronics"),
            trigger: TriggerPredicate::FactContains {
                path: f::MARKETS.into(),
                needle: "JP".into(),
            },
            min_capability: CapabilityClass::Silent,
            freshness: FreshnessRequirement::Static,
            effective: Interval::starting(ts("2026-10-01T00:00:00Z")),
            data_points: vec![
                DataPointRef::new("ferin:jp", "de.dpp.operator-id", Some("1.0.0")).unwrap(),
                DataPointRef::new("ferin:jp", "de.jp.pse-mark", Some("2.0.0")).unwrap(),
                DataPointRef::new("ferin:jp", "de.jp.top-runner-class", Some("2026.1")).unwrap(),
            ],
            crypto_suites: vec![SignatureSuite::EcdsaP256],
            confidential: false,
            resolution: Resolution::Public,
            edge_visibility: VisibilityClass::Blind,
            traversal: Traversal::RoleScoped,
        },
        bindings: vec![
            DataPointBinding {
                element: "ferin:jp/de.dpp.operator-id@1.0.0".into(),
                source: f::OPERATOR_ID.into(),
                min_trust: TrustMarker::Attested,
                min_capability: CapabilityClass::Silent,
                declared_unit: None,
            },
            DataPointBinding {
                element: "ferin:jp/de.jp.pse-mark@2.0.0".into(),
                source: f::PSE_MARK.into(),
                min_trust: TrustMarker::Attested,
                min_capability: CapabilityClass::Silent,
                declared_unit: None,
            },
            DataPointBinding {
                // Deliberately not provided by the demo passport: the
                // two lenses must disagree on coverage, visibly.
                element: "ferin:jp/de.jp.top-runner-class@2026.1".into(),
                source: f::TOP_RUNNER.into(),
                min_trust: TrustMarker::SelfDeclared,
                min_capability: CapabilityClass::Silent,
                declared_unit: None,
            },
        ],
        transforms: vec![
            TransformBinding::UnitConversion {
                id: "capacity-mj".into(),
                source: f::CAPACITY_KWH.into(),
                from_unit: "kWh".into(),
                to_unit: "MJ".into(),
                from_item: Some("unit-kwh".into()),
                to_item: Some("unit-mj".into()),
            },
            TransformBinding::Classification {
                id: "jp-reparability-class".into(),
                source: f::REPARABILITY.into(),
                bands: vec![
                    ClassBand {
                        label: "class-1".into(),
                        min: "8.5".parse().unwrap(),
                    },
                    ClassBand {
                        label: "class-2".into(),
                        min: "7.0".parse().unwrap(),
                    },
                    ClassBand {
                        label: "class-3".into(),
                        min: "5.0".parse().unwrap(),
                    },
                    ClassBand {
                        label: "class-4".into(),
                        min: "0".parse().unwrap(),
                    },
                ],
            },
        ],
    };
    lens.validate().expect("JP lens validates");
    lens
}

/// A built-in lens by profile item id (the fixtures-mode registry).
pub fn fixture_lens(profile_id: &str) -> Option<LensManifest> {
    match profile_id {
        EU_LENS_ID => Some(eu_lens()),
        JP_LENS_ID => Some(jp_lens()),
        _ => None,
    }
}

/// The built-in unit identities (fixtures mode): the registry seed
/// dataset's ISO 80000 citations, so the kWh -> MJ conversion still
/// shows its registered citation chain when no registry is reachable.
pub fn fixture_units() -> std::collections::BTreeMap<String, RegisteredUnit> {
    let mut units = std::collections::BTreeMap::new();
    for (item, name, citation) in [
        (
            "unit-kwh",
            "kilowatt hour",
            "ISO 80000-4:2006 (energy); 1 kWh = 3.6 MJ exactly",
        ),
        ("unit-mj", "megajoule", "ISO 80000-4:2006 (energy)"),
    ] {
        units.insert(
            item.to_string(),
            RegisteredUnit {
                item: item.to_string(),
                name: name.to_string(),
                citation: Some(citation.to_string()),
            },
        );
    }
    units
}

/// The demonstration instant as a [`Timestamp`].
pub fn demo_as_of() -> Timestamp {
    ts(DEMO_AS_OF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_passport_round_trips_through_the_document_shape() {
        let p = demo_passport();
        let text = p.to_json().unwrap();
        assert!(text.contains(SCHEMA));
        let back = Passport::from_json(&text).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn demo_passport_log_is_consistent() {
        let p = demo_passport();
        assert_eq!(p.log.len(), 8);
        p.log.verify().expect("fixture hash chain verifies");
        assert_eq!(p.log.subject(), &p.passport_id);
    }

    #[test]
    fn fixture_lenses_are_deterministic() {
        assert_eq!(eu_lens(), eu_lens());
        assert_eq!(jp_lens(), jp_lens());
        assert_ne!(eu_lens().id(), jp_lens().id());
        assert_eq!(demo_passport(), demo_passport());
    }

    #[test]
    fn demo_timestamps_parse() {
        assert_eq!(demo_as_of().to_string(), DEMO_AS_OF);
    }
}
