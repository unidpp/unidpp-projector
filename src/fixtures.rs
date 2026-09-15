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

use crate::aggregate::AggregationOperation;
use crate::codelist::{CodeListMapping, MappingSet};
use crate::lens::{
    ClassBand, DataPointBinding, FormattingRules, LensManifest, PresentationBinding,
    PresentationElement, PresentationSection, TransformBinding,
};
use crate::project::RegisteredUnit;

/// The demo passport id (one laptop instance, ISO/IEC 15459).
pub const DEMO_PASSPORT_ID: &str = "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345";

/// The EU lens item id.
pub const EU_LENS_ID: &str = "urn:unidpp:profile:eu-espr-electronics";

/// The JP lens item id.
pub const JP_LENS_ID: &str = "urn:unidpp:profile:jp-meti-pse";

/// The consumer presentation lens item id (TODO.impl 54).
pub const CONSUMER_LENS_ID: &str = "urn:unidpp:profile:consumer-dpp";

/// The CN regulatory protocol lens item id (TODO.impl 224).
pub const CN_PROTOCOL_LENS_ID: &str = "urn:unidpp:profile:cn-protocol-checks";

/// The EU battery-pack-system roll-up lens item id (TODO.impl 66/67).
pub const PACK_LENS_ID: &str = "urn:unidpp:profile:eu-battery-packs";

/// The battery-pack-system passport id (the aggregation subject).
pub const PACK_SYSTEM_ID: &str =
    "urn:iso:std:iso-iec:15459:unidpp:passport:packsystem-84120099077701";

/// The three battery-pack child passport ids (the traversal set), in
/// passport-id order.
pub const PACK_CHILD_IDS: [&str; 3] = [
    "urn:iso:std:iso-iec:15459:unidpp:passport:pack-84120099088001",
    "urn:iso:std:iso-iec:15459:unidpp:passport:pack-84120099088002",
    "urn:iso:std:iso-iec:15459:unidpp:passport:pack-84120099088003",
];

/// The EU-class-to-JP-star code-list mapping item id (TODO.impl 67).
pub const EU_CLASS_TO_JP_STAR_ID: &str = "urn:unidpp:mapping:eu-class-to-jp-star";

/// The reverse correspondence item id (JP stars back to EU classes).
pub const JP_STAR_TO_EU_CLASS_ID: &str = "urn:unidpp:mapping:jp-star-to-eu-class";

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
    pub const SOH: &str = "battery.soh-pct";
    pub const SOH_UNCERTAINTY: &str = "battery.soh-u-pct";
    pub const ROUND_TRIP_EFFICIENCY: &str = "battery.round-trip-efficiency-pct";
    /// Recycling instruction: deliberately NOT provided by the demo
    /// passport (the consumer lens's explicit coverage gap).
    pub const RECYCLING_INSTRUCTION: &str = "de.dpp.recycling-instruction";
    /// The pack system's EU energy-label class (string code value).
    pub const ENERGY_LABEL: &str = "eu.energy-label-class";
    /// Per-pack carbon footprint (kgCO2e).
    pub const PACK_CARBON: &str = "pack.carbon-footprint";
    /// Per-pack mass (kg).
    pub const PACK_MASS: &str = "pack.mass-kg";
    /// Per-pack state of health (%).
    pub const PACK_SOH: &str = "pack.soh-pct";
    /// CN regulatory protocol conformance (TODO.impl 224): the
    /// MobileQR `ProtocolChecks` as data points — national regimes as
    /// registry content, named not embedded in prose.
    pub const CN_PROTOCOL_3C: &str = "cn.protocol.3c";
    pub const CN_PROTOCOL_PRODUCER: &str = "cn.protocol.producer-regulation";
    pub const CN_PROTOCOL_LICENSE: &str = "cn.protocol.industrial-license";
}

/// Canonical element refs of the consumer lens's data points.
pub const OPERATOR_ELEMENT: &str = "ferin:eu/de.dpp.operator-id@1.0.0";
pub const CAPACITY_ELEMENT: &str = "ferin:eu/battery.capacity-kwh@1.0.0";
pub const REPARABILITY_ELEMENT: &str = "ferin:eu/de.dpp.reparability-score@1.1.0";
pub const CARBON_ELEMENT: &str = "ferin:eu/de.dpp.carbon-footprint@1.2.0";
pub const INSTRUCTION_ELEMENT: &str = "ferin:eu/de.dpp.recycling-instruction@1.0.0";
/// Canonical element refs of the pack lens's data points.
pub const ENERGY_LABEL_ELEMENT: &str = "ferin:eu/eu.energy-label-class@1.0.0";
pub const PACK_CARBON_ELEMENT: &str = "ferin:eu/pack.carbon-footprint@1.0.0";
pub const PACK_MASS_ELEMENT: &str = "ferin:eu/pack.mass-kg@1.0.0";
pub const PACK_SOH_ELEMENT: &str = "ferin:eu/pack.soh-pct@1.0.0";
/// Canonical element refs of the CN protocol-check lens's data points
/// (TODO.impl 224).
pub const CN_3C_ELEMENT: &str = "ferin:cn/cn.protocol.3c@1.0.0";
pub const CN_PRODUCER_ELEMENT: &str = "ferin:cn/cn.protocol.producer-regulation@1.0.0";
pub const CN_LICENSE_ELEMENT: &str = "ferin:cn/cn.protocol.industrial-license@1.0.0";

/// The built-in Primmel package (fixtures mode): the battery decision
/// rules, as a `.prml` JSON document — the exact wire shape the
/// parser serves, never a hand-built struct (the fixture proves the
/// schema).
pub const BATTERY_RULES_PRML: &str = r#"{
  "id": "urn:primmel:pkg:battery-rules",
  "version": "1.0.0",
  "title": "Battery passport decision rules (two-lens demo)",
  "rules": [
    {
      "id": "soh-guard-band",
      "clause_urn": "urn:oiml:pub:r:91-2:2025#clause-6.1",
      "title": "State of health >= 85 %, guarded acceptance with w = U",
      "arms": [
        { "label": "conforming",
          "when": { "op": "ge",
                    "lhs": { "sub": [ { "input": "soh" }, { "input": "U" } ] },
                    "rhs": { "const": "85" } } },
        { "label": "not-demonstrably-conforming" }
      ]
    },
    {
      "id": "efficiency-class",
      "clause_urn": "urn:eu:reg:2017:1369#annex-ii",
      "title": "Round-trip efficiency class bands",
      "arms": [
        { "label": "A", "when": { "op": "ge",
                                  "lhs": { "input": "eff" },
                                  "rhs": { "const": "92" } } },
        { "label": "B", "when": { "op": "ge",
                                  "lhs": { "input": "eff" },
                                  "rhs": { "const": "85" } } },
        { "label": "C" }
      ]
    }
  ]
}
"#;

/// The EU energy-label class to JP star-display correspondence (the
/// built-in code-list mapping fixture, TODO.impl 67) — the exact wire
/// shape the parser serves. The registered table scopes the
/// correspondence to the A–E band (bijective onto the five-star
/// display); values outside the band map to the explicit `unmapped`.
pub const EU_CLASS_TO_JP_STAR_MAPPING: &str = r#"{
  "id": "urn:unidpp:mapping:eu-class-to-jp-star",
  "version": "1.0.0",
  "title": "EU energy-label class to JP star display (A-E band)",
  "citation": "Regulation (EU) 2017/1369 Annex II <-> JP METI star display",
  "source_scheme": "urn:eu:reg:2017:1369#annex-ii-class",
  "target_scheme": "urn:jp:meti:star-rating",
  "table": [
    { "source_value": "A", "target_value": "\u2605\u2605\u2605\u2605\u2605",
      "note": "the A-E band of the EU scale maps onto the five-star display" },
    { "source_value": "B", "target_value": "\u2605\u2605\u2605\u2605" },
    { "source_value": "C", "target_value": "\u2605\u2605\u2605" },
    { "source_value": "D", "target_value": "\u2605\u2605" },
    { "source_value": "E", "target_value": "\u2605" }
  ]
}"#;

/// The built-in Primmel package id.
pub const BATTERY_RULES_PACKAGE_ID: &str = "urn:primmel:pkg:battery-rules";

/// The guard-band rule id within the package.
pub const SOH_GUARD_BAND_RULE: &str = "soh-guard-band";

/// The efficiency class rule id within the package.
pub const EFFICIENCY_CLASS_RULE: &str = "efficiency-class";

use crate::primmel::{PackageSet, PrimmelPackage};

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
                    // The battery state-of-health measurand and its
                    // expanded uncertainty (k = 2): the guard-band
                    // rule consumes both — 86.3 - 1.8 = 84.5 < 85, so
                    // the JP lens reports *not demonstrably*
                    // conforming although the bare value would pass.
                    (f::SOH.to_string(), "86.3".parse().unwrap()),
                    (f::SOH_UNCERTAINTY.to_string(), "1.8".parse().unwrap()),
                    (
                        f::ROUND_TRIP_EFFICIENCY.to_string(),
                        "88.5".parse().unwrap(),
                    ),
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
        // CN market entry: the regulatory protocol conformance
        // declarations (TODO.impl 224) — the MobileQR ProtocolChecks
        // pattern. 3C attested by the licensed CAB; producer-regulation
        // declared by the operator; industrial licensing *not* obtained
        // — a stated false, never an omission.
        event(
            8,
            "2027-02-11T10:50:00Z",
            "conformity assessment body",
            "urn:unidpp:actor:cab-cnccc-licensed",
            EventType::Correction,
            EventPayload::Correction {
                field: f::CN_PROTOCOL_3C.into(),
                prior_value: String::new(),
                new_value: "true".into(),
                reason: "CCC certification protocol conformance (CN market entry)".into(),
            },
            TrustMarker::Attested,
        ),
        event(
            9,
            "2027-02-11T10:51:00Z",
            "economic operator",
            "urn:unidpp:actor:oem-nordwave",
            EventType::Correction,
            EventPayload::Correction {
                field: f::CN_PROTOCOL_PRODUCER.into(),
                prior_value: String::new(),
                new_value: "true".into(),
                reason: "producer-regulation protocol conformance declaration".into(),
            },
            TrustMarker::SelfDeclared,
        ),
        event(
            10,
            "2027-02-11T10:52:00Z",
            "economic operator",
            "urn:unidpp:actor:oem-nordwave",
            EventType::Correction,
            EventPayload::Correction {
                field: f::CN_PROTOCOL_LICENSE.into(),
                prior_value: String::new(),
                new_value: "false".into(),
                reason: "industrial product production licence not required for this class"
                    .into(),
            },
            TrustMarker::SelfDeclared,
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
            issuer_class: unidpp_model::IssuerClass::Consensus,
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
        transforms: vec![
            TransformBinding::Classification {
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
            },
            // The EU lens also classifies the round-trip efficiency
            // through the Primmel package — the output carries the
            // clause URN of the class table it applies.
            TransformBinding::Primmel {
                id: "eu-efficiency-class".into(),
                package_ref: BATTERY_RULES_PACKAGE_ID.into(),
                rule_id: EFFICIENCY_CLASS_RULE.into(),
                inputs: [("eff".to_string(), f::ROUND_TRIP_EFFICIENCY.to_string())]
                    .into_iter()
                    .collect(),
            },
        ],
        presentation: None,
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
            issuer_class: unidpp_model::IssuerClass::Consensus,
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
            // The guard-band moment: the same SoH the EU lens would
            // call conforming (86.3 >= 85) is decided on the
            // uncertainty-narrowed limit (86.3 - 1.8 = 84.5 < 85) —
            // `not-demonstrably-conforming` under w = U, with the
            // clause URN the rule implements.
            TransformBinding::Primmel {
                id: "jp-soh-guard-band".into(),
                package_ref: BATTERY_RULES_PACKAGE_ID.into(),
                rule_id: SOH_GUARD_BAND_RULE.into(),
                inputs: [
                    ("soh".to_string(), f::SOH.to_string()),
                    ("U".to_string(), f::SOH_UNCERTAINTY.to_string()),
                ]
                .into_iter()
                .collect(),
            },
        ],
        presentation: None,
    };
    lens.validate().expect("JP lens validates");
    lens
}

/// The consumer presentation lens (TODO.impl 54): the demo passport
/// as the `/learn` page's four readers see it — sections product /
/// repair / recycling, per-element labels in English and Japanese, an
/// element the passport deliberately does not provide (the recycling
/// instruction) so the render's coverage gap is part of the demo.
pub fn consumer_lens() -> LensManifest {
    let labels = |pairs: &[(&str, &str)]| -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(l, t)| (l.to_string(), t.to_string()))
            .collect()
    };
    let presented = |element: &str, pairs: &[(&str, &str)]| PresentationElement {
        element: element.to_string(),
        labels: labels(pairs),
    };
    let section =
        |id: &str, section_labels: &[(&str, &str)], elements: Vec<PresentationElement>| {
            PresentationSection {
                id: id.to_string(),
                labels: labels(section_labels),
                elements,
            }
        };
    let lens = LensManifest {
        version: "1.0.0".to_string(),
        profile: ProfileManifest {
            issuer_class: unidpp_model::IssuerClass::Consensus,
            id: ProfileId::new(CONSUMER_LENS_ID).unwrap(),
            axes: ProfileAxes::jurisdiction("EU"),
            trigger: TriggerPredicate::Any,
            min_capability: CapabilityClass::Silent,
            freshness: FreshnessRequirement::Static,
            effective: Interval::starting(ts("2026-01-01T00:00:00Z")),
            data_points: vec![
                DataPointRef::new("ferin:eu", "de.dpp.operator-id", Some("1.0.0")).unwrap(),
                DataPointRef::new("ferin:eu", "battery.capacity-kwh", Some("1.0.0")).unwrap(),
                DataPointRef::new("ferin:eu", "de.dpp.reparability-score", Some("1.1.0")).unwrap(),
                DataPointRef::new("ferin:eu", "de.dpp.carbon-footprint", Some("1.2.0")).unwrap(),
                DataPointRef::new("ferin:eu", "de.dpp.recycling-instruction", Some("1.0.0"))
                    .unwrap(),
            ],
            crypto_suites: vec![SignatureSuite::EcdsaP256],
            confidential: false,
            resolution: Resolution::Public,
            edge_visibility: VisibilityClass::Public,
            traversal: Traversal::Public,
        },
        bindings: vec![
            DataPointBinding {
                element: OPERATOR_ELEMENT.into(),
                source: f::OPERATOR_ID.into(),
                min_trust: TrustMarker::Attested,
                min_capability: CapabilityClass::Silent,
                declared_unit: None,
            },
            DataPointBinding {
                element: CAPACITY_ELEMENT.into(),
                source: f::CAPACITY_KWH.into(),
                min_trust: TrustMarker::SelfDeclared,
                min_capability: CapabilityClass::Silent,
                declared_unit: Some("kWh".into()),
            },
            DataPointBinding {
                element: REPARABILITY_ELEMENT.into(),
                source: f::REPARABILITY.into(),
                min_trust: TrustMarker::SelfDeclared,
                min_capability: CapabilityClass::Silent,
                declared_unit: None,
            },
            DataPointBinding {
                element: CARBON_ELEMENT.into(),
                source: f::CARBON.into(),
                min_trust: TrustMarker::SelfDeclared,
                min_capability: CapabilityClass::Silent,
                declared_unit: Some("kgCO2e".into()),
            },
            DataPointBinding {
                // Deliberately not provided by the demo passport: the
                // render must show its gap, not hide it.
                element: INSTRUCTION_ELEMENT.into(),
                source: f::RECYCLING_INSTRUCTION.into(),
                min_trust: TrustMarker::SelfDeclared,
                min_capability: CapabilityClass::Silent,
                declared_unit: None,
            },
        ],
        transforms: vec![],
        presentation: Some(PresentationBinding {
            template_ref: "urn:unidpp:template:consumer-v1".to_string(),
            formatting: FormattingRules::default(),
            sections: vec![
                section(
                    "product",
                    &[("en", "Product"), ("ja", "製品情報")],
                    vec![
                        presented(OPERATOR_ELEMENT, &[("en", "Operator"), ("ja", "事業者ID")]),
                        presented(
                            CAPACITY_ELEMENT,
                            &[("en", "Battery capacity"), ("ja", "電池容量")],
                        ),
                    ],
                ),
                section(
                    "repair",
                    &[("en", "Repair"), ("ja", "修理")],
                    vec![presented(
                        REPARABILITY_ELEMENT,
                        &[("en", "Reparability score"), ("ja", "修理容易性スコア")],
                    )],
                ),
                section(
                    "recycling",
                    &[("en", "Recycling"), ("ja", "リサイクル")],
                    vec![
                        presented(
                            CARBON_ELEMENT,
                            &[("en", "Carbon footprint"), ("ja", "炭素フットプリント")],
                        ),
                        presented(
                            INSTRUCTION_ELEMENT,
                            &[("en", "Recycling instruction"), ("ja", "リサイクル手順")],
                        ),
                    ],
                ),
            ],
        }),
    };
    lens.validate().expect("consumer lens validates");
    lens
}

/// The CN regulatory protocol lens (TODO.impl 224): the MobileQR
/// `ProtocolChecks` pattern as a registered profile — national
/// conformity regimes (CCC certification, producer regulation,
/// industrial licensing) as *named data points with labels*, not
/// prose embedded in a page. A cross-jurisdiction verifier resolves
/// the CN protocol checks of any passport carrying them; the demo
/// passport carries all three (one deliberately false — stated, never
/// omitted).
pub fn cn_protocol_lens() -> LensManifest {
    let labels = |pairs: &[(&str, &str)]| -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(l, t)| (l.to_string(), t.to_string()))
            .collect()
    };
    let presented = |element: &str, pairs: &[(&str, &str)]| PresentationElement {
        element: element.to_string(),
        labels: labels(pairs),
    };
    let binding = |element: &str, source: &str, min_trust: TrustMarker| DataPointBinding {
        element: element.into(),
        source: source.into(),
        min_trust,
        min_capability: CapabilityClass::Silent,
        declared_unit: None,
    };
    let lens = LensManifest {
        version: "1.0.0".to_string(),
        profile: ProfileManifest {
            issuer_class: unidpp_model::IssuerClass::Consensus,
            id: ProfileId::new(CN_PROTOCOL_LENS_ID).unwrap(),
            axes: ProfileAxes::jurisdiction("CN"),
            trigger: TriggerPredicate::Any,
            min_capability: CapabilityClass::Silent,
            freshness: FreshnessRequirement::Static,
            effective: Interval::starting(ts("2026-01-01T00:00:00Z")),
            data_points: vec![
                DataPointRef::new("ferin:cn", "cn.protocol.3c", Some("1.0.0")).unwrap(),
                DataPointRef::new("ferin:cn", "cn.protocol.producer-regulation", Some("1.0.0"))
                    .unwrap(),
                DataPointRef::new("ferin:cn", "cn.protocol.industrial-license", Some("1.0.0"))
                    .unwrap(),
            ],
            crypto_suites: vec![SignatureSuite::EcdsaP256],
            confidential: false,
            resolution: Resolution::Public,
            edge_visibility: VisibilityClass::Public,
            traversal: Traversal::Public,
        },
        bindings: vec![
            binding(CN_3C_ELEMENT, f::CN_PROTOCOL_3C, TrustMarker::Attested),
            binding(
                CN_PRODUCER_ELEMENT,
                f::CN_PROTOCOL_PRODUCER,
                TrustMarker::SelfDeclared,
            ),
            binding(
                CN_LICENSE_ELEMENT,
                f::CN_PROTOCOL_LICENSE,
                TrustMarker::SelfDeclared,
            ),
        ],
        transforms: vec![],
        presentation: Some(PresentationBinding {
            template_ref: "urn:unidpp:template:cn-protocol-v1".to_string(),
            formatting: FormattingRules::default(),
            sections: vec![PresentationSection {
                id: "regulatory".to_string(),
                labels: labels(&[("zh", "监管协议核查"), ("en", "Regulatory protocol checks")]),
                elements: vec![
                    presented(CN_3C_ELEMENT, &[("zh", "强制性产品认证（CCC）"), ("en", "CCC certification protocol")]),
                    presented(CN_PRODUCER_ELEMENT, &[("zh", "生产者法规"), ("en", "Producer regulation protocol")]),
                    presented(CN_LICENSE_ELEMENT, &[("zh", "工业产品生产许可证"), ("en", "Industrial product production licence")]),
                ],
            }],
        }),
    };
    lens.validate().expect("CN protocol lens validates");
    lens
}

/// One battery-pack child: issued, then an attested milestone carrying
/// its carbon footprint (kgCO2e), mass (kg) and state of health (%).
/// Values chosen so the demo weighted average divides exactly.
pub fn pack_child(index: usize) -> Passport {
    let carbon = ["31.5", "33.0", "25.5"][index];
    let mass = ["12.5", "15.5", "12.0"][index];
    let soh = ["91.2", "88.4", "86.9"][index];
    let issued = [
        "2027-01-05T09:00:00Z",
        "2027-01-05T09:05:00Z",
        "2027-01-05T09:10:00Z",
    ][index];
    let passport_id = pid(PACK_CHILD_IDS[index]);
    let mut log = EventLog::new(passport_id.clone());
    let events: Vec<TypedEvent> = vec![
        event(
            0,
            issued,
            "issuing authority",
            "urn:unidpp:actor:oem-batteriewerke",
            EventType::Issuance,
            EventPayload::Issuance {
                derived: false,
                inputs: vec![],
            },
            TrustMarker::Attested,
        ),
        event(
            1,
            "2027-01-05T12:00:00Z",
            "economic operator",
            "urn:unidpp:actor:oem-batteriewerke",
            EventType::MilestoneRecord,
            EventPayload::MilestoneRecord {
                counters: [
                    (f::PACK_CARBON.to_string(), carbon.parse().unwrap()),
                    (f::PACK_MASS.to_string(), mass.parse().unwrap()),
                    (f::PACK_SOH.to_string(), soh.parse().unwrap()),
                ]
                .into_iter()
                .collect(),
            },
            TrustMarker::Attested,
        ),
    ];
    for e in events {
        log.append(e, None, None)
            .expect("fixture pack events append cleanly");
    }
    Passport {
        schema: SCHEMA.to_string(),
        passport_id,
        product_id: ProductIdentifier::parse(&format!(
            "cpid:urn:iso:std:iso-iec:15459:unidpp:inst:8412009908800{}",
            index + 1
        ))
        .expect("fixture product identifier parses"),
        type_ref: Some("battery-pack-hw-rev-a".to_string()),
        capability: CapabilityClass::PassiveAuth,
        eo_id: "urn:unidpp:actor:oem-batteriewerke".to_string(),
        resolver_uri: format!("https://dpp.unidpp.org/r/8412009908800{}", index + 1),
        validity: Interval {
            from: ts(issued),
            to: Some(ts("2042-01-05T09:00:00Z")),
        },
        created_at: ts(issued),
        log,
        event_signatures: Vec::new(),
    }
}

/// The three battery-pack children, in passport-id order.
pub fn pack_children() -> Vec<Passport> {
    (0..3).map(pack_child).collect()
}

/// The battery-pack system passport (the aggregation subject): a
/// derived issuance over the three packs — each input reference pins
/// the child's log head as-of the composition — plus the system's EU
/// energy-label class (the code value the localization mapping
/// translates).
pub fn pack_system() -> Passport {
    let children = pack_children();
    let composed_at = ts("2027-01-06T10:00:00Z");
    let inputs: Vec<unidpp_transform::InputReference> = children
        .iter()
        .zip(["12.5", "15.5", "12.0"])
        .map(|(child, mass)| unidpp_transform::InputReference {
            input: child.passport_id.clone(),
            quantity: unidpp_transform::Quantity::new(
                mass.parse().unwrap(),
                unidpp_transform::quantity::Unit::new("kg", "urn:iso:std:iso:80000-4").unwrap(),
            ),
            as_of_state_hash: child
                .log
                .state_hash_at(ts("2027-01-05T12:00:00Z"))
                .expect("child log has a state hash at its milestone"),
        })
        .collect();
    let passport_id = pid(PACK_SYSTEM_ID);
    let mut log = EventLog::new(passport_id.clone());
    let events: Vec<TypedEvent> = vec![
        event(
            0,
            "2027-01-06T10:00:00Z",
            "issuing authority",
            "urn:unidpp:actor:oem-batteriewerke",
            EventType::Issuance,
            EventPayload::Issuance {
                derived: true,
                inputs,
            },
            TrustMarker::Attested,
        ),
        event(
            1,
            "2027-01-06T10:05:00Z",
            "conformity assessment body",
            "urn:unidpp:actor:cab-eu-notified",
            EventType::Correction,
            EventPayload::Correction {
                field: f::ENERGY_LABEL.into(),
                prior_value: String::new(),
                new_value: "B".into(),
                reason: "EU energy-label class of the pack system".into(),
            },
            TrustMarker::Attested,
        ),
    ];
    for e in events {
        log.append(e, None, None)
            .expect("fixture system events append cleanly");
    }
    Passport {
        schema: SCHEMA.to_string(),
        passport_id,
        product_id: ProductIdentifier::parse(
            "cpid:urn:iso:std:iso-iec:15459:unidpp:inst:84120099077701",
        )
        .expect("fixture product identifier parses"),
        type_ref: Some("battery-pack-system-rev-a".to_string()),
        capability: CapabilityClass::PassiveAuth,
        eo_id: "urn:unidpp:actor:oem-batteriewerke".to_string(),
        resolver_uri: "https://dpp.unidpp.org/r/84120099077701".to_string(),
        validity: Interval {
            from: composed_at,
            to: Some(ts("2042-01-06T10:00:00Z")),
        },
        created_at: composed_at,
        log,
        event_signatures: Vec::new(),
    }
}

/// The EU battery-pack-system lens (TODO.impl 66 + 67): the roll-up
/// profile. The pack elements (carbon, mass, SoH) are data points of
/// the *packs* — the system twin state does not carry them, so the
/// subject-level coverage honestly reports them absent while the
/// aggregation transforms select them from every child of the
/// traversal set (the binding supplies the fact path and the gates).
pub fn pack_lens() -> LensManifest {
    let lens = LensManifest {
        version: "1.0.0".to_string(),
        profile: ProfileManifest {
            issuer_class: unidpp_model::IssuerClass::Consensus,
            id: ProfileId::new(PACK_LENS_ID).unwrap(),
            axes: ProfileAxes::jurisdiction("EU").with_sector("batteries"),
            trigger: TriggerPredicate::Any,
            min_capability: CapabilityClass::Silent,
            freshness: FreshnessRequirement::Static,
            effective: Interval::starting(ts("2027-01-01T00:00:00Z")),
            data_points: vec![
                DataPointRef::new("ferin:eu", "eu.energy-label-class", Some("1.0.0")).unwrap(),
                DataPointRef::new("ferin:eu", "pack.carbon-footprint", Some("1.0.0")).unwrap(),
                DataPointRef::new("ferin:eu", "pack.mass-kg", Some("1.0.0")).unwrap(),
                DataPointRef::new("ferin:eu", "pack.soh-pct", Some("1.0.0")).unwrap(),
            ],
            crypto_suites: vec![SignatureSuite::EcdsaP256],
            confidential: false,
            resolution: Resolution::Public,
            edge_visibility: VisibilityClass::Blind,
            traversal: Traversal::RoleScoped,
        },
        bindings: vec![
            DataPointBinding {
                element: ENERGY_LABEL_ELEMENT.into(),
                source: f::ENERGY_LABEL.into(),
                min_trust: TrustMarker::Attested,
                min_capability: CapabilityClass::Silent,
                declared_unit: None,
            },
            DataPointBinding {
                element: PACK_CARBON_ELEMENT.into(),
                source: f::PACK_CARBON.into(),
                min_trust: TrustMarker::Attested,
                min_capability: CapabilityClass::Silent,
                declared_unit: Some("kgCO2e".into()),
            },
            DataPointBinding {
                element: PACK_MASS_ELEMENT.into(),
                source: f::PACK_MASS.into(),
                min_trust: TrustMarker::Attested,
                min_capability: CapabilityClass::Silent,
                declared_unit: Some("kg".into()),
            },
            DataPointBinding {
                element: PACK_SOH_ELEMENT.into(),
                source: f::PACK_SOH.into(),
                min_trust: TrustMarker::Attested,
                min_capability: CapabilityClass::Silent,
                declared_unit: Some("%".into()),
            },
        ],
        transforms: vec![
            // The carbon roll-up across the three packs, methodology
            // bound to ISO 14067 (never invented).
            TransformBinding::Aggregation {
                id: "carbon-rollup".into(),
                operation: AggregationOperation::Sum,
                input_element: PACK_CARBON_ELEMENT.into(),
                weight_element: None,
                method_citation: "ISO 14067:2018".into(),
            },
            // The mass-weighted average state of health: exact
            // division by construction of the fixture values.
            TransformBinding::Aggregation {
                id: "soh-weighted-average".into(),
                operation: AggregationOperation::WeightedAverage,
                input_element: PACK_SOH_ELEMENT.into(),
                weight_element: Some(PACK_MASS_ELEMENT.into()),
                method_citation: "IEC 62660-1:2018".into(),
            },
            // The system's EU class, localized to the JP star display
            // through the registered correspondence item (B -> four
            // stars; a class outside the band maps to `unmapped`).
            TransformBinding::LocalizationMapping {
                id: "jp-star-display".into(),
                source: f::ENERGY_LABEL.into(),
                mapping_ref: EU_CLASS_TO_JP_STAR_ID.into(),
            },
        ],
        presentation: None,
    };
    lens.validate().expect("pack lens validates");
    lens
}

/// The built-in EU class to JP star mapping, parsed from its wire
/// document (the fixture proves the schema end to end).
pub fn eu_class_to_jp_star_mapping() -> CodeListMapping {
    let doc: serde_json::Value =
        serde_json::from_str(EU_CLASS_TO_JP_STAR_MAPPING).expect("fixture mapping is valid JSON");
    CodeListMapping::from_json(&doc).expect("fixture mapping validates")
}

/// The reverse correspondence (JP stars back to EU classes), as its
/// own registered item — the round-trip fixture.
pub fn jp_star_to_eu_class_mapping() -> CodeListMapping {
    let mut reverse = eu_class_to_jp_star_mapping()
        .reversed()
        .expect("the fixture table is bijective");
    reverse.id = JP_STAR_TO_EU_CLASS_ID.to_string();
    reverse.validate().expect("reverse mapping validates");
    reverse
}

/// The built-in code-list mappings (fixtures mode).
pub fn fixture_mappings() -> MappingSet {
    let mut set = MappingSet::empty();
    set.insert(eu_class_to_jp_star_mapping(), "fixtures");
    set.insert(jp_star_to_eu_class_mapping(), "fixtures");
    set
}

/// One built-in child passport by id, when the fixture corpus holds
/// it (the pack children; the laptop's sodimm parts have no fixture
/// documents — an aggregation over them would report the documents as
/// unavailable, honestly).
pub fn fixture_child(passport_id: &str) -> Option<Passport> {
    let index = PACK_CHILD_IDS.iter().position(|id| *id == passport_id)?;
    Some(pack_child(index))
}

/// The child documents of a fixture parent (the pack system's three
/// packs; nothing for the demo laptop).
pub fn fixture_children_of(parent_id: &str) -> Vec<Passport> {
    match parent_id {
        PACK_SYSTEM_ID => pack_children(),
        _ => Vec::new(),
    }
}

/// A built-in lens by profile item id (the fixtures-mode registry).
pub fn fixture_lens(profile_id: &str) -> Option<LensManifest> {
    match profile_id {
        EU_LENS_ID => Some(eu_lens()),
        JP_LENS_ID => Some(jp_lens()),
        CONSUMER_LENS_ID => Some(consumer_lens()),
        CN_PROTOCOL_LENS_ID => Some(cn_protocol_lens()),
        PACK_LENS_ID => Some(pack_lens()),
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

/// The built-in Primmel package, parsed from its `.prml` wire
/// document (the fixture proves the schema end to end).
pub fn battery_rules_package() -> PrimmelPackage {
    let doc: serde_json::Value =
        serde_json::from_str(BATTERY_RULES_PRML).expect("fixture .prml is valid JSON");
    PrimmelPackage::from_json(&doc).expect("fixture .prml package validates")
}

/// The built-in Primmel packages (fixtures mode): the battery
/// decision-rule package, ready for the JP/EU lens bindings.
pub fn fixture_primmel() -> PackageSet {
    PackageSet::of(battery_rules_package(), "fixtures")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        // 8 core lifecycle events + the 3 CN protocol-check corrections.
        assert_eq!(p.log.len(), 11);
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

    #[test]
    fn fixture_primmel_package_parses_with_clause_urns() {
        let pkg = battery_rules_package();
        assert_eq!(pkg.id, BATTERY_RULES_PACKAGE_ID);
        assert_eq!(pkg.version, "1.0.0");
        let guard = pkg.rule(SOH_GUARD_BAND_RULE).unwrap();
        assert_eq!(guard.clause_urn, "urn:oiml:pub:r:91-2:2025#clause-6.1");
        let class = pkg.rule(EFFICIENCY_CLASS_RULE).unwrap();
        assert_eq!(class.clause_urn, "urn:eu:reg:2017:1369#annex-ii");
        for rule in &pkg.rules {
            assert!(rule.clause_urn.starts_with("urn:"), "{}", rule.clause_urn);
        }
        let set = fixture_primmel();
        let (got, source) = set.get(BATTERY_RULES_PACKAGE_ID).unwrap();
        assert_eq!(got.id, BATTERY_RULES_PACKAGE_ID);
        assert_eq!(source, "fixtures");
    }

    #[test]
    fn demo_passport_carries_the_battery_measurands() {
        // The guard-band and efficiency-class rules run on facts the
        // demo passport provides, from the attested milestone.
        let state = crate::twin::fold(&demo_passport(), demo_as_of());
        for path in [
            facts::SOH,
            facts::SOH_UNCERTAINTY,
            facts::ROUND_TRIP_EFFICIENCY,
        ] {
            let fact = state.get(path).unwrap();
            assert!(matches!(fact.value, unidpp_model::FactValue::Num(_)));
            assert_eq!(fact.origin.trust, TrustMarker::Attested);
        }
    }

    #[test]
    fn pack_corpus_is_deterministic_and_consistent() {
        // Structural determinism (the documents are built, never
        // minted against the wall clock).
        assert_eq!(pack_system(), pack_system());
        for i in 0..3 {
            assert_eq!(pack_child(i), pack_child(i));
        }
        let system = pack_system();
        system
            .log
            .verify()
            .expect("pack system hash chain verifies");
        for child in pack_children() {
            child.log.verify().expect("pack child hash chain verifies");
            let doc = child.to_json().unwrap();
            let back = Passport::from_json(&doc).unwrap();
            assert_eq!(back, child);
        }

        // The system's derived issuance names the three packs, each
        // input pinning the child's log head as-of the composition —
        // the traversal set the aggregation consumes.
        let state = crate::twin::fold(&system, demo_as_of());
        let active: Vec<&str> = state.children.iter().map(String::as_str).collect();
        assert_eq!(active, PACK_CHILD_IDS.to_vec());
        // Before the composition, no children.
        let before = ts("2027-01-05T12:00:00Z");
        assert!(crate::twin::fold(&system, before).children.is_empty());
        // The system's own fact: the EU energy-label class.
        assert_eq!(
            state.get(facts::ENERGY_LABEL).unwrap().value,
            unidpp_model::FactValue::Str("B".into())
        );
    }

    #[test]
    fn fixture_children_resolve_by_id() {
        assert_eq!(fixture_child(PACK_CHILD_IDS[1]).unwrap(), pack_child(1));
        assert!(fixture_child("urn:unidpp:passport:none").is_none());
        assert_eq!(fixture_children_of(PACK_SYSTEM_ID), pack_children());
        assert!(fixture_children_of(DEMO_PASSPORT_ID).is_empty());
    }

    #[test]
    fn code_list_fixture_round_trips_and_is_bijective() {
        let forward = eu_class_to_jp_star_mapping();
        assert_eq!(forward.id, EU_CLASS_TO_JP_STAR_ID);
        assert_eq!(forward.table.len(), 5);
        // B -> four stars.
        assert_eq!(forward.lookup("B").unwrap().target_value, "★★★★");
        // The A-E band maps onto the five-star display; values outside
        // the band are unmapped.
        assert!(forward.lookup("F").is_none());
        assert!(forward.lookup("G").is_none());
        // The reverse item is its own registered identity and round
        // trips the correspondence.
        let reverse = jp_star_to_eu_class_mapping();
        assert_eq!(reverse.id, JP_STAR_TO_EU_CLASS_ID);
        assert_eq!(reverse.lookup("★★★★").unwrap().target_value, "B");
        assert_eq!(reverse.lookup("★★★★★").unwrap().target_value, "A");
        // The fixture set holds both, sourced fixtures.
        let set = fixture_mappings();
        let (got, source) = set.get(EU_CLASS_TO_JP_STAR_ID).unwrap();
        assert_eq!(got.id, EU_CLASS_TO_JP_STAR_ID);
        assert_eq!(source, "fixtures");
        assert!(set.get(JP_STAR_TO_EU_CLASS_ID).is_some());
    }

    #[test]
    fn consumer_lens_presents_localized_sections() {
        let consumer = consumer_lens();
        let presentation = consumer.presentation.as_ref().unwrap();
        assert_eq!(presentation.template_ref, "urn:unidpp:template:consumer-v1");
        for section in &presentation.sections {
            assert!(section.labels.contains_key("en"));
            assert!(section.labels.contains_key("ja"));
            for element in &section.elements {
                assert!(element.labels.contains_key("en"));
                assert!(element.labels.contains_key("ja"));
            }
        }
        // The demo passport provides every presented element except
        // the recycling instruction — the render's coverage gap.
        let state = crate::twin::fold(&demo_passport(), demo_as_of());
        assert!(state.get(facts::RECYCLING_INSTRUCTION).is_none());
    }

    #[test]
    fn fixture_lenses_bind_primmel_rules() {
        // Both fixture lenses carry a Primmel binding; the two-lens
        // demo shows both rules live with clause-URN provenance.
        for lens in [eu_lens(), jp_lens()] {
            assert!(
                lens.transforms.iter().any(|t| !t.package_refs().is_empty()),
                "{} carries a primmel transform",
                lens.id().as_str()
            );
        }
        lens_primmel_evaluates();
    }

    /// The fixture package and lens bindings agree end to end: every
    /// bound rule exists and every rule input is bound.
    fn lens_primmel_evaluates() {
        let pkg = battery_rules_package();
        for lens in [eu_lens(), jp_lens()] {
            for t in &lens.transforms {
                let refs = t.package_refs();
                let Some(p) = refs.first() else {
                    continue;
                };
                assert_eq!(p, BATTERY_RULES_PACKAGE_ID);
                if let crate::lens::TransformBinding::Primmel {
                    rule_id, inputs, ..
                } = t
                {
                    let rule = pkg
                        .rule(rule_id)
                        .unwrap_or_else(|| panic!("rule {rule_id} exists in the package"));
                    for input in rule.inputs() {
                        assert!(inputs.contains_key(&input), "input {input} is bound");
                    }
                }
            }
        }
    }
    #[test]
    fn the_cn_protocol_lens_renders_the_regime_checks_in_chinese() {
        // TODO.impl 224: regulatory protocol conformance as named
        // data points (the MobileQR ProtocolChecks pattern) — rendered
        // through the same presentation machinery, labels served in
        // the requested language, the false check stated not omitted.
        let passport = demo_passport();
        let lens = cn_protocol_lens();
        let source = crate::project::ProfileSource::fallback("fixtures", None);
        let doc = crate::render::render(&passport, &lens, demo_as_of(), "zh", &source)
            .expect("the CN protocol lens renders");
        let sections = doc.pointer("/sections").unwrap().as_array().unwrap();
        assert_eq!(sections.len(), 1);
        let section = &sections[0];
        assert_eq!(section["label"], json!("监管协议核查"));
        let items = section["items"].as_array().unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0]["label"], json!("强制性产品认证（CCC）"));
        assert_eq!(items[0]["label_lang"], json!("zh"));
        assert_eq!(items[0]["formatted"], json!("true"));
        assert_eq!(items[1]["label"], json!("生产者法规"));
        assert_eq!(items[1]["formatted"], json!("true"));
        // The not-obtained licence: a stated false, never an omission.
        assert_eq!(items[2]["label"], json!("工业产品生产许可证"));
        assert_eq!(items[2]["formatted"], json!("false"));
        assert_eq!(doc.pointer("/coverage/complete").unwrap(), &json!(true));
        assert_eq!(doc.pointer("/coverage/elements_present").unwrap(), &json!(3));
        // Every serialization carries the regime: the HTML page names
        // the section, the text form speaks it.
        let page = crate::html::document(&doc);
        assert!(page.contains("监管协议核查"));
        assert!(page.contains("工业产品生产许可证"));
        let spoken = crate::html::text(&doc);
        assert!(spoken.contains("强制性产品认证（CCC）: true."));
        assert!(spoken.contains("工业产品生产许可证: false."));
    }
}
