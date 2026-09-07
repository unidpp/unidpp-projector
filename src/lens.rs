//! The lens projection model: what a registered profile item carries
//! beyond the core [`ProfileManifest`] so the projector can *render*
//! a view — the data-point bindings and the transform bindings.
//!
//! A registry profile item's `manifest` slot (seam S4: version-pinned
//! to the item) is a JSON document of this shape:
//!
//! ```json
//! {
//!   "version": "1.0.0",
//!   "profile": { "id": "urn:unidpp:profile:eu-espr-electronics", "...": "core ProfileManifest" },
//!   "bindings": [
//!     { "element": "ferin:eu/de.dpp.operator-id@1.0.0",
//!       "source": "de.dpp.operator-id",
//!       "min_trust": "attested", "min_capability": "silent" }
//!   ],
//!   "transforms": [
//!     { "kind": "unit-conversion", "id": "capacity-mj",
//!       "source": "battery.capacity-kwh",
//!       "from_unit": "kWh", "to_unit": "MJ",
//!       "from_item": "unit-kwh", "to_item": "unit-mj" },
//!     { "kind": "classification", "id": "eu-reparability-class",
//!       "source": "de.dpp.reparability-score",
//!       "bands": [ { "label": "A", "min": "8.0" } ] }
//!   ]
//! }
//! ```
//!
//! Division of semantics (model-driven): the core manifest states
//! *what the lens requires* (data points, capability floor, freshness,
//! posture); the bindings state *where each element's value lives on
//! the twin state and which provenance/capability it must clear*; the
//! transforms state *how derived values are produced* (registered
//! units, classification tables). The projector executes the manifest
//! — it never hardcodes a jurisdiction.

use serde_json::{json, Value};

use unidpp_model::{CapabilityClass, Decimal, ProfileId, ProfileManifest, TrustMarker};

/// Default provenance floor when a binding states none: no floor.
fn no_trust_floor() -> TrustMarker {
    TrustMarker::Unsigned
}

/// Default capability gate when a binding states none: no gate.
fn no_capability_gate() -> CapabilityClass {
    CapabilityClass::Silent
}

/// One data-point binding: how a required element is selected from
/// the twin state.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DataPointBinding {
    /// The required element, as the canonical `register/item@version`
    /// string of one of the profile's `data_points`.
    pub element: String,
    /// The twin-state fact path holding the element's value.
    pub source: String,
    /// Provenance filter: the sourcing event's trust marker must
    /// meet or exceed this grade (I9 ladder), else the element is
    /// excluded and reported.
    #[serde(default = "no_trust_floor")]
    pub min_trust: TrustMarker,
    /// Capability gate: the subject's capability class must meet or
    /// exceed this floor, else the element is blocked and reported.
    #[serde(default = "no_capability_gate")]
    pub min_capability: CapabilityClass,
    /// Display-only declared unit for the value (e.g. `kgCO2e`):
    /// carries no conversion claim — conversions are transforms.
    #[serde(default)]
    pub declared_unit: Option<String>,
}

/// One classification band: `label` applies when the input value is
/// `>= min`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClassBand {
    pub label: String,
    pub min: Decimal,
}

/// A transform binding: how one derived value is produced.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TransformBinding {
    /// Exact unit conversion through the ISO 80000 unit registry
    /// (e.g. kWh -> MJ, x 3.6 exactly). `from_item`/`to_item`
    /// optionally name registry unit items, binding the conversion's
    /// unit identity to the registered citation chain.
    UnitConversion {
        id: String,
        source: String,
        from_unit: String,
        to_unit: String,
        #[serde(default)]
        from_item: Option<String>,
        #[serde(default)]
        to_item: Option<String>,
    },
    /// Band classification: the manifest's own table, applied to a
    /// numeric fact; the highest band whose `min` the value meets
    /// wins; below the lowest band the value is `unclassified`
    /// (explicit, never silent).
    Classification {
        id: String,
        source: String,
        bands: Vec<ClassBand>,
    },
}

impl TransformBinding {
    /// The transform's identity within the lens.
    pub fn id(&self) -> &str {
        match self {
            TransformBinding::UnitConversion { id, .. } => id,
            TransformBinding::Classification { id, .. } => id,
        }
    }

    /// The twin-state fact path the transform reads.
    pub fn source(&self) -> &str {
        match self {
            TransformBinding::UnitConversion { source, .. } => source,
            TransformBinding::Classification { source, .. } => source,
        }
    }

    /// Registry unit items this transform references (for identity
    /// resolution), in encounter order.
    pub fn unit_items(&self) -> Vec<String> {
        match self {
            TransformBinding::UnitConversion {
                from_item, to_item, ..
            } => [from_item.clone(), to_item.clone()]
                .into_iter()
                .flatten()
                .collect(),
            TransformBinding::Classification { .. } => Vec::new(),
        }
    }
}

/// The lens manifest: core profile + projection bindings.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LensManifest {
    /// Manifest version — pinned to a registered version of the
    /// profile item (the registry enforces the pin on write).
    pub version: String,
    /// The core profile manifest (axes, trigger, capability floor,
    /// freshness, data points, suites, posture).
    pub profile: ProfileManifest,
    /// One binding per required data point.
    #[serde(default)]
    pub bindings: Vec<DataPointBinding>,
    /// Derived values, in manifest order.
    #[serde(default)]
    pub transforms: Vec<TransformBinding>,
}

impl LensManifest {
    /// Parse a lens manifest from a registry item's `manifest` slot.
    /// The item document is the full registry item view; its
    /// `manifest` object must be present and version-pinned.
    pub fn from_item(item: &Value) -> Result<LensManifest, String> {
        let class = item.get("item_class").and_then(Value::as_str);
        if class.is_some() && class != Some("profile") {
            return Err(format!(
                "item `{}` is not a profile item (class `{}`)",
                item.get("identifier")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                class.unwrap_or("?")
            ));
        }
        let manifest = item
            .get("manifest")
            .filter(|m| m.is_object())
            .ok_or_else(|| {
                format!(
                    "profile item `{}` carries no manifest",
                    item.get("identifier")
                        .and_then(Value::as_str)
                        .unwrap_or("?")
                )
            })?;
        let lens: LensManifest = serde_json::from_value(manifest.clone())
            .map_err(|e| format!("lens manifest does not parse: {e}"))?;
        lens.validate()?;
        Ok(lens)
    }

    /// Structural validation: the core manifest's rules, every
    /// required element bound exactly once (no orphans, no extras),
    /// transform ids unique, and classification tables well-formed.
    pub fn validate(&self) -> Result<(), String> {
        self.profile.validate().map_err(|e| e.to_string())?;
        let required: Vec<String> = self
            .profile
            .data_points
            .iter()
            .map(|dp| dp.to_string())
            .collect();
        let mut bound: Vec<&str> = Vec::with_capacity(self.bindings.len());
        for b in &self.bindings {
            if !required.iter().any(|r| r == &b.element) {
                return Err(format!(
                    "binding element `{}` is not a data point of profile {}",
                    b.element, self.profile.id
                ));
            }
            if bound.contains(&b.element.as_str()) {
                return Err(format!(
                    "element `{}` is bound more than once in profile {}",
                    b.element, self.profile.id
                ));
            }
            if b.source.trim().is_empty() {
                return Err(format!(
                    "binding for `{}` has an empty source fact path",
                    b.element
                ));
            }
            bound.push(&b.element);
        }
        for r in &required {
            if !bound.contains(&r.as_str()) {
                return Err(format!(
                    "data point `{r}` of profile {} has no binding",
                    self.profile.id
                ));
            }
        }
        let mut ids: Vec<&str> = Vec::with_capacity(self.transforms.len());
        for t in &self.transforms {
            if ids.contains(&t.id()) {
                return Err(format!("duplicate transform id `{}`", t.id()));
            }
            if t.source().trim().is_empty() {
                return Err(format!(
                    "transform `{}` has an empty source fact path",
                    t.id()
                ));
            }
            if let TransformBinding::Classification { bands, .. } = t {
                if bands.is_empty() {
                    return Err(format!("classification `{}` has no bands", t.id()));
                }
                for band in bands {
                    if band.label.trim().is_empty() {
                        return Err(format!(
                            "classification `{}` has an empty band label",
                            t.id()
                        ));
                    }
                }
            }
            ids.push(t.id());
        }
        if self.version.trim().is_empty() {
            return Err(format!(
                "profile {} manifest lacks a version pin",
                self.profile.id
            ));
        }
        Ok(())
    }

    /// The manifest slot (for registering this lens as a profile
    /// item with the registry).
    pub fn manifest_json(&self) -> Value {
        serde_json::to_value(self).expect("lens manifest serializes")
    }

    /// The `POST /profiles` body registering this lens as a profile
    /// item (used by tests and tooling; production registration goes
    /// through the issuer's admin surface).
    pub fn registration_body(&self, register_id: &str, definition: &str) -> Value {
        json!({
            "register_id": register_id,
            "item_id": self.profile.id.as_str(),
            "class": "profile",
            "definition": definition,
            "version": self.version,
            "effective_from": self.profile.effective.from.to_string(),
            "manifest": self.manifest_json(),
        })
    }

    /// The lens identity.
    pub fn id(&self) -> &ProfileId {
        &self.profile.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use unidpp_model::{
        DataPointRef, FreshnessRequirement, Interval, ProfileAxes, Resolution, SignatureSuite,
        Timestamp, Traversal, TriggerPredicate, VisibilityClass,
    };

    fn minimal_lens() -> LensManifest {
        LensManifest {
            version: "1.0.0".into(),
            profile: ProfileManifest {
                id: ProfileId::new("urn:unidpp:profile:test-min").unwrap(),
                axes: ProfileAxes::jurisdiction("EU"),
                trigger: TriggerPredicate::Any,
                min_capability: CapabilityClass::Silent,
                freshness: FreshnessRequirement::Static,
                effective: Interval::starting(Timestamp::from_secs(0)),
                data_points: vec![DataPointRef::new("ferin:eu", "a", Some("1")).unwrap()],
                crypto_suites: vec![SignatureSuite::EcdsaP256],
                confidential: false,
                resolution: Resolution::Public,
                edge_visibility: VisibilityClass::Public,
                traversal: Traversal::Public,
            },
            bindings: vec![DataPointBinding {
                element: "ferin:eu/a@1".into(),
                source: "fact.a".into(),
                min_trust: TrustMarker::Unsigned,
                min_capability: CapabilityClass::Silent,
                declared_unit: None,
            }],
            transforms: vec![],
        }
    }

    #[test]
    fn serde_round_trip_with_defaults() {
        // Binding without min_trust/min_capability defaults to no
        // floor / no gate.
        let raw = json!({
            "element": "ferin:eu/a@1",
            "source": "fact.a"
        });
        let binding: DataPointBinding = serde_json::from_value(raw).unwrap();
        assert_eq!(binding.min_trust, TrustMarker::Unsigned);
        assert_eq!(binding.min_capability, CapabilityClass::Silent);
        let back = serde_json::to_value(&binding).unwrap();
        assert_eq!(
            back.get("min_trust").and_then(Value::as_str),
            Some("unsigned")
        );

        let lens = fixtures::eu_lens();
        let value = lens.manifest_json();
        let parsed: LensManifest = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, lens);
    }

    #[test]
    fn transform_tagging_and_unit_items() {
        let jp = fixtures::jp_lens();
        let conv = jp
            .transforms
            .iter()
            .find(|t| t.id() == "capacity-mj")
            .unwrap();
        match conv {
            TransformBinding::UnitConversion { .. } => {}
            other => panic!("expected unit conversion, got {other:?}"),
        }
        assert_eq!(conv.unit_items(), vec!["unit-kwh", "unit-mj"]);
        let class = jp
            .transforms
            .iter()
            .find(|t| t.id() == "jp-reparability-class")
            .unwrap();
        assert!(class.unit_items().is_empty());
        // Wire tag is kebab-case `kind`.
        let raw = json!({
            "kind": "unit-conversion",
            "id": "c",
            "source": "s",
            "from_unit": "kWh",
            "to_unit": "MJ"
        });
        let t: TransformBinding = serde_json::from_value(raw).unwrap();
        assert!(matches!(t, TransformBinding::UnitConversion { .. }));
    }

    #[test]
    fn validate_rejects_unbound_data_point() {
        let mut lens = minimal_lens();
        lens.bindings.clear();
        let err = lens.validate().unwrap_err();
        assert!(err.contains("has no binding"), "{err}");
    }

    #[test]
    fn validate_rejects_orphan_and_duplicate_bindings() {
        let mut lens = minimal_lens();
        lens.bindings.push(DataPointBinding {
            element: "ferin:eu/ghost@9".into(),
            source: "fact.ghost".into(),
            min_trust: TrustMarker::Unsigned,
            min_capability: CapabilityClass::Silent,
            declared_unit: None,
        });
        let err = lens.validate().unwrap_err();
        assert!(err.contains("not a data point"), "{err}");

        let mut lens = minimal_lens();
        lens.bindings.push(lens.bindings[0].clone());
        let err = lens.validate().unwrap_err();
        assert!(err.contains("bound more than once"), "{err}");
    }

    #[test]
    fn validate_rejects_duplicate_transform_ids_and_bad_tables() {
        let mut lens = minimal_lens();
        lens.transforms = vec![
            TransformBinding::Classification {
                id: "dup".into(),
                source: "fact.a".into(),
                bands: vec![ClassBand {
                    label: "A".into(),
                    min: "1".parse().unwrap(),
                }],
            },
            TransformBinding::Classification {
                id: "dup".into(),
                source: "fact.a".into(),
                bands: vec![],
            },
        ];
        let err = lens.validate().unwrap_err();
        assert!(err.contains("duplicate transform id"), "{err}");

        lens.transforms.truncate(1);
        lens.transforms[0] = TransformBinding::Classification {
            id: "ok-id".into(),
            source: "fact.a".into(),
            bands: vec![],
        };
        let err = lens.validate().unwrap_err();
        assert!(err.contains("no bands"), "{err}");
    }

    #[test]
    fn from_item_requires_manifest_and_profile_class() {
        let lens = fixtures::eu_lens();
        let mut item = json!({
            "identifier": "urn:unidpp:profile:eu-espr-electronics",
            "item_class": "profile",
            "manifest": lens.manifest_json(),
        });
        assert!(LensManifest::from_item(&item).is_ok());

        item.as_object_mut().unwrap().remove("manifest");
        let err = LensManifest::from_item(&item).unwrap_err();
        assert!(err.contains("carries no manifest"), "{err}");

        let unit_item = json!({"identifier": "unit-kwh", "item_class": "unit"});
        let err = LensManifest::from_item(&unit_item).unwrap_err();
        assert!(err.contains("not a profile item"), "{err}");
    }

    #[test]
    fn registration_body_pins_the_manifest_version() {
        let lens = fixtures::jp_lens();
        let body = lens.registration_body("ferin:jp", "JP METI PSE lens");
        assert_eq!(
            body.get("item_id").and_then(Value::as_str),
            Some("urn:unidpp:profile:jp-meti-pse")
        );
        assert_eq!(body.get("version").and_then(Value::as_str), Some("1.0.0"));
        let manifest = body.get("manifest").unwrap();
        assert_eq!(
            manifest.get("version").and_then(Value::as_str),
            Some("1.0.0")
        );
    }

    #[test]
    fn fixture_lenses_validate() {
        fixtures::eu_lens().validate().unwrap();
        fixtures::jp_lens().validate().unwrap();
        assert_eq!(
            fixtures::eu_lens().id().as_str(),
            "urn:unidpp:profile:eu-espr-electronics"
        );
        assert!(fixtures::fixture_lens("urn:unidpp:profile:nope").is_none());
        assert!(fixtures::fixture_lens("urn:unidpp:profile:eu-espr-electronics").is_some());
    }
}
