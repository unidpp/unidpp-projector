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
//!       "bands": [ { "label": "A", "min": "8.0" } ] },
//!     { "kind": "primmel", "id": "jp-soh-guard-band",
//!       "package_ref": "urn:primmel:pkg:battery-rules",
//!       "rule_id": "soh-guard-band",
//!       "inputs": { "soh": "battery.soh-pct", "U": "battery.soh-u-pct" } },
//!     { "kind": "aggregation", "id": "carbon-rollup",
//!       "operation": "sum",
//!       "input_element": "ferin:eu/de.dpp.carbon-footprint@1.2.0",
//!       "method_citation": "ISO 14067:2018" },
//!     { "kind": "localization-mapping", "id": "jp-star-display",
//!       "source": "de.dpp.energy-label-class",
//!       "mapping_ref": "urn:unidpp:mapping:eu-class-to-jp-star" }
//!   ],
//!   "presentation": {
//!     "template_ref": "urn:unidpp:template:consumer-v1",
//!     "formatting": { "unit_position": "suffix", "decimal_digits": 1,
//!                     "fallback_lang": "en" },
//!     "sections": [
//!       { "id": "product", "labels": { "en": "Product", "ja": "製品情報" },
//!         "elements": [
//!           { "element": "ferin:eu/de.dpp.operator-id@1.0.0",
//!             "labels": { "en": "Operator", "ja": "事業者ID" } }
//!         ] }
//!     ]
//!   }
//! }
//! ```
//!
//! Division of semantics (model-driven): the core manifest states
//! *what the lens requires* (data points, capability floor, freshness,
//! posture); the bindings state *where each element's value lives on
//! the twin state and which provenance/capability it must clear*; the
//! transforms state *how derived values are produced* (registered
//! units, classification tables, and Primmel decision rules — each
//! carrying the clause URN of the legal paragraph it implements). The
//! projector executes the manifest — it never hardcodes a
//! jurisdiction.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use unidpp_model::{CapabilityClass, Decimal, ProfileId, ProfileManifest, TrustMarker};

use crate::aggregate::AggregationOperation;

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

/// Where the declared unit renders relative to the formatted value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitPosition {
    /// After the value, separated by a space (`96.4 kgCO2e`) — the
    /// ISO 80000 style.
    Suffix,
    /// The unit is not rendered (the raw `value` field still carries
    /// it structurally).
    None,
}

fn unit_suffix() -> UnitPosition {
    UnitPosition::Suffix
}

fn one_digit() -> u8 {
    1
}

fn fallback_en() -> String {
    "en".to_string()
}

/// Display formatting rules of a presentation (TODO.impl 54): how
/// selected values become consumer-facing strings. Display-only —
/// the exact value always travels in the render item's `value` field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FormattingRules {
    /// Where the declared unit renders.
    #[serde(default = "unit_suffix")]
    pub unit_position: UnitPosition,
    /// Digits kept after the decimal point in the formatted string
    /// (explicit display rounding; the exact value is untouched).
    #[serde(default = "one_digit")]
    pub decimal_digits: u8,
    /// Language tag consulted when the requested language has no
    /// label for a section or element (the missing-label fallback).
    #[serde(default = "fallback_en")]
    pub fallback_lang: String,
}

impl Default for FormattingRules {
    fn default() -> FormattingRules {
        FormattingRules {
            unit_position: unit_suffix(),
            decimal_digits: one_digit(),
            fallback_lang: fallback_en(),
        }
    }
}

/// One presented data point with its per-language labels.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PresentationElement {
    /// The data point presented (`register/item@version` — must be a
    /// data point of this profile).
    pub element: String,
    /// Labels per language tag (`en`, `ja`, …).
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// One presentation section: a titled group of data points.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PresentationSection {
    /// Section id (`product`, `repair`, `recycling`, …).
    pub id: String,
    /// Section labels per language tag.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// The presented data points, in display order.
    pub elements: Vec<PresentationElement>,
}

/// The presentation binding (TODO.impl 54): how a lens renders for
/// consumers — sections of data points with per-language labels and
/// display formatting. A first-class part of the manifest model; the
/// `/render` surface consumes it, the `/view` surface ignores it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PresentationBinding {
    /// The registered template this presentation instantiates
    /// (rendered as `template_ref` in the render metadata).
    pub template_ref: String,
    /// Display formatting rules.
    #[serde(default)]
    pub formatting: FormattingRules,
    /// Sections in display order.
    pub sections: Vec<PresentationSection>,
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
    /// A Primmel decision rule (deterministic, clause-URN-provenant):
    /// the projector resolves `package_ref` against the packages it
    /// holds (operator-pinned directory, registry transform items, or
    /// the built-in fixtures) and evaluates `rule_id` over the named
    /// inputs — the output carries the rule's `clause_urn`, the legal
    /// paragraph the decision implements. Input *names* are the
    /// rule's own; the binding maps them to twin fact paths, so one
    /// package serves many lenses without naming any twin.
    Primmel {
        id: String,
        /// The package URN the rule lives in.
        package_ref: String,
        /// The rule id within the package.
        rule_id: String,
        /// Rule input name → twin-state fact path.
        inputs: BTreeMap<String, String>,
    },
    /// Aggregation (TODO.impl 66): a cross-child roll-up over the
    /// subject's active traversal set, methodology-bound — the method
    /// standard is cited, never invented. The projector selects the
    /// input element's value from each child passport (the profile's
    /// own binding for that element supplies the fact path and the
    /// selection gates), applies the operation exactly, and emits the
    /// aggregated output with the `method_citation` provenance and the
    /// committed child set's root hash.
    Aggregation {
        id: String,
        /// The roll-up operation.
        operation: AggregationOperation,
        /// The element whose *selected value* is fetched from every
        /// child (a data point of this profile).
        input_element: String,
        /// The element weighting each child — weighted-average only.
        #[serde(default)]
        weight_element: Option<String>,
        /// The method standard the roll-up follows (`ISO 14067:2018`).
        method_citation: String,
    },
    /// Localization mapping (TODO.impl 67): translate a code value
    /// through a registered code-list correspondence item (waste
    /// codes, HS/TARIC vs national, EU A–G vs JP star display). The
    /// projector looks the input value up in the mapping item's table
    /// and emits the target value — a value with no correspondence is
    /// reported `unmapped`, never silently passed through.
    LocalizationMapping {
        id: String,
        /// Twin-state fact path holding the source-scheme code value.
        source: String,
        /// The registered mapping item (transforms subregister).
        mapping_ref: String,
    },
}

impl TransformBinding {
    /// The transform's identity within the lens.
    pub fn id(&self) -> &str {
        match self {
            TransformBinding::UnitConversion { id, .. } => id,
            TransformBinding::Classification { id, .. } => id,
            TransformBinding::Primmel { id, .. } => id,
            TransformBinding::Aggregation { id, .. } => id,
            TransformBinding::LocalizationMapping { id, .. } => id,
        }
    }

    /// The twin-state fact path the transform reads (for a Primmel
    /// binding: the first input's path in input-name order —
    /// deterministic, informational; the full map is `inputs`).
    pub fn source(&self) -> &str {
        match self {
            TransformBinding::UnitConversion { source, .. } => source,
            TransformBinding::Classification { source, .. } => source,
            TransformBinding::Primmel { inputs, .. } => {
                inputs.values().next().map(String::as_str).unwrap_or("")
            }
            // The aggregation input lives on the children, not the
            // subject — the transform entry renders `input_element`.
            TransformBinding::Aggregation { .. } => "",
            TransformBinding::LocalizationMapping { source, .. } => source,
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
            TransformBinding::Classification { .. }
            | TransformBinding::Primmel { .. }
            | TransformBinding::Aggregation { .. }
            | TransformBinding::LocalizationMapping { .. } => Vec::new(),
        }
    }

    /// The Primmel package this transform binds, when it is a Primmel
    /// binding (for package resolution), in encounter order.
    pub fn package_refs(&self) -> Vec<String> {
        match self {
            TransformBinding::Primmel { package_ref, .. } => vec![package_ref.clone()],
            _ => Vec::new(),
        }
    }

    /// The registered code-list mapping items this transform
    /// references (for mapping resolution), in encounter order.
    pub fn mapping_refs(&self) -> Vec<String> {
        match self {
            TransformBinding::LocalizationMapping { mapping_ref, .. } => {
                vec![mapping_ref.clone()]
            }
            _ => Vec::new(),
        }
    }

    /// The aggregation binding's data points (input, weight), in
    /// declaration order — empty for the other classes.
    pub fn aggregation_elements(&self) -> Vec<&str> {
        match self {
            TransformBinding::Aggregation {
                input_element,
                weight_element,
                ..
            } => {
                let mut elements = vec![input_element.as_str()];
                if let Some(w) = weight_element {
                    elements.push(w.as_str());
                }
                elements
            }
            _ => Vec::new(),
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
    /// The presentation binding (TODO.impl 54) — how the lens renders
    /// for consumers. `None` on view-only lenses (`/render` refuses
    /// them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation: Option<PresentationBinding>,
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
            if let TransformBinding::Primmel {
                package_ref,
                rule_id,
                inputs,
                ..
            } = t
            {
                // Primmel bindings validate their own input map (the
                // generic source check below would fire first on the
                // empty map with a less specific message).
                if package_ref.trim().is_empty() {
                    return Err(format!("primmel transform `{}` names no package", t.id()));
                }
                if rule_id.trim().is_empty() {
                    return Err(format!(
                        "primmel transform `{}` names no rule of package `{package_ref}`",
                        t.id()
                    ));
                }
                if inputs.is_empty() {
                    return Err(format!(
                        "primmel transform `{}` binds no inputs (rule `{}` \
                         of package `{package_ref}` needs at least one)",
                        t.id(),
                        rule_id
                    ));
                }
                for (name, path) in inputs {
                    if name.trim().is_empty() || path.trim().is_empty() {
                        return Err(format!(
                            "primmel transform `{}` has an empty input \
                             binding (`{name}` -> `{path}`)",
                            t.id()
                        ));
                    }
                }
            } else if let TransformBinding::Aggregation {
                operation,
                input_element,
                weight_element,
                method_citation,
                ..
            } = t
            {
                // Aggregation bindings validate their own shape (the
                // generic source check does not apply: the input lives
                // on the children, and the binding is validated against
                // the profile's data points).
                if method_citation.trim().is_empty() {
                    return Err(format!(
                        "aggregation `{}` cites no method standard — a \
                         roll-up never invents its methodology",
                        t.id()
                    ));
                }
                if !required.iter().any(|r| r == input_element) {
                    return Err(format!(
                        "aggregation `{}` input element `{}` is not a data \
                         point of profile {}",
                        t.id(),
                        input_element,
                        self.profile.id
                    ));
                }
                match (operation, weight_element) {
                    (AggregationOperation::WeightedAverage, None) => {
                        return Err(format!(
                            "aggregation `{}` is a weighted average without a \
                             weight element",
                            t.id()
                        ));
                    }
                    (AggregationOperation::WeightedAverage, Some(w)) => {
                        if !required.iter().any(|r| r == w) {
                            return Err(format!(
                                "aggregation `{}` weight element `{}` is not \
                                 a data point of profile {}",
                                t.id(),
                                w,
                                self.profile.id
                            ));
                        }
                        if w == input_element {
                            return Err(format!(
                                "aggregation `{}` weights the roll-up with its \
                                 own input element `{}`",
                                t.id(),
                                input_element
                            ));
                        }
                    }
                    (_, Some(_)) => {
                        return Err(format!(
                            "aggregation `{}` names a weight element but is a \
                             `{}` — weights apply to weighted-average only",
                            t.id(),
                            operation
                        ));
                    }
                    (_, None) => {}
                }
            } else if let TransformBinding::LocalizationMapping { mapping_ref, .. } = t {
                if mapping_ref.trim().is_empty() {
                    return Err(format!(
                        "localization mapping `{}` names no registered mapping \
                         item",
                        t.id()
                    ));
                }
                if t.source().trim().is_empty() {
                    return Err(format!(
                        "transform `{}` has an empty source fact path",
                        t.id()
                    ));
                }
            } else if t.source().trim().is_empty() {
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
        if let Some(presentation) = &self.presentation {
            if presentation.template_ref.trim().is_empty() {
                return Err(format!(
                    "profile {} presentation names no template",
                    self.profile.id
                ));
            }
            if presentation.formatting.decimal_digits > 18 {
                return Err(format!(
                    "profile {} presentation formats to {} decimal digits \
                     (max 18)",
                    self.profile.id, presentation.formatting.decimal_digits
                ));
            }
            if presentation.sections.is_empty() {
                return Err(format!(
                    "profile {} presentation has no sections",
                    self.profile.id
                ));
            }
            let mut section_ids: Vec<&str> = Vec::with_capacity(presentation.sections.len());
            let mut presented: Vec<&str> = Vec::new();
            for section in &presentation.sections {
                if section.id.trim().is_empty() {
                    return Err(format!(
                        "profile {} presentation has a section without an id",
                        self.profile.id
                    ));
                }
                if section_ids.contains(&section.id.as_str()) {
                    return Err(format!(
                        "duplicate presentation section `{}` in profile {}",
                        section.id, self.profile.id
                    ));
                }
                section_ids.push(&section.id);
                if section.elements.is_empty() {
                    return Err(format!(
                        "presentation section `{}` of profile {} presents no \
                         elements",
                        section.id, self.profile.id
                    ));
                }
                for label in section.labels.values() {
                    if label.trim().is_empty() {
                        return Err(format!(
                            "presentation section `{}` of profile {} has an \
                             empty label",
                            section.id, self.profile.id
                        ));
                    }
                }
                for element in &section.elements {
                    if !required.iter().any(|r| r == &element.element) {
                        return Err(format!(
                            "presentation section `{}` presents `{}` which is \
                             not a data point of profile {}",
                            section.id, element.element, self.profile.id
                        ));
                    }
                    if presented.contains(&element.element.as_str()) {
                        return Err(format!(
                            "element `{}` is presented in more than one place \
                             by profile {}",
                            element.element, self.profile.id
                        ));
                    }
                    presented.push(&element.element);
                    for label in element.labels.values() {
                        if label.trim().is_empty() {
                            return Err(format!(
                                "presentation of `{}` in profile {} has an \
                                 empty label",
                                element.element, self.profile.id
                            ));
                        }
                    }
                }
            }
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

    /// The binding of one data point, when the lens binds it (after
    /// `validate()`, every data point has exactly one).
    pub fn binding_for(&self, element: &str) -> Option<&DataPointBinding> {
        self.bindings.iter().find(|b| b.element == element)
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
            presentation: None,
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
    fn primmel_bindings_parse_and_validate() {
        // Wire tag is kebab-case `kind`; inputs map rule names to twin
        // fact paths.
        let raw = json!({
            "kind": "primmel",
            "id": "jp-soh-guard-band",
            "package_ref": "urn:primmel:pkg:battery-rules",
            "rule_id": "soh-guard-band",
            "inputs": { "soh": "battery.soh-pct", "U": "battery.soh-u-pct" }
        });
        let t: TransformBinding = serde_json::from_value(raw).unwrap();
        match &t {
            TransformBinding::Primmel {
                package_ref,
                rule_id,
                inputs,
                ..
            } => {
                assert_eq!(package_ref, "urn:primmel:pkg:battery-rules");
                assert_eq!(rule_id, "soh-guard-band");
                assert_eq!(inputs.len(), 2);
                assert_eq!(inputs["soh"], "battery.soh-pct");
            }
            other => panic!("expected primmel binding, got {other:?}"),
        }
        assert_eq!(t.unit_items(), Vec::<String>::new());
        assert_eq!(t.package_refs(), vec!["urn:primmel:pkg:battery-rules"]);
        // Round trip through the typed model.
        let back: TransformBinding =
            serde_json::from_value(serde_json::to_value(&t).unwrap()).unwrap();
        assert_eq!(back, t);

        // The fixture JP lens carries the guard-band binding and
        // validates.
        let jp = fixtures::jp_lens();
        let primmel = jp
            .transforms
            .iter()
            .find(|t| t.id() == "jp-soh-guard-band")
            .unwrap();
        assert_eq!(
            primmel.package_refs(),
            vec![fixtures::BATTERY_RULES_PACKAGE_ID.to_string()]
        );
        jp.validate().unwrap();

        // Validation refuses the degenerate shapes.
        let mut lens = minimal_lens();
        lens.transforms = vec![TransformBinding::Primmel {
            id: "p".into(),
            package_ref: " ".into(),
            rule_id: "r".into(),
            inputs: [("a".to_string(), "fact.a".to_string())]
                .into_iter()
                .collect(),
        }];
        assert!(lens.validate().unwrap_err().contains("names no package"));

        lens.transforms = vec![TransformBinding::Primmel {
            id: "p".into(),
            package_ref: "urn:primmel:pkg:x".into(),
            rule_id: "r".into(),
            inputs: BTreeMap::new(),
        }];
        assert!(lens.validate().unwrap_err().contains("binds no inputs"));

        lens.transforms = vec![TransformBinding::Primmel {
            id: "p".into(),
            package_ref: "urn:primmel:pkg:x".into(),
            rule_id: "r".into(),
            inputs: [("a".to_string(), " ".to_string())].into_iter().collect(),
        }];
        assert!(lens.validate().unwrap_err().contains("empty input binding"));
    }

    #[test]
    fn aggregation_bindings_parse_and_validate() {
        // Wire tags are kebab-case like every transform class.
        let raw = json!({
            "kind": "aggregation",
            "id": "carbon-rollup",
            "operation": "weighted-average",
            "input_element": "ferin:eu/a@1",
            "weight_element": "ferin:eu/w@1",
            "method_citation": "ISO 14067:2018"
        });
        let t: TransformBinding = serde_json::from_value(raw).unwrap();
        match &t {
            TransformBinding::Aggregation {
                operation,
                input_element,
                weight_element,
                method_citation,
                ..
            } => {
                assert_eq!(*operation, AggregationOperation::WeightedAverage);
                assert_eq!(input_element, "ferin:eu/a@1");
                assert_eq!(weight_element.as_deref(), Some("ferin:eu/w@1"));
                assert_eq!(method_citation, "ISO 14067:2018");
            }
            other => panic!("expected aggregation binding, got {other:?}"),
        }
        // Round trip through the typed model.
        let back: TransformBinding =
            serde_json::from_value(serde_json::to_value(&t).unwrap()).unwrap();
        assert_eq!(back, t);
        assert_eq!(t.unit_items(), Vec::<String>::new());
        assert!(t.package_refs().is_empty());
        assert!(t.mapping_refs().is_empty());
        assert_eq!(t.source(), "");
        assert_eq!(
            t.aggregation_elements(),
            vec!["ferin:eu/a@1", "ferin:eu/w@1"]
        );

        // The wire tokens cover every operation.
        for (wire, expected) in [
            ("sum", AggregationOperation::Sum),
            ("weighted-average", AggregationOperation::WeightedAverage),
            ("count", AggregationOperation::Count),
        ] {
            let t: TransformBinding = serde_json::from_value(json!({
                "kind": "aggregation", "id": "x", "operation": wire,
                "input_element": "ferin:eu/a@1",
                "method_citation": "ISO 14067:2018"
            }))
            .unwrap();
            assert!(matches!(
                t,
                TransformBinding::Aggregation { operation, .. } if operation == expected
            ));
        }
    }

    #[test]
    fn aggregation_validation_is_methodology_bound() {
        let mut lens = minimal_lens();
        lens.profile
            .data_points
            .push(DataPointRef::new("ferin:eu", "w", Some("1")).unwrap());
        lens.bindings.push(DataPointBinding {
            element: "ferin:eu/w@1".into(),
            source: "fact.w".into(),
            min_trust: TrustMarker::Unsigned,
            min_capability: CapabilityClass::Silent,
            declared_unit: None,
        });
        let cases: Vec<(TransformBinding, &str)> = vec![
            // No citation: a roll-up never invents its methodology.
            (
                TransformBinding::Aggregation {
                    id: "a".into(),
                    operation: AggregationOperation::Sum,
                    input_element: "ferin:eu/a@1".into(),
                    weight_element: None,
                    method_citation: " ".into(),
                },
                "cites no method standard",
            ),
            // Input element outside the profile.
            (
                TransformBinding::Aggregation {
                    id: "a".into(),
                    operation: AggregationOperation::Sum,
                    input_element: "ferin:eu/ghost@1".into(),
                    weight_element: None,
                    method_citation: "ISO 14067:2018".into(),
                },
                "is not a data point",
            ),
            // Weighted average without a weight.
            (
                TransformBinding::Aggregation {
                    id: "a".into(),
                    operation: AggregationOperation::WeightedAverage,
                    input_element: "ferin:eu/a@1".into(),
                    weight_element: None,
                    method_citation: "ISO 14067:2018".into(),
                },
                "without a weight element",
            ),
            // Weighted average weighted by itself.
            (
                TransformBinding::Aggregation {
                    id: "a".into(),
                    operation: AggregationOperation::WeightedAverage,
                    input_element: "ferin:eu/a@1".into(),
                    weight_element: Some("ferin:eu/a@1".into()),
                    method_citation: "ISO 14067:2018".into(),
                },
                "own input element",
            ),
            // A weight on a plain sum.
            (
                TransformBinding::Aggregation {
                    id: "a".into(),
                    operation: AggregationOperation::Sum,
                    input_element: "ferin:eu/a@1".into(),
                    weight_element: Some("ferin:eu/w@1".into()),
                    method_citation: "ISO 14067:2018".into(),
                },
                "weights apply to weighted-average only",
            ),
        ];
        for (transform, expected) in cases {
            lens.transforms = vec![transform];
            let err = lens.validate().unwrap_err();
            assert!(err.contains(expected), "expected `{expected}`, got `{err}`");
        }
    }

    #[test]
    fn localization_binding_parses_and_validates() {
        let raw = json!({
            "kind": "localization-mapping",
            "id": "jp-star-display",
            "source": "eu.energy-label-class",
            "mapping_ref": "urn:unidpp:mapping:eu-class-to-jp-star"
        });
        let t: TransformBinding = serde_json::from_value(raw).unwrap();
        assert_eq!(t.source(), "eu.energy-label-class");
        assert_eq!(
            t.mapping_refs(),
            vec!["urn:unidpp:mapping:eu-class-to-jp-star"]
        );
        let back: TransformBinding =
            serde_json::from_value(serde_json::to_value(&t).unwrap()).unwrap();
        assert_eq!(back, t);

        let mut lens = minimal_lens();
        lens.transforms = vec![TransformBinding::LocalizationMapping {
            id: "m".into(),
            source: "fact.a".into(),
            mapping_ref: " ".into(),
        }];
        assert!(lens
            .validate()
            .unwrap_err()
            .contains("no registered mapping"));
    }

    #[test]
    fn presentation_binding_parses_with_defaults() {
        let raw = json!({
            "template_ref": "urn:unidpp:template:consumer-v1",
            "sections": [
                {"id": "product",
                 "labels": {"en": "Product"},
                 "elements": [
                    {"element": "ferin:eu/a@1", "labels": {"en": "A", "ja": "エー"}}
                 ]}
            ]
        });
        let presentation: PresentationBinding = serde_json::from_value(raw).unwrap();
        assert_eq!(presentation.sections.len(), 1);
        // Formatting defaults: suffix units, one decimal digit, en
        // fallback.
        assert_eq!(presentation.formatting, FormattingRules::default());
        assert_eq!(presentation.formatting.unit_position, UnitPosition::Suffix);
        assert_eq!(presentation.formatting.decimal_digits, 1);
        assert_eq!(presentation.formatting.fallback_lang, "en");
        // Round trip.
        let back: PresentationBinding =
            serde_json::from_value(serde_json::to_value(&presentation).unwrap()).unwrap();
        assert_eq!(back, presentation);

        // A lens without `presentation` parses to None (the field is
        // optional for view-only lenses).
        let eu = fixtures::eu_lens();
        assert!(eu.presentation.is_none());
        let wire = serde_json::to_value(&eu).unwrap();
        assert!(wire.get("presentation").is_none());
        let parsed: LensManifest = serde_json::from_value(wire).unwrap();
        assert!(parsed.presentation.is_none());
    }

    #[test]
    fn presentation_validation_rejects_degenerate_shapes() {
        let present = |sections: Vec<PresentationSection>| LensManifest {
            presentation: Some(PresentationBinding {
                template_ref: "urn:t:1".into(),
                formatting: FormattingRules::default(),
                sections,
            }),
            ..minimal_lens()
        };
        let section_of = |id: &str, elements: Vec<PresentationElement>| PresentationSection {
            id: id.into(),
            labels: [("en".to_string(), format!("{id} title"))]
                .into_iter()
                .collect(),
            elements,
        };
        let element_of = |element: &str| PresentationElement {
            element: element.into(),
            labels: [("en".to_string(), "label".into())].into_iter().collect(),
        };

        // Presents an element that is not a data point.
        let lens = present(vec![section_of("s", vec![element_of("ferin:eu/ghost@1")])]);
        assert!(lens.validate().unwrap_err().contains("not a data point"));

        // The same element presented twice.
        let lens = present(vec![
            section_of("s1", vec![element_of("ferin:eu/a@1")]),
            section_of("s2", vec![element_of("ferin:eu/a@1")]),
        ]);
        assert!(lens.validate().unwrap_err().contains("more than one place"));

        // Duplicate section ids (each section presents a distinct
        // element, so the earlier checks do not fire first).
        let mut two_points = minimal_lens();
        two_points
            .profile
            .data_points
            .push(DataPointRef::new("ferin:eu", "w", Some("1")).unwrap());
        two_points.bindings.push(DataPointBinding {
            element: "ferin:eu/w@1".into(),
            source: "fact.w".into(),
            min_trust: TrustMarker::Unsigned,
            min_capability: CapabilityClass::Silent,
            declared_unit: None,
        });
        let duplicate_ids = LensManifest {
            presentation: Some(PresentationBinding {
                template_ref: "urn:t:1".into(),
                formatting: FormattingRules::default(),
                sections: vec![
                    section_of("s", vec![element_of("ferin:eu/a@1")]),
                    section_of("s", vec![element_of("ferin:eu/w@1")]),
                ],
            }),
            ..two_points
        };
        assert!(duplicate_ids
            .validate()
            .unwrap_err()
            .contains("duplicate presentation section"));

        // A section presenting nothing.
        let lens = present(vec![section_of("s", vec![])]);
        assert!(lens
            .validate()
            .unwrap_err()
            .contains("presents no elements"));

        // No sections at all / no template.
        assert!(present(vec![])
            .validate()
            .unwrap_err()
            .contains("no sections"));
        let mut lens = present(vec![section_of("s", vec![element_of("ferin:eu/a@1")])]);
        lens.presentation.as_mut().unwrap().template_ref = " ".into();
        assert!(lens.validate().unwrap_err().contains("no template"));

        // Display digits beyond the decimal domain.
        let mut lens = present(vec![section_of("s", vec![element_of("ferin:eu/a@1")])]);
        lens.presentation
            .as_mut()
            .unwrap()
            .formatting
            .decimal_digits = 19;
        assert!(lens.validate().unwrap_err().contains("max 18"));

        // The well-formed shape validates.
        let lens = present(vec![section_of("s", vec![element_of("ferin:eu/a@1")])]);
        lens.validate().unwrap();
    }

    #[test]
    fn fixture_lenses_carry_the_new_classes() {
        // The pack lens binds two aggregations and a mapping; the
        // consumer lens carries the presentation — both validate.
        let pack = fixtures::pack_lens();
        assert!(pack
            .transforms
            .iter()
            .any(|t| matches!(t, TransformBinding::Aggregation { .. })));
        let refs: Vec<String> = pack
            .transforms
            .iter()
            .flat_map(|t| t.mapping_refs())
            .collect();
        assert_eq!(refs, vec![fixtures::EU_CLASS_TO_JP_STAR_ID]);
        pack.validate().unwrap();

        let consumer = fixtures::consumer_lens();
        let presentation = consumer.presentation.as_ref().unwrap();
        assert_eq!(
            presentation
                .sections
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>(),
            vec!["product", "repair", "recycling"]
        );
        consumer.validate().unwrap();
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
        assert!(fixtures::fixture_lens(fixtures::CONSUMER_LENS_ID).is_some());
        assert!(fixtures::fixture_lens(fixtures::PACK_LENS_ID).is_some());
    }
}
