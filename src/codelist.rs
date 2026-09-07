//! The localization / code-list mapping transform class (TODO.impl 67
//! / T-19): registered code-list correspondences.
//!
//! PLAN.md transform taxonomy (5): "localization mapping — registered
//! code-list correspondences (waste codes, HS/TARIC vs national)". A
//! **mapping item** is a versioned registry item (class `transform`,
//! the same channel as the Primmel packages) whose manifest is this
//! module's wire shape:
//!
//! ```json
//! {
//!   "id": "urn:unidpp:mapping:eu-class-to-jp-star",
//!   "version": "1.0.0",
//!   "title": "EU energy-label class ↔ JP star display",
//!   "citation": "Regulation (EU) 2017/1369 Annex II ↔ METI star display",
//!   "source_scheme": "urn:eu:reg:2017:1369#annex-ii-class",
//!   "target_scheme": "urn:jp:meti:star-rating",
//!   "table": [
//!     { "source_value": "A", "target_value": "★★★★★" },
//!     { "source_value": "B", "target_value": "★★★★" }
//!   ]
//! }
//! ```
//!
//! A lens binding references the item by `mapping_ref`; the projector
//! resolves it (registry transforms subregister, else the built-in
//! fixtures — per-package sourcing recorded in the output), looks the
//! input value up in the table, and emits the target value together
//! with the mapping item's identity, version, schemes and citation. A
//! value with no correspondence is emitted as the explicit `unmapped`
//! output — never a silent pass-through of the source value.

use std::collections::BTreeMap;

use serde_json::Value;

/// The output emitted for an input value the table does not carry
/// (explicit, never silent).
pub const UNMAPPED: &str = "unmapped";

/// One correspondence row of the mapping table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MappingEntry {
    /// The value in the source scheme.
    pub source_value: String,
    /// The corresponding value in the target scheme.
    pub target_value: String,
    /// Optional correspondence note (why this row maps as it does).
    #[serde(default)]
    pub note: Option<String>,
}

/// A registered code-list correspondence item (versioned like any
/// registry item; the item's manifest slot carries this shape).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CodeListMapping {
    /// The mapping item id (what a lens binding's `mapping_ref` names).
    pub id: String,
    /// The version pin (recorded in every mapped output).
    pub version: String,
    /// Human-readable title.
    #[serde(default)]
    pub title: Option<String>,
    /// The correspondence's citation — the authority the table
    /// transcribes.
    #[serde(default)]
    pub citation: Option<String>,
    /// The scheme the input value belongs to.
    pub source_scheme: String,
    /// The scheme the output value belongs to.
    pub target_scheme: String,
    /// The correspondence rows (unique on `source_value`).
    pub table: Vec<MappingEntry>,
}

impl CodeListMapping {
    /// Parse and validate a mapping item from its manifest JSON.
    pub fn from_json(doc: &Value) -> Result<CodeListMapping, String> {
        let mapping: CodeListMapping = serde_json::from_value(doc.clone())
            .map_err(|e| format!("code-list mapping does not parse: {e}"))?;
        mapping.validate()?;
        Ok(mapping)
    }

    /// Parse from a registry item document (the `manifest` slot).
    pub fn from_item(item: &Value) -> Result<CodeListMapping, String> {
        let id = item.get("identifier").and_then(Value::as_str);
        let class = item.get("item_class").and_then(Value::as_str);
        if class.is_some() && class != Some("transform") {
            return Err(format!(
                "item `{}` is not a transform item (class `{}`)",
                id.unwrap_or("?"),
                class.unwrap_or("?")
            ));
        }
        let manifest = item
            .get("manifest")
            .filter(|m| m.is_object())
            .ok_or_else(|| format!("mapping item `{}` carries no manifest", id.unwrap_or("?")))?;
        let mapping = CodeListMapping::from_json(manifest)?;
        if let Some(id) = id {
            if mapping.id != id {
                return Err(format!(
                    "mapping item `{id}` carries a manifest for `{}`",
                    mapping.id
                ));
            }
        }
        Ok(mapping)
    }

    /// Structural validation: identity present, schemes and citation
    /// chains named, table non-empty with unique, non-empty values.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("code-list mapping lacks an id".to_string());
        }
        if self.version.trim().is_empty() {
            return Err(format!(
                "code-list mapping `{}` lacks a version pin",
                self.id
            ));
        }
        if self.source_scheme.trim().is_empty() || self.target_scheme.trim().is_empty() {
            return Err(format!(
                "code-list mapping `{}` must name its source and target \
                 schemes",
                self.id
            ));
        }
        if self.table.is_empty() {
            return Err(format!(
                "code-list mapping `{}` has an empty table",
                self.id
            ));
        }
        let mut sources: Vec<&str> = Vec::with_capacity(self.table.len());
        for entry in &self.table {
            if entry.source_value.trim().is_empty() || entry.target_value.trim().is_empty() {
                return Err(format!(
                    "code-list mapping `{}` has a row with an empty value",
                    self.id
                ));
            }
            if sources.contains(&entry.source_value.as_str()) {
                return Err(format!(
                    "code-list mapping `{}` maps source value `{}` twice",
                    self.id, entry.source_value
                ));
            }
            sources.push(&entry.source_value);
        }
        Ok(())
    }

    /// Look up one source-scheme value.
    pub fn lookup(&self, source_value: &str) -> Option<&MappingEntry> {
        self.table.iter().find(|e| e.source_value == source_value)
    }

    /// The reverse correspondence (target scheme back to source): rows
    /// re-keyed on the target values. Only total for bijective tables;
    /// a collision is an error the caller surfaces.
    pub fn reversed(&self) -> Result<CodeListMapping, String> {
        let mut table: Vec<MappingEntry> = Vec::with_capacity(self.table.len());
        for entry in &self.table {
            let swapped = MappingEntry {
                source_value: entry.target_value.clone(),
                target_value: entry.source_value.clone(),
                note: entry.note.clone(),
            };
            if table.iter().any(|e| e.source_value == swapped.source_value) {
                return Err(format!(
                    "code-list mapping `{}` is not bijective — the reverse \
                     correspondence is not a function (target value `{}` \
                     appears twice)",
                    self.id, swapped.source_value
                ));
            }
            table.push(swapped);
        }
        Ok(CodeListMapping {
            id: format!("{}:reversed", self.id),
            version: self.version.clone(),
            title: self.title.clone(),
            citation: self.citation.clone(),
            source_scheme: self.target_scheme.clone(),
            target_scheme: self.source_scheme.clone(),
            table,
        })
    }
}

/// The mappings a projection may consult, with per-item sourcing
/// (`registry` — a transforms subregister item, `fixtures` — the
/// built-in demo corpus).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MappingSet {
    /// Mappings keyed by item id.
    pub mappings: BTreeMap<String, CodeListMapping>,
    /// Sourcing mode per item id.
    pub sources: BTreeMap<String, &'static str>,
}

impl MappingSet {
    /// An empty set (no localization bindings consult it).
    pub fn empty() -> MappingSet {
        MappingSet::default()
    }

    /// A one-mapping set with its source mode.
    pub fn of(mapping: CodeListMapping, source: &'static str) -> MappingSet {
        let mut set = MappingSet::empty();
        set.insert(mapping, source);
        set
    }

    /// Add a mapping with its source mode.
    pub fn insert(&mut self, mapping: CodeListMapping, source: &'static str) {
        self.sources.insert(mapping.id.clone(), source);
        self.mappings.insert(mapping.id.clone(), mapping);
    }

    /// Look up a mapping by item id together with its sourcing mode.
    pub fn get(&self, id: &str) -> Option<(&CodeListMapping, &'static str)> {
        let source = self.sources.get(id).copied()?;
        self.mappings.get(id).map(|m| (m, source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn wire() -> Value {
        json!({
            "id": "urn:unidpp:mapping:test",
            "version": "1.0.0",
            "title": "EU class ↔ JP stars",
            "citation": "Regulation (EU) 2017/1369 Annex II ↔ METI star display",
            "source_scheme": "urn:eu:reg:2017:1369#annex-ii-class",
            "target_scheme": "urn:jp:meti:star-rating",
            "table": [
                { "source_value": "A", "target_value": "★★★★★",
                  "note": "best class ↔ five stars" },
                { "source_value": "B", "target_value": "★★★★" },
                { "source_value": "C", "target_value": "★★★" }
            ]
        })
    }

    #[test]
    fn parses_validates_and_looks_up() {
        let mapping = CodeListMapping::from_json(&wire()).unwrap();
        assert_eq!(mapping.id, "urn:unidpp:mapping:test");
        assert_eq!(mapping.table.len(), 3);
        let hit = mapping.lookup("B").unwrap();
        assert_eq!(hit.target_value, "★★★★");
        assert!(hit.note.is_none());
        assert_eq!(
            mapping.lookup("A").unwrap().note.as_deref(),
            Some("best class ↔ five stars")
        );
        // A value outside the table: nothing found — the projector
        // emits the explicit `unmapped` output.
        assert!(mapping.lookup("G").is_none());
        assert_eq!(UNMAPPED, "unmapped");
    }

    #[test]
    fn round_trips_through_the_typed_model() {
        let mapping = CodeListMapping::from_json(&wire()).unwrap();
        let back = serde_json::to_value(&mapping).unwrap();
        let again = CodeListMapping::from_json(&back).unwrap();
        assert_eq!(again, mapping);
    }

    #[test]
    fn reversed_round_trips_bijective_tables() {
        let mapping = CodeListMapping::from_json(&wire()).unwrap();
        let reverse = mapping.reversed().unwrap();
        assert_eq!(reverse.source_scheme, mapping.target_scheme);
        assert_eq!(reverse.lookup("★★★★★").unwrap().target_value, "A");
        assert_eq!(reverse.lookup("★").map(|e| e.target_value.clone()), None);
        // Round trip: A → ★★★★★ → A.
        let stars = mapping.lookup("A").unwrap().target_value.clone();
        assert_eq!(
            reverse.lookup(&stars).unwrap().target_value,
            "A",
            "A → {stars} → A"
        );
    }

    #[test]
    fn validation_refuses_degenerate_shapes() {
        let mut doc = wire();
        doc["table"].as_array_mut().unwrap().clear();
        assert!(CodeListMapping::from_json(&doc)
            .unwrap_err()
            .contains("empty table"));

        let mut doc = wire();
        doc["table"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "source_value": "A", "target_value": "★" }));
        assert!(CodeListMapping::from_json(&doc)
            .unwrap_err()
            .contains("twice"));

        let mut doc = wire();
        doc["table"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "source_value": "", "target_value": "★" }));
        assert!(CodeListMapping::from_json(&doc)
            .unwrap_err()
            .contains("empty value"));

        let mut doc = wire();
        doc.as_object_mut().unwrap().remove("version");
        assert!(CodeListMapping::from_json(&doc)
            .unwrap_err()
            .contains("version"));

        // A missing scheme is caught at parse (the field is required
        // on the wire); an empty one by validation.
        let mut doc = wire();
        doc.as_object_mut().unwrap().remove("target_scheme");
        assert!(CodeListMapping::from_json(&doc)
            .unwrap_err()
            .contains("target_scheme"));
        let mut doc = wire();
        doc["target_scheme"] = json!(" ");
        assert!(CodeListMapping::from_json(&doc)
            .unwrap_err()
            .contains("schemes"));
    }

    #[test]
    fn reversal_refuses_non_functions() {
        let mut doc = wire();
        doc["table"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "source_value": "D", "target_value": "★★★" }));
        let mapping = CodeListMapping::from_json(&doc).unwrap();
        let err = mapping.reversed().unwrap_err();
        assert!(err.contains("not bijective"), "{err}");
    }

    #[test]
    fn from_item_checks_the_class_and_identifier() {
        let mut item = json!({
            "identifier": "urn:unidpp:mapping:test",
            "item_class": "transform",
            "manifest": wire()
        });
        assert!(CodeListMapping::from_item(&item).is_ok());

        item["item_class"] = json!("unit");
        assert!(CodeListMapping::from_item(&item)
            .unwrap_err()
            .contains("not a transform item"));

        item["item_class"] = json!("transform");
        item["identifier"] = json!("urn:unidpp:mapping:other");
        assert!(CodeListMapping::from_item(&item)
            .unwrap_err()
            .contains("manifest for"));

        item.as_object_mut().unwrap().remove("manifest");
        assert!(CodeListMapping::from_item(&item)
            .unwrap_err()
            .contains("no manifest"));
    }

    #[test]
    fn mapping_set_records_sourcing() {
        let mapping = CodeListMapping::from_json(&wire()).unwrap();
        let set = MappingSet::of(mapping.clone(), "registry");
        let (got, source) = set.get("urn:unidpp:mapping:test").unwrap();
        assert_eq!(got, &mapping);
        assert_eq!(source, "registry");
        assert!(set.get("urn:unidpp:mapping:none").is_none());
        assert_eq!(MappingSet::empty(), MappingSet::default());
    }
}
