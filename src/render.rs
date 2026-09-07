//! The consumer presentation render (TODO.impl 54 / T-04): a passport
//! under a lens *as a consumer sees it* — the profile's data points
//! arranged per its presentation binding (sections, labels in the
//! requested language, formatted values with units, links to the
//! authoritative sources).
//!
//! `/view` is the projection (selected elements, transforms, coverage
//! — for the operator); `/render` is the presentation of the same
//! selection — for the four readers of the `/learn` page. The render
//! consumes the manifest's [`PresentationBinding`]
//! (`crate::lens::PresentationBinding`): sections in display order,
//! per-element labels per language, and display formatting rules.
//!
//! Honesty doctrine (unchanged): the render states what it could not
//! see. An element its section presents that the selection gates block
//! renders as an explicit gap item with its reason; the response
//! carries the same coverage report shape as the view; a label missing
//! in the requested language falls back to the binding's fallback
//! language — and the item says which language served (`label_lang`).
//!
//! Determinism: the same passport, lens, instant, and language always
//! render the same bytes; display rounding is explicit (the rules'
//! `decimal_digits`, half-up) and the exact value always travels in
//! the item's `value` field.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use unidpp_cli::passport::Passport;
use unidpp_model::{FactValue, Timestamp};
use unidpp_verdict::CoverageReport;

use crate::lens::{LensManifest, PresentationElement, UnitPosition};
use crate::primmel::{round_decimal, RoundingMode};
use crate::project::{fact_value_json, select, MissingReason, ProfileSource, ViewError};
use crate::twin;

/// Render the presentation. Fails only structurally (an invalid lens,
/// or a lens without a presentation binding); data gaps are reported
/// *in* the render.
pub fn render(
    passport: &Passport,
    lens: &LensManifest,
    at: Timestamp,
    lang: &str,
    source: &ProfileSource,
) -> Result<Value, ViewError> {
    lens.validate().map_err(ViewError::Invalid)?;
    let Some(presentation) = &lens.presentation else {
        return Err(ViewError::Invalid(format!(
            "profile {} carries no presentation binding — it cannot render",
            lens.profile.id
        )));
    };
    let state = twin::fold(passport, at);

    // --- selection (same gates as the view) ----------------------------
    let mut selected: BTreeMap<String, &crate::twin::SourcedFact> = BTreeMap::new();
    let mut missing: Vec<(String, MissingReason)> = Vec::new();
    let mut trust: BTreeMap<String, String> = BTreeMap::new();
    let mut provided: Vec<String> = Vec::new();
    for dp in &lens.profile.data_points {
        let element = dp.to_string();
        let binding = lens
            .binding_for(&element)
            .ok_or_else(|| ViewError::Invalid(format!("data point `{element}` has no binding")))?;
        match select(passport, &state, binding) {
            crate::project::Selection::Blocked(reason) => missing.push((element.clone(), reason)),
            crate::project::Selection::Found(fact) => {
                provided.push(element.clone());
                trust.insert(element.clone(), fact.origin.trust.to_string());
                selected.insert(element.clone(), fact);
            }
        }
    }

    // --- sections ------------------------------------------------------
    let rules = &presentation.formatting;
    let mut sections: Vec<Value> = Vec::with_capacity(presentation.sections.len());
    for section in &presentation.sections {
        let (section_label, section_lang) = label_for(&section.labels, lang, rules, &section.id);
        let mut items: Vec<Value> = Vec::with_capacity(section.elements.len());
        for element in &section.elements {
            items.push(render_item(
                element,
                passport,
                lens,
                lang,
                rules,
                selected.get(&element.element).copied(),
                missing
                    .iter()
                    .find(|(e, _)| e == &element.element)
                    .map(|(_, r)| r),
                at,
            ));
        }
        let mut block = Map::new();
        block.insert("id".into(), json!(section.id));
        block.insert("label".into(), json!(section_label));
        if let Some(l) = section_lang {
            block.insert("label_lang".into(), json!(l));
        } else {
            block.insert("label_lang".into(), Value::Null);
        }
        block.insert("items".into(), Value::Array(items));
        sections.push(Value::Object(block));
    }

    // --- coverage (the same report shape as the view) -------------------
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

    // --- blocks ---------------------------------------------------------
    let mut metadata = Map::new();
    metadata.insert("template_ref".into(), json!(presentation.template_ref));
    metadata.insert("lang".into(), json!(lang));
    metadata.insert("fallback_lang".into(), json!(rules.fallback_lang));
    metadata.insert(
        "formatting_rules".into(),
        serde_json::to_value(rules).unwrap(),
    );
    metadata.insert("as_of".into(), json!(at.to_string()));
    let mut profile = Map::new();
    profile.insert("id".into(), json!(lens.profile.id.as_str()));
    profile.insert("version".into(), json!(lens.version));
    profile.insert("source".into(), json!(source.mode));
    if let Some(d) = &source.detail {
        profile.insert("source_detail".into(), json!(d));
    }
    metadata.insert("profile".into(), Value::Object(profile));

    let mut passport_block = Map::new();
    passport_block.insert("id".into(), json!(passport.passport_id.as_str()));
    passport_block.insert("product_id".into(), json!(passport.product_id.to_string()));
    passport_block.insert("capability".into(), json!(passport.capability.to_string()));
    passport_block.insert("status".into(), json!(state.status.to_string()));
    if let Some(head) = passport.log.state_hash_at(at) {
        passport_block.insert("log_head".into(), json!(head.hex()));
    }

    let mut doc = Map::new();
    doc.insert("service".into(), json!("unidpp-projector"));
    doc.insert("render_metadata".into(), Value::Object(metadata));
    doc.insert("passport".into(), Value::Object(passport_block));
    doc.insert("sections".into(), Value::Array(sections));
    doc.insert(
        "coverage".into(),
        json!({
            "elements_required": report.required.len(),
            "elements_present": report.present.len(),
            "missing": missing_json,
            "complete": report.is_complete(),
            "ratio": report.ratio(),
        }),
    );
    doc.insert("trust".into(), serde_json::to_value(trust).unwrap());
    Ok(Value::Object(doc))
}

/// One presented item: the localized label, the exact value, the
/// formatted value, and the link to the authoritative source (the
/// `/view` projection of this passport under this profile, plus the
/// sourcing event). A gated element renders as an explicit gap.
#[allow(clippy::too_many_arguments)]
fn render_item<'a>(
    element: &'a PresentationElement,
    passport: &Passport,
    lens: &LensManifest,
    lang: &str,
    rules: &crate::lens::FormattingRules,
    fact: Option<&'a crate::twin::SourcedFact>,
    blocked: Option<&MissingReason>,
    at: Timestamp,
) -> Value {
    let binding = lens.binding_for(&element.element);
    let (label, label_lang) = label_for(&element.labels, lang, rules, &element.element);
    let mut m = Map::new();
    m.insert("element".into(), json!(element.element));
    m.insert("label".into(), json!(label));
    if let Some(l) = label_lang {
        m.insert("label_lang".into(), json!(l));
    } else {
        m.insert("label_lang".into(), Value::Null);
    }
    // The link every consumer can follow to the authoritative view.
    m.insert(
        "source".into(),
        json!({
            "view": format!(
                "/view?passport={}&profile={}&at={}",
                passport.passport_id.as_str(),
                lens.profile.id.as_str(),
                at.to_string()
            ),
        }),
    );
    match (fact, blocked) {
        (Some(fact), _) => {
            m.insert("value".into(), fact_value_json(&fact.value));
            m.insert("kind".into(), json!(fact.value.type_name()));
            let unit = binding.and_then(|b| b.declared_unit.clone());
            if let Some(u) = &unit {
                m.insert("unit".into(), json!(u));
            }
            m.insert(
                "formatted".into(),
                json!(formatted(&fact.value, unit.as_deref(), rules)),
            );
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
            m.insert("status".into(), json!("present"));
        }
        (None, Some(reason)) => {
            m.insert("status".into(), json!("missing"));
            if let Value::Object(fields) = serde_json::to_value(reason).unwrap() {
                for (k, v) in fields {
                    m.insert(k, v);
                }
            }
            m.insert("detail".into(), json!(reason.detail()));
        }
        (None, None) => {
            // Unreachable (every presented element is a data point and
            // every data point is selected or reported) — stated, not
            // guessed.
            m.insert("status".into(), json!("missing"));
            m.insert("reason".into(), json!("not-selected"));
            m.insert(
                "detail".into(),
                json!("the element resolved to neither a selected value nor a reported gap"),
            );
        }
    }
    Value::Object(m)
}

/// The label for one language, with the missing-label fallback chain:
/// requested language → the rules' fallback language → the first
/// label in language-tag order → the element (or section) id itself.
/// Returns the label and the language tag that served it (`None` on
/// the last resort — the id is not a translation).
fn label_for(
    labels: &BTreeMap<String, String>,
    lang: &str,
    rules: &crate::lens::FormattingRules,
    fallback_text: &str,
) -> (String, Option<String>) {
    if let Some(label) = labels.get(lang) {
        return (label.clone(), Some(lang.to_string()));
    }
    if let Some(label) = labels.get(&rules.fallback_lang) {
        return (label.clone(), Some(rules.fallback_lang.clone()));
    }
    if let Some((tag, label)) = labels.iter().next() {
        return (label.clone(), Some(tag.clone()));
    }
    (fallback_text.to_string(), None)
}

/// The display string of one fact value under the formatting rules:
/// display-only rounding (explicit `decimal_digits`, half-up — the
/// exact value travels in `value`), unit placement per
/// `unit_position`.
fn formatted(
    value: &FactValue,
    unit: Option<&str>,
    rules: &crate::lens::FormattingRules,
) -> String {
    let body = match value {
        FactValue::Num(n) => round_decimal(*n, rules.decimal_digits, RoundingMode::HalfUp)
            .map(|d| d.to_string())
            .unwrap_or_else(|_| n.to_string()),
        FactValue::Str(s) => s.clone(),
        FactValue::Bool(b) => b.to_string(),
        FactValue::List(l) => l.join(", "),
    };
    match (unit, rules.unit_position) {
        (Some(u), UnitPosition::Suffix) => format!("{body} {u}"),
        (Some(_), UnitPosition::None) | (None, _) => body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use crate::project::ProfileSource;

    const LANG_EN: &str = "en";
    const LANG_JA: &str = "ja";

    fn rendered(lang: &str) -> Value {
        render(
            &fixtures::demo_passport(),
            &fixtures::consumer_lens(),
            fixtures::demo_as_of(),
            lang,
            &ProfileSource::fallback("fixtures", None),
        )
        .unwrap()
    }

    fn section<'a>(doc: &'a Value, id: &str) -> &'a Value {
        doc["sections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"].as_str() == Some(id))
            .unwrap_or(&Value::Null)
    }

    fn item<'a>(doc: &'a Value, section_id: &str, element: &str) -> &'a Value {
        section(doc, section_id)["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["element"].as_str() == Some(element))
            .unwrap_or(&Value::Null)
    }

    #[test]
    fn renders_two_languages_from_one_profile() {
        // Same profile, same passport, two languages: the sections and
        // values are identical, the labels are not.
        let en = rendered(LANG_EN);
        let ja = rendered(LANG_JA);
        assert_eq!(
            en["render_metadata"]["template_ref"],
            json!("urn:unidpp:template:consumer-v1")
        );
        assert_eq!(en["render_metadata"]["lang"], json!("en"));
        assert_eq!(ja["render_metadata"]["lang"], json!("ja"));

        // The sections, in binding order.
        let ids: Vec<&str> = en["sections"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["id"].as_str())
            .collect();
        assert_eq!(ids, vec!["product", "repair", "recycling"]);

        // Localized section labels.
        assert_eq!(section(&en, "product")["label"], json!("Product"));
        assert_eq!(section(&ja, "product")["label"], json!("製品情報"));
        assert_eq!(section(&en, "product")["label_lang"], json!("en"));
        assert_eq!(section(&ja, "product")["label_lang"], json!("ja"));

        // Localized element labels with formatted values and units.
        let carbon_en = item(&en, "recycling", fixtures::CARBON_ELEMENT);
        assert_eq!(carbon_en["label"], json!("Carbon footprint"));
        assert_eq!(carbon_en["formatted"], json!("96.4 kgCO2e"));
        assert_eq!(carbon_en["value"], json!("96.4"));
        assert_eq!(carbon_en["unit"], json!("kgCO2e"));
        assert_eq!(carbon_en["status"], json!("present"));
        let carbon_ja = item(&ja, "recycling", fixtures::CARBON_ELEMENT);
        assert_eq!(carbon_ja["label"], json!("炭素フットプリント"));
        assert_eq!(carbon_ja["formatted"], json!("96.4 kgCO2e"));
        // The exact value and provenance are language-independent.
        assert_eq!(carbon_ja["value"], carbon_en["value"]);
        assert_eq!(carbon_ja["sourced"], carbon_en["sourced"]);
        assert_eq!(carbon_ja["trust"], json!("attested"));
    }

    #[test]
    fn formatting_rounds_display_only_with_explicit_digits() {
        // 0.072 kWh at one decimal renders as 0.1; the exact value
        // stays exact.
        let en = rendered(LANG_EN);
        let capacity = item(&en, "product", fixtures::CAPACITY_ELEMENT);
        assert_eq!(capacity["formatted"], json!("0.1 kWh"));
        assert_eq!(capacity["value"], json!("0.072"));
        // A string fact renders unformatted and unitless.
        let operator = item(&en, "product", fixtures::OPERATOR_ELEMENT);
        assert_eq!(
            operator["formatted"],
            json!("urn:unidpp:actor:oem-nordwave")
        );
        assert!(operator.get("unit").is_none());
    }

    #[test]
    fn items_link_to_the_authoritative_view() {
        let en = rendered(LANG_EN);
        let view = item(&en, "repair", fixtures::REPARABILITY_ELEMENT)["source"]["view"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(view.starts_with("/view?passport="), "{view}");
        assert!(
            view.contains("profile=urn:unidpp:profile:consumer-dpp"),
            "{view}"
        );
        assert!(
            view.ends_with(&format!("&at={}", fixtures::DEMO_AS_OF)),
            "{view}"
        );
        let repair = item(&en, "repair", fixtures::REPARABILITY_ELEMENT);
        assert_eq!(repair["sourced"]["seq"], json!(6));
        assert_eq!(repair["trust"], json!("attested"));
    }

    #[test]
    fn missing_label_falls_back_to_the_declared_language() {
        // French is requested; no label carries it — every label falls
        // back to the binding's fallback language (en), and the render
        // states which language served.
        let fr = rendered("fr");
        assert_eq!(fr["render_metadata"]["lang"], json!("fr"));
        assert_eq!(fr["render_metadata"]["fallback_lang"], json!("en"));
        assert_eq!(section(&fr, "product")["label"], json!("Product"));
        assert_eq!(section(&fr, "product")["label_lang"], json!("en"));
        let carbon = item(&fr, "recycling", fixtures::CARBON_ELEMENT);
        assert_eq!(carbon["label"], json!("Carbon footprint"));
        assert_eq!(carbon["label_lang"], json!("en"));
    }

    #[test]
    fn coverage_report_travels_with_the_render() {
        let en = rendered(LANG_EN);
        // The consumer lens binds an element the demo passport does not
        // provide on purpose (the recycling instruction): the gap is
        // explicit, in the section and in the coverage report.
        let instruction = item(&en, "recycling", fixtures::INSTRUCTION_ELEMENT);
        assert_eq!(instruction["status"], json!("missing"));
        assert_eq!(instruction["reason"], json!("absent-as-of"));
        assert_eq!(en["coverage"]["elements_required"], json!(5));
        assert_eq!(en["coverage"]["elements_present"], json!(4));
        assert!(!en["coverage"]["complete"].as_bool().unwrap());
        let missing = en["coverage"]["missing"].as_array().unwrap();
        assert_eq!(missing[0]["element"], json!(fixtures::INSTRUCTION_ELEMENT));
        assert_eq!(missing[0]["reason"], json!("absent-as-of"));
    }

    #[test]
    fn lens_without_presentation_is_refused() {
        let err = render(
            &fixtures::demo_passport(),
            &fixtures::eu_lens(),
            fixtures::demo_as_of(),
            LANG_EN,
            &ProfileSource::registry(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("no presentation binding"), "{err}");
    }

    #[test]
    fn render_is_deterministic() {
        let first = rendered(LANG_JA);
        let second = rendered(LANG_JA);
        assert_eq!(first, second);
    }
}
