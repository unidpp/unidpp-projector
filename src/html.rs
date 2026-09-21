//! The consumer serializations of the render (TODO.impl 224): the
//! same presentation, additional wire formats. `/render` negotiated to
//! `text/html` serves a standalone page and to `text/plain` serves the
//! speakable text form (the TTS substrate) — both built **from the
//! render JSON document**, so there is exactly one presentation
//! computation and neither can disagree with the JSON (MobileQR
//! dissection lesson: one renderer, presentation as data — never
//! per-template forks).
//!
//! Doctrine (unchanged): honesty — a gap item renders as a stated
//! absence with its reason; the coverage footer states the ratio and
//! completeness; the newest fact's recording time is stated as the
//! page's change notice. Determinism: the same render document always
//! serializes to the same bytes (no clocks, no counters, no external
//! assets — a single inline stylesheet). Every string is HTML-escaped;
//! the page contains no client-side script.

use std::collections::HashMap;

use serde_json::Value;

/// Serialize a render document to a standalone HTML page.
pub fn document(render: &Value) -> String {
    let lang = str_of(render, &["render_metadata", "lang"]).unwrap_or_else(|| "en".into());
    let product = str_of(render, &["passport", "product_id"]).unwrap_or_default();
    let title = if product.is_empty() {
        "UniDPP".to_string()
    } else {
        format!("{product} — UniDPP")
    };

    let mut out = String::with_capacity(4096);
    out.push_str("<!DOCTYPE html>\n");
    out.push_str(&format!(r#"<html lang="{}">"#, esc(&lang)));
    out.push_str("\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str(&format!("<title>{}</title>\n", esc(&title)));
    out.push_str("<style>");
    out.push_str(STYLE);
    out.push_str("</style>\n</head>\n<body>\n");

    // --- header: identity, as the consumer anchors on it --------------
    out.push_str("<header class=\"card\">\n<h1>");
    out.push_str(&esc(&product));
    out.push_str("</h1>\n<p class=\"meta\">");
    out.push_str(&esc(&format!(
        "passport {} · capability {} · status {}",
        str_of(render, &["passport", "id"]).unwrap_or_default(),
        str_of(render, &["passport", "capability"]).unwrap_or_default(),
        str_of(render, &["passport", "status"]).unwrap_or_default(),
    )));
    out.push_str("</p>\n</header>\n");

    // --- sections: labels and values from the render ------------------
    if let Some(sections) = render.pointer("/sections").and_then(Value::as_array) {
        for section in sections {
            out.push_str(&format!(
                "<section id=\"{}\">\n<h2>{}</h2>\n",
                esc(&str_of(section, &["id"]).unwrap_or_default()),
                esc(&str_of(section, &["label"]).unwrap_or_default()),
            ));
            if let Some(items) = section.get("items").and_then(Value::as_array) {
                for item in items {
                    out.push_str(&item_html(item));
                }
            }
            out.push_str("</section>\n");
        }
    }

    // --- change notice: the newest fact this page shows ----------------
    if let Some(newest) = newest_recorded_at(render) {
        out.push_str(&format!(
            "<p class=\"notice\">{}</p>\n",
            esc(&format!(
                "The most recent information on this page was recorded on {newest}."
            ))
        ));
    }

    // --- coverage footer: the same honesty as the JSON -----------------
    let required = render
        .pointer("/coverage/elements_required")
        .and_then(Value::as_u64);
    let present = render
        .pointer("/coverage/elements_present")
        .and_then(Value::as_u64);
    let complete = render
        .pointer("/coverage/complete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let (Some(required), Some(present)) = (required, present) {
        out.push_str("<footer class=\"coverage\">\n<h2>Coverage</h2>\n<p>");
        out.push_str(&esc(&format!(
            "{present} of {required} elements presented — {}.",
            if complete { "complete" } else { "incomplete" }
        )));
        out.push_str("</p>\n");
        if let Some(missing) = render
            .pointer("/coverage/missing")
            .and_then(Value::as_array)
        {
            if !missing.is_empty() {
                out.push_str("<ul class=\"gaps\">\n");
                for m in missing {
                    out.push_str(&format!(
                        "<li>{} — {}</li>\n",
                        esc(&str_of(m, &["element"]).unwrap_or_default()),
                        esc(&str_of(m, &["detail"]).unwrap_or_else(|| "not provided".into())),
                    ));
                }
                out.push_str("</ul>\n");
            }
        }
        let as_of = str_of(render, &["render_metadata", "as_of"]).unwrap_or_default();
        let profile = render
            .pointer("/render_metadata/profile/id")
            .and_then(Value::as_str)
            .unwrap_or("");
        out.push_str(&format!(
            "<p class=\"asof\">{}</p>\n",
            esc(&format!("Rendered as of {as_of} · profile {profile}"))
        ));
        out.push_str("</footer>\n");
    }

    out.push_str("</body>\n</html>\n");
    out
}

/// One presented item: the label and the formatted value, or the label
/// and the stated absence. Trust tags along in the class list — the
/// consumer can see what is attested vs self-declared.
fn item_html(item: &Value) -> String {
    let label = str_of(item, &["label"]).unwrap_or_default();
    let status = str_of(item, &["status"]).unwrap_or_default();
    let trust = str_of(item, &["trust"]).unwrap_or_default();
    let mut class = String::from("item");
    if status == "missing" {
        class.push_str(" gap");
    }
    if !trust.is_empty() {
        class.push_str(&format!(" trust-{trust}"));
    }
    let body = match status.as_str() {
        "present" => str_of(item, &["formatted"]).unwrap_or_default(),
        // The gap is stated, never hidden: the reason's detail renders
        // in place of the value.
        _ => format!(
            "not shown — {}",
            str_of(item, &["detail"]).unwrap_or_else(|| "not provided".into())
        ),
    };
    format!(
        "<div class=\"{class}\"><span class=\"label\">{}</span><span class=\"value\">{}</span></div>\n",
        esc(&label),
        esc(&body),
    )
}

/// The newest `sourced.occurred_at` across presented items — the page's
/// change notice, derived from the render itself (RFC 3339 `Z` strings
/// sort lexicographically).
fn newest_recorded_at(render: &Value) -> Option<String> {
    render
        .pointer("/sections")?
        .as_array()?
        .iter()
        .filter_map(|s| s.get("items")?.as_array())
        .flatten()
        .filter(|i| str_of(i, &["status"]).as_deref() == Some("present"))
        .filter_map(|i| str_of(i, &["sourced", "occurred_at"]))
        .max()
}

/// The plain-text serialization of the render (TODO.impl 224): the
/// same presentation as speakable text — the deterministic substrate a
/// text-to-speech transform consumes (synthesis is a pluggable
/// transform over this form, never an architecture commitment; the
/// MobileQR `getaudiobase64` server-side TTS is the deployment-side
/// counterpart). Plain sentences, no markup: every gap is spoken, not
/// hidden.
pub fn text(render: &Value) -> String {
    let mut out = String::with_capacity(1024);
    let product = str_of(render, &["passport", "product_id"]).unwrap_or_default();
    if !product.is_empty() {
        out.push_str(&format!("{product}.\n"));
    }
    if let Some(sections) = render.pointer("/sections").and_then(Value::as_array) {
        for section in sections {
            let label = str_of(section, &["label"]).unwrap_or_default();
            if !label.is_empty() {
                out.push_str(&format!("\n{label}.\n"));
            }
            if let Some(items) = section.get("items").and_then(Value::as_array) {
                for item in items {
                    let item_label = str_of(item, &["label"]).unwrap_or_default();
                    let status = str_of(item, &["status"]).unwrap_or_default();
                    let body = match status.as_str() {
                        "present" => str_of(item, &["formatted"]).unwrap_or_default(),
                        _ => format!(
                            "not shown — {}",
                            str_of(item, &["detail"]).unwrap_or_else(|| "not provided".into())
                        ),
                    };
                    if !item_label.is_empty() {
                        out.push_str(&format!("{item_label}: {body}.\n"));
                    }
                }
            }
        }
    }
    if let Some(newest) = newest_recorded_at(render) {
        out.push_str(&format!(
            "\nThe most recent information on this page was recorded on {newest}.\n"
        ));
    }
    let required = render
        .pointer("/coverage/elements_required")
        .and_then(Value::as_u64);
    let present = render
        .pointer("/coverage/elements_present")
        .and_then(Value::as_u64);
    let complete = render
        .pointer("/coverage/complete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let (Some(required), Some(present)) = (required, present) {
        out.push_str(&format!(
            "Coverage: {present} of {required} elements presented, {}.",
            if complete { "complete" } else { "incomplete" }
        ));
    }
    out
}

/// Whether an `Accept` header prefers an HTML representation: the
/// client's first media type decides (browsers list `text/html` first;
/// API clients list `application/json` or `*/*`). An explicit `format`
/// query parameter always outranks the header — the same doctrine as
/// the resolver's content negotiation.
pub fn accept_prefers_html(accept: Option<&str>) -> bool {
    first_media_type(accept).is_some_and(|m| m == "text/html" || m == "application/xhtml+xml")
}

/// The client's first (most-preferred) media type, lowercased and
/// parameter-stripped.
fn first_media_type(accept: Option<&str>) -> Option<String> {
    let accept = accept?;
    let first = accept
        .split(',')
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if first.is_empty() {
        None
    } else {
        Some(first)
    }
}

/// The requested output format for `/render`: the explicit `format`
/// parameter first, else the `Accept` header's preference.
pub fn requested_format(params: &HashMap<String, String>, accept: Option<&str>) -> Format {
    match params.get("format").map(|s| s.trim()) {
        Some("html") => Format::Html,
        Some("text") => Format::Text,
        Some("json") => Format::Json,
        Some(other) => Format::Invalid(other.to_string()),
        None => match first_media_type(accept).as_deref() {
            Some("text/html") | Some("application/xhtml+xml") => Format::Html,
            Some("text/plain") => Format::Text,
            _ => Format::Json,
        },
    }
}

/// The `/render` output format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    Html,
    Text,
    Json,
    Invalid(String),
}

/// Minimal mobile-first styling, inline (no external assets — the page
/// is standalone by construction).
const STYLE: &str = "body{font-family:system-ui,sans-serif;margin:0 auto;max-width:640px;\
padding:1rem;color:#1a1a1a;background:#fafafa}\
.card{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:1rem;margin-bottom:1rem}\
h1{font-size:1.25rem;margin:0 0 .5rem}\
h2{font-size:1.05rem;margin:0 0 .5rem}\
.meta,.asof{color:#666;font-size:.8rem;margin:.25rem 0}\
section{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:1rem;margin-bottom:1rem}\
.item{display:flex;justify-content:space-between;gap:1rem;padding:.4rem 0;border-bottom:1px solid #f0f0f0}\
.item:last-child{border-bottom:none}\
.label{color:#555}\
.value{text-align:right;font-weight:500}\
.gap .value{color:#b00;font-weight:400}\
.notice{color:#555;font-size:.85rem;padding:0 .25rem}\
.coverage{color:#555;font-size:.85rem;padding:.5rem .25rem}\
.gaps{margin:.25rem 0;padding-left:1.25rem}";

/// HTML-escape a string (`&`, `<`, `>`, `"`, `'`).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn str_of(value: &Value, path: &[&str]) -> Option<String> {
    let mut v = value;
    for key in path {
        v = v.get(*key)?;
    }
    v.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{consumer_lens, demo_as_of, demo_passport};
    use crate::project::ProfileSource;
    use serde_json::json;

    fn demo_render() -> Value {
        let source = ProfileSource::fallback("fixtures", None);
        crate::render::render(
            &demo_passport(),
            &consumer_lens(),
            demo_as_of(),
            "en",
            &source,
        )
        .unwrap()
    }

    #[test]
    fn the_page_serializes_the_render() {
        let doc = demo_render();
        let page = document(&doc);
        // Section labels and values come from the render document.
        assert!(page.contains("<h2>Product</h2>"), "sections carry labels");
        assert!(page.contains("Battery capacity"), "item labels present");
        assert!(page.contains("kWh"), "formatted values with units present");
        // The deliberate gap is stated, never hidden.
        assert!(
            page.contains("Recycling instruction"),
            "the missing element's label still renders"
        );
        assert!(page.contains("not shown — "), "the gap states its absence");
        assert!(page.contains("Coverage"), "the coverage footer renders");
        assert!(page.contains("4 of 5"), "the coverage counts render");
        // Language and identity anchor the page.
        assert!(page.contains(r#"<html lang="en">"#));
        assert!(
            page.contains("urn:iso:std:iso-iec:15459"),
            "the product id is the title"
        );
    }

    #[test]
    fn the_page_is_deterministic() {
        let doc = demo_render();
        assert_eq!(document(&doc), document(&doc));
    }

    #[test]
    fn hostile_strings_are_escaped() {
        let doc = json!({
            "render_metadata": {"lang": "en"},
            "passport": {"id": "p", "product_id": "<script>alert(1)</script>", "capability": "silent", "status": "active"},
            "sections": [{
                "id": "s", "label": "Product \"&\" <b>bold</b>",
                "items": [{
                    "element": "e", "label": "Name", "status": "present",
                    "formatted": "<img src=x onerror=alert(2)>",
                    "sourced": {"occurred_at": "2027-01-01T00:00:00Z"}
                }]
            }],
            "coverage": {"elements_required": 1, "elements_present": 1, "complete": true, "missing": []}
        });
        let page = document(&doc);
        assert!(!page.contains("<script>alert(1)"));
        assert!(!page.contains("<img src=x"));
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(page.contains("Product &quot;&amp;&quot; &lt;b&gt;bold&lt;/b&gt;"));
    }

    #[test]
    fn the_change_notice_states_the_newest_recorded_fact() {
        let doc = json!({
            "render_metadata": {"lang": "en"},
            "passport": {"id": "p", "product_id": "x", "capability": "silent", "status": "active"},
            "sections": [{
                "id": "s", "label": "Product",
                "items": [
                    {"element": "a", "label": "A", "status": "present", "formatted": "1",
                     "sourced": {"occurred_at": "2026-01-01T00:00:00Z"}},
                    {"element": "b", "label": "B", "status": "present", "formatted": "2",
                     "sourced": {"occurred_at": "2027-03-05T09:00:00Z"}},
                    {"element": "c", "label": "C", "status": "missing", "detail": "not provided"}
                ]
            }],
            "coverage": {"elements_required": 3, "elements_present": 2, "complete": false, "missing": []}
        });
        let page = document(&doc);
        assert!(page.contains("recorded on 2027-03-05T09:00:00Z"));
    }

    #[test]
    fn acceptance_negotiation() {
        assert!(accept_prefers_html(Some(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )));
        assert!(!accept_prefers_html(Some("*/*")));
        assert!(!accept_prefers_html(Some("application/json")));
        assert!(!accept_prefers_html(Some(
            "application/json, text/html;q=0.5"
        )));
        assert!(!accept_prefers_html(None));
        // The explicit parameter outranks the header.
        let mut params = HashMap::new();
        params.insert("format".to_string(), "json".to_string());
        assert_eq!(requested_format(&params, Some("text/html")), Format::Json);
        params.insert("format".to_string(), "html".to_string());
        assert_eq!(requested_format(&params, None), Format::Html);
        params.insert("format".to_string(), "text".to_string());
        assert_eq!(requested_format(&params, None), Format::Text);
        params.insert("format".to_string(), "xml".to_string());
        assert_eq!(
            requested_format(&params, None),
            Format::Invalid("xml".to_string())
        );
        params.remove("format");
        assert_eq!(requested_format(&params, Some("text/html")), Format::Html);
        assert_eq!(requested_format(&params, Some("text/plain")), Format::Text);
        assert_eq!(requested_format(&params, None), Format::Json);
    }

    #[test]
    fn the_text_form_is_speakable_and_honest() {
        let doc = demo_render();
        let spoken = text(&doc);
        // Determinism: pure function of the render.
        assert_eq!(spoken, text(&doc));
        // Labels and values serialize as plain sentences — no markup.
        assert!(!spoken.contains('<'));
        assert!(spoken.contains("Battery capacity: "));
        assert!(spoken.contains("kWh"));
        // A gap is spoken, never hidden.
        assert!(spoken.contains("Recycling instruction: not shown — "));
        // The coverage summary closes the reading.
        assert!(spoken.contains("Coverage: 4 of 5 elements presented, incomplete."));
        assert!(spoken.contains("The most recent information on this page was recorded on"));
    }
}
