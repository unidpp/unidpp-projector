//! Integration: the EU/JP two-lens scenario against a real
//! `unidpp-registry` instance (seeded with the EU/JP profile items and
//! the unit items), driven over hand-rolled HTTP (house pattern).
//!
//! The B4 border moment as a service: one passport, two profile items
//! → two views with different classifications and different coverage,
//! as-of-reconstructable, deterministic, and honest about fallback
//! when the registry is unreachable.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{json, Value};
use unidpp_projector::http::{json_request, Url};
use unidpp_projector::{fixtures, Config, TestServer};
use unidpp_registry::{Config as RegistryConfig, TestServer as RegistryServer};

const TIMEOUT: Duration = Duration::from_secs(5);
const DEMO_PASSPORT: &str = fixtures::DEMO_PASSPORT_ID;
const EU_LENS: &str = fixtures::EU_LENS_ID;
const JP_LENS: &str = fixtures::JP_LENS_ID;
const DEMO_AT: &str = fixtures::DEMO_AS_OF;

static DIR_SEQ: AtomicUsize = AtomicUsize::new(0);

/// A unique scratch directory (OS temp; no cleanup dependency).
fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "unidpp-projector-it-{}-{}-{}",
        label,
        std::process::id(),
        DIR_SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir creates");
    dir
}

/// A registry seeded with the two lenses and the energy units.
async fn seeded_registry() -> RegistryServer {
    let registry = RegistryServer::spawn(RegistryConfig::default())
        .await
        .expect("registry spawns");
    register_lens(
        &registry,
        fixtures::eu_lens().registration_body("ferin:eu", "EU ESPR electronics lens"),
    )
    .await;
    register_lens(
        &registry,
        fixtures::jp_lens().registration_body("ferin:jp", "JP METI PSE lens"),
    )
    .await;
    register_unit(
        &registry,
        "unit-kwh",
        "kilowatt hour",
        "ISO 80000-4:2006 (energy); 1 kWh = 3.6 MJ exactly",
    )
    .await;
    register_unit(
        &registry,
        "unit-mj",
        "megajoule",
        "ISO 80000-4:2006 (energy)",
    )
    .await;
    registry
}

async fn post_json(url: &str, body: &Value) -> (u16, String) {
    let resp = json_request("POST", url, Some(&body.to_string()), None, TIMEOUT)
        .await
        .expect("request completes");
    (resp.status, resp.body_string())
}

async fn register_lens(registry: &RegistryServer, body: Value) {
    let (status, text) = post_json(&format!("{}/profiles", registry.base_url), &body).await;
    assert_eq!(status, 201, "lens registration failed: {text}");
}

async fn register_unit(registry: &RegistryServer, item: &str, name: &str, citation: &str) {
    let body = json!({
        "register_id": "unidpp-seed",
        "item_id": item,
        "class": "unit",
        "definition": name,
        "version": "1.0.0",
        "manifest": {
            "version": "1.0.0",
            "name": name,
            "iso_80000_citation": citation
        }
    });
    let (status, text) = post_json(&format!("{}/units", registry.base_url), &body).await;
    assert_eq!(status, 201, "unit registration failed: {text}");
}

/// A projector wired to the registry and a store holding the demo
/// passport document.
async fn wired_projector(registry_url: Option<String>) -> (TestServer, PathBuf) {
    let dir = scratch_dir("store");
    let path = dir.join("laptop.json");
    std::fs::write(&path, fixtures::demo_passport().to_json().unwrap())
        .expect("passport document writes");
    let config = Config {
        registry_url,
        passports_dir: Some(dir.clone()),
        ..Config::default()
    };
    let server = TestServer::spawn(config).await.expect("projector spawns");
    (server, dir)
}

async fn get_view(
    base: &str,
    passport: &str,
    profile: &str,
    actor: &str,
    at: Option<&str>,
) -> (u16, Value, Option<String>) {
    let mut query = format!(
        "?passport={}&profile={}&actor={}",
        Url::encode_query_component(passport),
        Url::encode_query_component(profile),
        Url::encode_query_component(actor)
    );
    if let Some(at) = at {
        query.push_str(&format!("&at={}", Url::encode_query_component(at)));
    }
    let resp = json_request("GET", &format!("{base}/view{query}"), None, None, TIMEOUT)
        .await
        .expect("view request completes");
    let as_of_header = resp.header("x-as-of").map(str::to_string);
    let body: Value = serde_json::from_str(&resp.body_string()).unwrap_or(Value::Null);
    (resp.status, body, as_of_header)
}

fn selected_element<'a>(view: &'a Value, element: &str) -> &'a Value {
    view["selected"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["element"].as_str() == Some(element))
        .unwrap_or(&Value::Null)
}

fn transformed<'a>(view: &'a Value, id: &str) -> &'a Value {
    view["transformed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"].as_str() == Some(id))
        .unwrap_or(&Value::Null)
}

#[tokio::test]
async fn two_lens_demo_eu_complete_jp_diverges() {
    let registry = seeded_registry().await;
    let (projector, _dir) = wired_projector(Some(registry.base_url.clone())).await;

    // --- the EU lens: complete coverage, class A ----------------------
    let (status, eu, as_of_header) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        EU_LENS,
        "customs",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 200, "{}", eu);
    assert_eq!(eu["service"], json!("unidpp-projector"));
    assert_eq!(eu["actor"], json!("customs"));
    assert_eq!(eu["as_of"], json!(DEMO_AT));
    assert_eq!(as_of_header.as_deref(), Some(DEMO_AT));
    assert_eq!(eu["profile"]["id"], json!(EU_LENS));
    assert_eq!(eu["profile"]["version"], json!("1.0.0"));
    assert_eq!(eu["profile"]["axes"], json!("EU x electronics x -"));
    assert_eq!(eu["profile"]["applies"], json!(true));
    assert_eq!(eu["profile"]["satisfiable"], json!(true));
    assert_eq!(eu["profile"]["source"], json!("registry"));
    assert_eq!(eu["passport"]["source"], json!("store"));
    assert_eq!(eu["passport"]["id"], json!(DEMO_PASSPORT));
    assert_eq!(eu["passport"]["status"], json!("issued"));
    assert_eq!(eu["coverage"]["elements_required"], json!(3));
    assert_eq!(eu["coverage"]["elements_present"], json!(3));
    assert_eq!(eu["coverage"]["complete"], json!(true));
    assert_eq!(eu["coverage"]["missing"].as_array().map(Vec::len), Some(0));

    // Values come from the twin state with their provenance.
    let operator = selected_element(&eu, "ferin:eu/de.dpp.operator-id@1.0.0");
    assert_eq!(operator["value"], json!("urn:unidpp:actor:oem-nordwave"));
    assert_eq!(operator["sourced"]["seq"], json!(4));
    assert_eq!(
        operator["sourced"]["actor_role"],
        json!("economic operator")
    );
    let score = selected_element(&eu, "ferin:eu/de.dpp.reparability-score@1.1.0");
    assert_eq!(score["value"], json!("8.1"));
    assert_eq!(score["kind"], json!("num"));
    let carbon = selected_element(&eu, "ferin:eu/de.dpp.carbon-footprint@1.2.0");
    assert_eq!(carbon["value"], json!("96.4"));
    assert_eq!(carbon["declared_unit"], json!("kgCO2e"));

    // The trust map: marker per element.
    assert_eq!(
        eu["trust"]["ferin:eu/de.dpp.operator-id@1.0.0"],
        json!("attested")
    );
    assert_eq!(
        eu["trust"]["ferin:eu/de.dpp.reparability-score@1.1.0"],
        json!("attested")
    );
    assert_eq!(
        eu["trust"]["ferin:eu/de.dpp.carbon-footprint@1.2.0"],
        json!("attested")
    );

    // The EU classification of the score.
    assert_eq!(
        transformed(&eu, "eu-reparability-class")["output"],
        json!("A")
    );
    assert_eq!(
        transformed(&eu, "eu-reparability-class")["band"]["min"],
        json!("8")
    );

    // --- the JP lens: same passport, different lens --------------------
    let (status, jp, _) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        JP_LENS,
        "customs",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 200, "{}", jp);
    assert_eq!(jp["profile"]["id"], json!(JP_LENS));
    assert_eq!(jp["profile"]["axes"], json!("JP x electronics x -"));
    assert_eq!(jp["profile"]["trigger"], json!("subject.markets ~ JP"));
    assert_eq!(jp["profile"]["applies"], json!(true));
    assert_eq!(jp["profile"]["source"], json!("registry"));

    // Coverage diverges: the top-runner-class data point is not
    // provided — the gap is explicit, with its reason.
    assert_eq!(jp["coverage"]["elements_required"], json!(3));
    assert_eq!(jp["coverage"]["elements_present"], json!(2));
    assert_eq!(jp["coverage"]["complete"], json!(false));
    let missing = jp["coverage"]["missing"].as_array().unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(
        missing[0]["element"],
        json!("ferin:jp/de.jp.top-runner-class@2026.1")
    );
    assert_eq!(missing[0]["reason"], json!("absent-as-of"));
    assert!(missing[0]["detail"].as_str().unwrap().contains("as-of"));

    // The JP facts that ARE provided.
    let pse = selected_element(&jp, "ferin:jp/de.jp.pse-mark@2.0.0");
    assert_eq!(pse["value"], json!("pse-square-95"));
    assert_eq!(
        pse["sourced"]["actor_id"],
        json!("urn:unidpp:actor:cab-meti-licensed")
    );
    assert_eq!(
        jp["trust"]["ferin:jp/de.jp.pse-mark@2.0.0"],
        json!("attested")
    );

    // The exact kWh -> MJ conversion with registered unit identity
    // (the units subregister's ISO 80000 citation chain).
    let capacity = transformed(&jp, "capacity-mj");
    assert_eq!(capacity["status"], json!("computed"));
    assert_eq!(capacity["input"], json!({"amount": "0.072", "unit": "kWh"}));
    assert_eq!(
        capacity["output"],
        json!({"amount": "0.2592", "unit": "MJ"})
    );
    assert_eq!(capacity["exact"], json!(true));
    assert_eq!(capacity["units"]["kWh"]["uom_registered"], json!(true));
    assert_eq!(capacity["units"]["kWh"]["item"], json!("unit-kwh"));
    assert!(capacity["units"]["kWh"]["citation"]
        .as_str()
        .unwrap()
        .contains("1 kWh = 3.6 MJ exactly"));
    assert_eq!(capacity["units"]["MJ"]["item"], json!("unit-mj"));
    assert_eq!(capacity["trust"], json!("attested"));

    // The same reparability score, classified differently by the JP
    // bands: EU says A, JP says class-2. Neither overrides the other.
    assert_eq!(
        transformed(&jp, "jp-reparability-class")["output"],
        json!("class-2")
    );
    assert_eq!(
        transformed(&eu, "eu-reparability-class")["output"],
        json!("A")
    );

    projector.stop().await;
    registry.stop().await;
}

#[tokio::test]
async fn as_of_reshapes_the_view() {
    let registry = seeded_registry().await;
    let (projector, _dir) = wired_projector(Some(registry.base_url.clone())).await;

    // 2026-12-15: the EU lens is not yet effective (from 2027-01-01)
    // and the milestone facts (2027-01-12) do not exist; the JP lens
    // already applies (the market fact landed 2026-12-01).
    let early = "2026-12-15T00:00:00Z";
    let (status, eu, _) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        EU_LENS,
        "customs",
        Some(early),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(eu["profile"]["applies"], json!(false));
    assert_eq!(eu["coverage"]["elements_present"], json!(1));
    assert_eq!(eu["coverage"]["elements_required"], json!(3));
    // The one present element is the operator id.
    assert_eq!(
        eu["trust"].as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["ferin:eu/de.dpp.operator-id@1.0.0"]
    );
    // The classification cannot run: its source is absent, and it
    // says so instead of guessing.
    assert_eq!(
        transformed(&eu, "eu-reparability-class")["status"],
        json!("failed")
    );

    let (status, jp, _) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        JP_LENS,
        "customs",
        Some(early),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(jp["profile"]["applies"], json!(true));
    assert_eq!(jp["coverage"]["elements_present"], json!(2));
    // The capacity conversion also degrades explicitly.
    assert_eq!(transformed(&jp, "capacity-mj")["status"], json!("failed"));
    assert!(transformed(&jp, "capacity-mj")["error"]
        .as_str()
        .unwrap()
        .contains("absent as-of"));

    // Later, the full state exists ("was it covered when sold?").
    let (status, eu_late, _) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        EU_LENS,
        "customs",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(eu_late["profile"]["applies"], json!(true));
    assert_eq!(eu_late["coverage"]["elements_present"], json!(3));
    // The as-of head differs because it is the hash of a different
    // log prefix.
    assert_ne!(eu["passport"]["log_head"], eu_late["passport"]["log_head"]);

    projector.stop().await;
    registry.stop().await;
}

#[tokio::test]
async fn registry_unreachable_falls_back_to_fixtures() {
    // Port 1 on loopback: reserved, nothing listens there.
    let (projector, _dir) = wired_projector(Some("http://127.0.0.1:1".into())).await;

    let (status, jp, _) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        JP_LENS,
        "customs",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 200, "{}", jp);
    assert_eq!(jp["profile"]["source"], json!("unreachable"));
    assert!(jp["profile"]["source_detail"]
        .as_str()
        .unwrap()
        .contains("not reachable"));
    // The projection still runs deterministically from the fixture
    // lens: same coverage gap, same classification, same conversion.
    assert_eq!(jp["coverage"]["elements_present"], json!(2));
    assert_eq!(
        transformed(&jp, "capacity-mj")["output"],
        json!({"amount": "0.2592", "unit": "MJ"})
    );
    // Fixture unit identities carry the same ISO 80000 citations.
    assert_eq!(
        transformed(&jp, "capacity-mj")["units"]["kWh"]["uom_registered"],
        json!(true)
    );

    // An unknown lens with a dead registry is a 503, not a silent
    // fixture invention.
    let (status, body, _) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        "urn:unidpp:profile:nowhere",
        "customs",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 503, "{body}");
    assert!(body["error"].as_str().unwrap().contains("unreachable"));

    projector.stop().await;
}

#[tokio::test]
async fn no_registry_configured_uses_fixtures() {
    let (projector, _dir) = wired_projector(None).await;
    let (status, eu, _) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        EU_LENS,
        "customs",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(eu["profile"]["source"], json!("fixtures"));
    assert!(eu["profile"]["source_detail"]
        .as_str()
        .unwrap()
        .contains("no registry URL configured"));
    assert_eq!(eu["coverage"]["elements_present"], json!(3));
    projector.stop().await;
}

#[tokio::test]
async fn projection_is_deterministic() {
    let registry = seeded_registry().await;
    let (projector, _dir) = wired_projector(Some(registry.base_url.clone())).await;
    let query = format!(
        "/view?passport={}&profile={}&actor=customs&at={}",
        Url::encode_query_component(DEMO_PASSPORT),
        Url::encode_query_component(JP_LENS),
        Url::encode_query_component(DEMO_AT)
    );
    let first = json_request(
        "GET",
        &format!("{}{}", projector.base_url, query),
        None,
        None,
        TIMEOUT,
    )
    .await
    .unwrap();
    let second = json_request(
        "GET",
        &format!("{}{}", projector.base_url, query),
        None,
        None,
        TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(first.status, 200);
    assert_eq!(
        first.body_string(),
        second.body_string(),
        "the same query must render identical bytes"
    );
    projector.stop().await;
    registry.stop().await;
}

#[tokio::test]
async fn unknowns_and_bad_params_are_rejected() {
    let registry = seeded_registry().await;
    let (projector, _dir) = wired_projector(Some(registry.base_url.clone())).await;

    // Unknown passport (registry live, store authoritative).
    let (status, body, _) = get_view(
        &projector.base_url,
        "urn:unidpp:passport:none-such",
        EU_LENS,
        "customs",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 404, "{body}");

    // Unknown profile item: the live registry's negative stands.
    let (status, body, _) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        "urn:unidpp:profile:none-such",
        "customs",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert!(body["error"].as_str().unwrap().contains("no profile item"));

    // Missing required parameters.
    let resp = json_request(
        "GET",
        &format!(
            "{}/view?passport={}&profile={}",
            projector.base_url, DEMO_PASSPORT, EU_LENS
        ),
        None,
        None,
        TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(resp.status, 400);

    // Bad as-of.
    let (status, body, _) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        EU_LENS,
        "customs",
        Some("yesterday"),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    projector.stop().await;
    registry.stop().await;
}

#[tokio::test]
async fn closed_resolution_lens_is_refused() {
    let registry = seeded_registry().await;
    // A third lens identical to the EU one but not servable.
    let mut body = fixtures::eu_lens().registration_body("ferin:eu", "closed test lens");
    body["item_id"] = json!("urn:unidpp:profile:test-closed");
    body["manifest"]["profile"]["id"] = json!("urn:unidpp:profile:test-closed");
    body["manifest"]["profile"]["resolution"] = json!("none");
    register_lens(&registry, body).await;

    let (projector, _dir) = wired_projector(Some(registry.base_url.clone())).await;
    let (status, resp, _) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        "urn:unidpp:profile:test-closed",
        "customs",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 403, "{resp}");
    assert!(resp["error"].as_str().unwrap().contains("not servable"));

    projector.stop().await;
    registry.stop().await;
}

#[tokio::test]
async fn fixture_mode_serves_the_demo_passport() {
    // Dev mode: no registry, no store — the built-in two-lens demo.
    let projector = TestServer::spawn(Config::default()).await.unwrap();
    let (status, eu, _) = get_view(
        &projector.base_url,
        DEMO_PASSPORT,
        EU_LENS,
        "market-surveillance-authority",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(eu["passport"]["source"], json!("fixture"));
    assert_eq!(eu["profile"]["source"], json!("fixtures"));
    assert_eq!(eu["coverage"]["elements_present"], json!(3));
    projector.stop().await;
}

#[tokio::test]
async fn demo_output_is_printable() {
    // Not an assertion test: renders the two-lens demonstration views
    // for human inspection (`cargo test -- --nocapture`).
    let registry = seeded_registry().await;
    let (projector, _dir) = wired_projector(Some(registry.base_url.clone())).await;
    for lens in [EU_LENS, JP_LENS] {
        let (status, view, _) = get_view(
            &projector.base_url,
            DEMO_PASSPORT,
            lens,
            "customs",
            Some(DEMO_AT),
        )
        .await;
        assert_eq!(status, 200);
        println!(
            "\n=== two-lens view: {lens} at {DEMO_AT} ===\n{}",
            serde_json::to_string_pretty(&view).unwrap()
        );
    }
    projector.stop().await;
    registry.stop().await;
}
