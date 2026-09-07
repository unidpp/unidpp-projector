//! Integration: the consumer presentation render (TODO.impl 54), the
//! aggregation transform class (TODO.impl 66), and the code-list
//! localization mappings (TODO.impl 67) against a real
//! `unidpp-registry` instance (seeded with the consumer lens, the
//! pack roll-up lens, and the EU-class/JP-star mapping items), driven
//! over hand-rolled HTTP (house pattern).
//!
//! One corpus carries the two transform items: the battery-pack
//! system passport (a derived issuance over three pack children, each
//! input pinning the child's log head) and its EU lens — the carbon
//! roll-up cites ISO 14067, the mass-weighted SoH average divides
//! exactly, and the system's EU energy-label class localizes to the
//! JP star display through a versioned mapping item.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{json, Value};
use unidpp_projector::http::{json_request, Url};
use unidpp_projector::{fixtures, Config, RollupSealer, TestServer};
use unidpp_registry::{Config as RegistryConfig, TestServer as RegistryServer};
use unidpp_signatif::rollup::check_rollup_signature;
use unidpp_transform::quantity::UnitRegistry;
use unidpp_transform::rollup::{
    verify_rollup, RollupAttestation, RollupVerdict, TraversalMember, TraversalSet,
};

const TIMEOUT: Duration = Duration::from_secs(5);
const DEMO_PASSPORT: &str = fixtures::DEMO_PASSPORT_ID;
const DEMO_AT: &str = fixtures::DEMO_AS_OF;
const PACK_SYSTEM: &str = fixtures::PACK_SYSTEM_ID;
const PACK_LENS: &str = fixtures::PACK_LENS_ID;
const CONSUMER_LENS: &str = fixtures::CONSUMER_LENS_ID;
const MAPPING_ID: &str = fixtures::EU_CLASS_TO_JP_STAR_ID;

static DIR_SEQ: AtomicUsize = AtomicUsize::new(0);

/// A unique scratch directory (OS temp; no cleanup dependency).
fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "unidpp-projector-it2-{}-{}-{}",
        label,
        std::process::id(),
        DIR_SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir creates");
    dir
}

async fn post_json(url: &str, body: &Value) -> (u16, String) {
    let resp = json_request("POST", url, Some(&body.to_string()), None, TIMEOUT)
        .await
        .expect("request completes");
    (resp.status, resp.body_string())
}

/// A registry seeded with the consumer lens, the pack lens, the unit
/// items, the Primmel battery package, and both correspondence items.
async fn seeded_registry() -> RegistryServer {
    let registry = RegistryServer::spawn(RegistryConfig::default())
        .await
        .expect("registry spawns");
    for (lens, register, definition) in [
        (
            fixtures::consumer_lens(),
            "ferin:eu",
            "Consumer presentation lens (product / repair / recycling, en + ja)",
        ),
        (
            fixtures::pack_lens(),
            "ferin:eu",
            "EU battery-pack-system roll-up lens (carbon sum, weighted SoH, star display)",
        ),
    ] {
        let (status, text) = post_json(
            &format!("{}/profiles", registry.base_url),
            &lens.registration_body(register, definition),
        )
        .await;
        assert_eq!(status, 201, "lens registration failed: {text}");
    }
    register_mapping(&registry, &fixtures::eu_class_to_jp_star_mapping()).await;
    register_mapping(&registry, &fixtures::jp_star_to_eu_class_mapping()).await;
    registry
}

async fn register_mapping(registry: &RegistryServer, mapping: &unidpp_projector::CodeListMapping) {
    let body = json!({
        "register_id": "unidpp-seed",
        "item_id": mapping.id,
        "class": "transform",
        "definition": "Registered code-list correspondence (TODO.impl 67)",
        "version": mapping.version,
        "manifest": serde_json::to_value(mapping).unwrap()
    });
    let (status, text) = post_json(&format!("{}/transforms", registry.base_url), &body).await;
    assert_eq!(status, 201, "mapping registration failed: {text}");
}

/// A projector wired to the registry and a store holding the given
/// passport documents.
async fn wired_projector(
    registry_url: Option<String>,
    passports: Vec<unidpp_cli::passport::Passport>,
) -> (TestServer, PathBuf) {
    projector_with_config(registry_url, passports, |_| {}).await
}

/// [`wired_projector`] with a final configuration pass (the roll-up
/// sealer tests arm the key the default projector does not hold).
async fn projector_with_config(
    registry_url: Option<String>,
    passports: Vec<unidpp_cli::passport::Passport>,
    tune: impl FnOnce(&mut Config),
) -> (TestServer, PathBuf) {
    let dir = scratch_dir("store");
    for (i, passport) in passports.into_iter().enumerate() {
        std::fs::write(
            dir.join(format!("passport-{i:02}.json")),
            passport.to_json().unwrap(),
        )
        .expect("passport document writes");
    }
    let mut config = Config {
        registry_url,
        passports_dir: Some(dir.clone()),
        ..Config::default()
    };
    tune(&mut config);
    let server = TestServer::spawn(config).await.expect("projector spawns");
    (server, dir)
}

async fn get(base: &str, path_and_query: &str) -> (u16, Value, Option<String>) {
    let resp = json_request(
        "GET",
        &format!("{base}{path_and_query}"),
        None,
        None,
        TIMEOUT,
    )
    .await
    .expect("request completes");
    let as_of_header = resp.header("x-as-of").map(str::to_string);
    let body: Value = serde_json::from_str(&resp.body_string()).unwrap_or(Value::Null);
    (resp.status, body, as_of_header)
}

async fn get_render(
    base: &str,
    passport: &str,
    profile: &str,
    lang: &str,
    at: Option<&str>,
) -> (u16, Value) {
    let mut query = format!(
        "?passport={}&profile={}&lang={}",
        Url::encode_query_component(passport),
        Url::encode_query_component(profile),
        Url::encode_query_component(lang)
    );
    if let Some(at) = at {
        query.push_str(&format!("&at={}", Url::encode_query_component(at)));
    }
    let (status, body, _) = get(base, &format!("/render{query}")).await;
    (status, body)
}

async fn get_view(base: &str, passport: &str, profile: &str, at: &str) -> (u16, Value) {
    let query = format!(
        "?passport={}&profile={}&actor=customs&at={}",
        Url::encode_query_component(passport),
        Url::encode_query_component(profile),
        Url::encode_query_component(at)
    );
    let (status, body, _) = get(base, &format!("/view{query}")).await;
    (status, body)
}

fn transformed<'a>(view: &'a Value, id: &str) -> &'a Value {
    view["transformed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"].as_str() == Some(id))
        .unwrap_or(&Value::Null)
}

fn section<'a>(render: &'a Value, id: &str) -> &'a Value {
    render["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"].as_str() == Some(id))
        .unwrap_or(&Value::Null)
}

fn item<'a>(render: &'a Value, section_id: &str, element: &str) -> &'a Value {
    section(render, section_id)["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["element"].as_str() == Some(element))
        .unwrap_or(&Value::Null)
}

// ---------------------------------------------------------------------------
// #54 — the consumer presentation render
// ---------------------------------------------------------------------------

#[tokio::test]
async fn render_presents_two_languages_from_one_profile() {
    let registry = seeded_registry().await;
    let (projector, _dir) = wired_projector(
        Some(registry.base_url.clone()),
        vec![fixtures::demo_passport()],
    )
    .await;

    for (lang, product_label, carbon_label) in [
        ("en", "Product", "Carbon footprint"),
        ("ja", "製品情報", "炭素フットプリント"),
    ] {
        let (status, render) = get_render(
            &projector.base_url,
            DEMO_PASSPORT,
            CONSUMER_LENS,
            lang,
            Some(DEMO_AT),
        )
        .await;
        assert_eq!(status, 200, "{}", render);
        assert_eq!(render["service"], json!("unidpp-projector"));
        let metadata = &render["render_metadata"];
        assert_eq!(
            metadata["template_ref"],
            json!("urn:unidpp:template:consumer-v1")
        );
        assert_eq!(metadata["lang"], json!(lang));
        assert_eq!(metadata["fallback_lang"], json!("en"));
        assert_eq!(
            metadata["formatting_rules"],
            json!({"unit_position": "suffix", "decimal_digits": 1, "fallback_lang": "en"})
        );
        assert_eq!(metadata["as_of"], json!(DEMO_AT));
        assert_eq!(metadata["profile"]["id"], json!(CONSUMER_LENS));
        assert_eq!(metadata["profile"]["source"], json!("registry"));

        // Sections in binding order, localized.
        let ids: Vec<&str> = render["sections"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["id"].as_str())
            .collect();
        assert_eq!(ids, vec!["product", "repair", "recycling"]);
        assert_eq!(section(&render, "product")["label"], json!(product_label));
        assert_eq!(section(&render, "product")["label_lang"], json!(lang));

        // The carbon item: localized label, formatted value with unit,
        // exact value, link to the authoritative view.
        let carbon = item(&render, "recycling", fixtures::CARBON_ELEMENT);
        assert_eq!(carbon["label"], json!(carbon_label));
        assert_eq!(carbon["formatted"], json!("96.4 kgCO2e"));
        assert_eq!(carbon["value"], json!("96.4"));
        assert_eq!(carbon["unit"], json!("kgCO2e"));
        assert_eq!(carbon["status"], json!("present"));
        assert_eq!(carbon["trust"], json!("attested"));
        let view_link = carbon["source"]["view"].as_str().unwrap();
        assert!(view_link.contains("/view?passport="), "{view_link}");
        assert!(view_link.contains("at=2027-02-11"), "{view_link}");

        // The recycling instruction is deliberately absent: an
        // explicit gap item and the coverage report state it.
        let instruction = item(&render, "recycling", fixtures::INSTRUCTION_ELEMENT);
        assert_eq!(instruction["status"], json!("missing"));
        assert_eq!(instruction["reason"], json!("absent-as-of"));
        assert_eq!(render["coverage"]["elements_required"], json!(5));
        assert_eq!(render["coverage"]["elements_present"], json!(4));
        assert!(!render["coverage"]["complete"].as_bool().unwrap());
    }

    projector.stop().await;
    registry.stop().await;
}

#[tokio::test]
async fn render_falls_back_when_the_language_has_no_labels() {
    let registry = seeded_registry().await;
    let (projector, _dir) = wired_projector(
        Some(registry.base_url.clone()),
        vec![fixtures::demo_passport()],
    )
    .await;
    let (status, render) = get_render(
        &projector.base_url,
        DEMO_PASSPORT,
        CONSUMER_LENS,
        "fr",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 200, "{}", render);
    // French was requested; no label carries it — the fallback
    // language serves and the render states which language served.
    assert_eq!(render["render_metadata"]["lang"], json!("fr"));
    assert_eq!(section(&render, "repair")["label"], json!("Repair"));
    assert_eq!(section(&render, "repair")["label_lang"], json!("en"));
    let score = item(&render, "repair", fixtures::REPARABILITY_ELEMENT);
    assert_eq!(score["label"], json!("Reparability score"));
    assert_eq!(score["label_lang"], json!("en"));

    // A lens without a presentation binding is refused — `/render`
    // needs one, `/view` serves it. (The EU lens must be in the
    // registry for the refusal to be about the presentation.)
    let (status, text) = post_json(
        &format!("{}/profiles", registry.base_url),
        &fixtures::eu_lens().registration_body("ferin:eu", "EU ESPR electronics lens"),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    let (status, body) = get_render(
        &projector.base_url,
        DEMO_PASSPORT,
        fixtures::EU_LENS_ID,
        "en",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body["error"].as_str().unwrap().contains("no presentation"));

    // Missing lang parameter: 400 (the render is per-language).
    let resp = json_request(
        "GET",
        &format!(
            "{}/render?passport={}&profile={}",
            projector.base_url, DEMO_PASSPORT, CONSUMER_LENS
        ),
        None,
        None,
        TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(resp.status, 400);

    // Unknown passport: 404 like the view.
    let (status, _) = get_render(
        &projector.base_url,
        "urn:unidpp:passport:none",
        CONSUMER_LENS,
        "en",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 404);

    projector.stop().await;
    registry.stop().await;
}

#[tokio::test]
async fn render_works_in_fixture_mode() {
    // Dev mode: no registry, no store — the built-in demo renders and
    // states its sources.
    let projector = TestServer::spawn(Config::default()).await.unwrap();
    let (status, render) = get_render(
        &projector.base_url,
        DEMO_PASSPORT,
        CONSUMER_LENS,
        "ja",
        Some(DEMO_AT),
    )
    .await;
    assert_eq!(status, 200, "{}", render);
    assert_eq!(
        render["render_metadata"]["profile"]["source"],
        json!("fixtures")
    );
    assert_eq!(render["passport"]["source"], json!("fixture"));
    assert_eq!(
        item(&render, "product", fixtures::OPERATOR_ELEMENT)["formatted"],
        json!("urn:unidpp:actor:oem-nordwave")
    );
    projector.stop().await;
}

// ---------------------------------------------------------------------------
// #66 — the aggregation transform class
// ---------------------------------------------------------------------------

#[tokio::test]
async fn carbon_rollup_cites_its_method_across_three_packs() {
    let registry = seeded_registry().await;
    let mut store = vec![fixtures::pack_system()];
    store.extend(fixtures::pack_children());
    let (projector, _dir) = wired_projector(Some(registry.base_url.clone()), store).await;

    let (status, view) = get_view(&projector.base_url, PACK_SYSTEM, PACK_LENS, DEMO_AT).await;
    assert_eq!(status, 200, "{}", view);

    // The pack elements live on the children: the subject-level
    // coverage reports them absent — honestly — while the roll-up
    // computes over the traversal set.
    assert_eq!(view["coverage"]["elements_required"], json!(4));
    assert_eq!(view["coverage"]["elements_present"], json!(1));
    assert_eq!(
        view["selected"][0]["element"],
        json!(fixtures::ENERGY_LABEL_ELEMENT)
    );

    // 31.5 + 33.0 + 25.5 = 90 kgCO2e, citing ISO 14067, committed to
    // the input set's root hash.
    let rollup = transformed(&view, "carbon-rollup");
    assert_eq!(rollup["kind"], json!("aggregation"));
    assert_eq!(rollup["operation"], json!("sum"));
    assert_eq!(rollup["method_citation"], json!("ISO 14067:2018"));
    assert_eq!(rollup["status"], json!("computed"));
    assert_eq!(rollup["output"], json!({"amount": "90", "unit": "kgCO2e"}));
    assert_eq!(rollup["children_required"], json!(3));
    assert_eq!(rollup["children_provided"], json!(3));
    assert_eq!(rollup["input_set_root"].as_str().unwrap().len(), 64);
    let inputs = rollup["inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 3);
    for input in inputs {
        assert_eq!(input["trust"], json!("attested"));
        assert!(input["log_head"].as_str().unwrap().len() >= 16);
    }

    // The mass-weighted SoH average: 3553 / 40 = 88.825 exactly.
    let average = transformed(&view, "soh-weighted-average");
    assert_eq!(average["status"], json!("computed"));
    assert_eq!(average["output"], json!({"amount": "88.825", "unit": "%"}));
    assert_eq!(average["method_citation"], json!("IEC 62660-1:2018"));

    // Deterministic bytes for the same query.
    let (_, again) = get_view(&projector.base_url, PACK_SYSTEM, PACK_LENS, DEMO_AT).await;
    assert_eq!(view, again);

    projector.stop().await;
    registry.stop().await;
}

#[tokio::test]
async fn missing_child_is_a_coverage_gap_over_http() {
    let registry = seeded_registry().await;
    // The store holds the system and only two of the three packs: the
    // roll-up computes over the two provided children and reports the
    // third as a document gap — never an error.
    let mut store = vec![fixtures::pack_system()];
    store.extend(fixtures::pack_children().into_iter().take(2));
    let (projector, _dir) = wired_projector(Some(registry.base_url.clone()), store).await;

    let (status, view) = get_view(&projector.base_url, PACK_SYSTEM, PACK_LENS, DEMO_AT).await;
    assert_eq!(status, 200, "{}", view);
    let rollup = transformed(&view, "carbon-rollup");
    assert_eq!(rollup["status"], json!("missing-children"));
    assert_eq!(rollup["output"]["amount"], json!("64.5"));
    assert_eq!(rollup["method_citation"], json!("ISO 14067:2018"));
    let missing = rollup["missing_children"].as_array().unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0]["passport"], json!(fixtures::PACK_CHILD_IDS[2]));
    assert_eq!(missing[0]["reason"], json!("document-unavailable"));
    // The rest of the view still renders.
    assert_eq!(view["profile"]["source"], json!("registry"));

    projector.stop().await;
    registry.stop().await;
}

#[tokio::test]
async fn sealed_rollup_attestation_travels_over_http_and_verifies() {
    let registry = seeded_registry().await;
    let mut store = vec![fixtures::pack_system()];
    store.extend(fixtures::pack_children());
    const SEED: &str = "it-rollup-seed";
    const ATTESTER: &str = "urn:unidpp:eo:projector";
    let (projector, _dir) =
        projector_with_config(Some(registry.base_url.clone()), store, |config| {
            config.rollup_seed = Some(SEED.to_string());
            config.rollup_attester = Some(ATTESTER.to_string());
        })
        .await;

    let (status, view) = get_view(&projector.base_url, PACK_SYSTEM, PACK_LENS, DEMO_AT).await;
    assert_eq!(status, 200, "{}", view);
    let rollup = transformed(&view, "carbon-rollup");
    assert_eq!(rollup["status"], json!("computed"));

    // The canonical root over the same children, built straight from
    // the core types: what the entry carries and the attestation
    // seals are the same commitment.
    let at = fixtures::demo_as_of();
    let members: Vec<TraversalMember> = fixtures::pack_children()
        .iter()
        .map(|child| TraversalMember {
            passport: child.passport_id.clone(),
            version: 1,
            state_hash: child.log.state_hash_at(at).unwrap(),
            quantities: std::collections::BTreeMap::new(),
        })
        .collect();
    let set = TraversalSet::new(members).unwrap();
    assert_eq!(rollup["input_set_root"].as_str().unwrap(), set.root().hex());

    // The attestation deserializes from the wire and verifies against
    // the pinned anchor (the same seed's public key).
    let attestation: RollupAttestation = serde_json::from_value(rollup["rollup"].clone()).unwrap();
    assert_eq!(attestation.subject, fixtures::pack_system().passport_id);
    assert_eq!(attestation.method_ref, "ISO 14067:2018");
    let sealer = RollupSealer::seeded(SEED, ATTESTER).unwrap();
    let anchor = sealer.public().unwrap();
    let verdict = verify_rollup(
        &attestation,
        &set,
        &UnitRegistry::iso80000(),
        |slot, body| check_rollup_signature(slot, body, anchor),
    );
    assert_eq!(verdict, RollupVerdict::Verified);

    // A second view seals the same commitment: the roots are stable
    // across runs (the signatures differ by their attested moments,
    // by design).
    let (_, again) = get_view(&projector.base_url, PACK_SYSTEM, PACK_LENS, DEMO_AT).await;
    assert_eq!(
        transformed(&again, "carbon-rollup")["input_set_root"],
        rollup["input_set_root"]
    );

    projector.stop().await;
    registry.stop().await;
}

// ---------------------------------------------------------------------------
// #67 — the code-list localization mappings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn eu_class_localizes_to_the_jp_star_display() {
    let registry = seeded_registry().await;
    let mut store = vec![fixtures::pack_system()];
    store.extend(fixtures::pack_children());
    let (projector, _dir) = wired_projector(Some(registry.base_url.clone()), store).await;

    let (status, view) = get_view(&projector.base_url, PACK_SYSTEM, PACK_LENS, DEMO_AT).await;
    assert_eq!(status, 200, "{}", view);
    let stars = transformed(&view, "jp-star-display");
    assert_eq!(stars["kind"], json!("localization-mapping"));
    assert_eq!(stars["status"], json!("computed"));
    assert_eq!(stars["input"], json!("B"));
    assert_eq!(stars["output"], json!("★★★★"));
    // The registered item served it: identity, version, schemes and
    // citation travel with the mapped value.
    assert_eq!(stars["mapping"]["id"], json!(MAPPING_ID));
    assert_eq!(stars["mapping"]["version"], json!("1.0.0"));
    assert_eq!(stars["mapping"]["source"], json!("registry"));
    assert_eq!(
        stars["mapping"]["source_scheme"],
        json!("urn:eu:reg:2017:1369#annex-ii-class")
    );

    projector.stop().await;
    registry.stop().await;
}

#[tokio::test]
async fn the_mapping_item_is_versioned_like_any_registry_item() {
    // Supersede the correspondence with a v1.1.0 whose table drops
    // the B row: the projector serves the new version, and B — a
    // value the registered table no longer carries — maps to the
    // explicit `unmapped` output, never a silent pass.
    let registry = seeded_registry().await;
    let mut narrowed = fixtures::eu_class_to_jp_star_mapping();
    narrowed.version = "1.1.0".to_string();
    narrowed.table.retain(|e| e.source_value != "B");
    let (status, text) = post_json(
        &format!(
            "{}/items/{}/versions",
            registry.base_url,
            Url::encode_path_segment(MAPPING_ID)
        ),
        &json!({
            "version": "1.1.0",
            "reason": "narrowed correspondence (v1.1.0)",
            "manifest": serde_json::to_value(&narrowed).unwrap()
        }),
    )
    .await;
    assert_eq!(status, 201, "mapping supersession failed: {text}");

    let mut store = vec![fixtures::pack_system()];
    store.extend(fixtures::pack_children());
    let (projector, _dir) = wired_projector(Some(registry.base_url.clone()), store).await;

    let (status, view) = get_view(&projector.base_url, PACK_SYSTEM, PACK_LENS, DEMO_AT).await;
    assert_eq!(status, 200, "{}", view);
    let stars = transformed(&view, "jp-star-display");
    assert_eq!(stars["mapping"]["version"], json!("1.1.0"));
    assert_eq!(stars["status"], json!("unmapped"));
    assert_eq!(stars["output"], json!("unmapped"));
    assert_eq!(stars["input"], json!("B"));
    assert!(stars["detail"].as_str().unwrap().contains("`B`"));

    projector.stop().await;
    registry.stop().await;
}

#[tokio::test]
async fn mapping_degrades_to_fixtures_and_reports_the_source() {
    // A registry WITHOUT the mapping item: the live negative stands —
    // the binding fails honestly instead of inventing a fixture.
    let registry = RegistryServer::spawn(RegistryConfig::default())
        .await
        .expect("registry spawns");
    let (status, body) = post_json(
        &format!("{}/profiles", registry.base_url),
        &fixtures::pack_lens().registration_body("ferin:eu", "pack lens"),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let mut store = vec![fixtures::pack_system()];
    store.extend(fixtures::pack_children());
    let (projector, _dir) = wired_projector(Some(registry.base_url.clone()), store).await;
    let (status, view) = get_view(&projector.base_url, PACK_SYSTEM, PACK_LENS, DEMO_AT).await;
    assert_eq!(status, 200, "{}", view);
    let stars = transformed(&view, "jp-star-display");
    assert_eq!(stars["status"], json!("failed"));
    assert!(stars["error"].as_str().unwrap().contains("not available"));
    projector.stop().await;
    registry.stop().await;

    // No registry at all: the built-in fixtures serve the mapping and
    // the transform entry says which source served.
    let mut fixture_store = vec![fixtures::pack_system()];
    fixture_store.extend(fixtures::pack_children());
    let (projector, _dir) = wired_projector(None, fixture_store).await;
    let (status, view) = get_view(&projector.base_url, PACK_SYSTEM, PACK_LENS, DEMO_AT).await;
    assert_eq!(status, 200, "{}", view);
    let stars = transformed(&view, "jp-star-display");
    assert_eq!(stars["status"], json!("computed"));
    assert_eq!(stars["output"], json!("★★★★"));
    assert_eq!(stars["mapping"]["source"], json!("fixtures"));
    assert_eq!(stars["mapping"]["version"], json!("1.0.0"));
    projector.stop().await;
}
