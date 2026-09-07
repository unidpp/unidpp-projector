//! Primmel rule packages for the transform path (TODO.impl C9).
//!
//! A **Primmel package** is a versioned set of *deterministic decision
//! rules*, each rule carrying the clause URN of the legal paragraph it
//! implements. The projector binds a rule into a lens manifest's
//! transform list ([`crate::lens::TransformBinding::Primmel`]) and
//! evaluates it over the selected twin facts; the transformed output
//! then states `clause_urn` — the rule's normative provenance — so a
//! derived verdict is traceable to the paragraph that demands it
//! (decision provenance, the rule-side sibling of unit provenance).
//!
//! The shape follows the Primmel corpus (primmel-ts / mmel): a package
//! manifest with an edition-pinned version, rules as machine-checkable
//! limits, acceptance decisions `shared_risk | guarded` with a guard
//! band, and source provenance `{ doc, clause }` addressed as
//! `urn:<doc>#clause-N.M` (the fragment grammar of the .prd address
//! space). What is implemented here is the *consumption* slice: the
//! smallest package a projector can execute — no subject models, no
//! processes, just typed rules.
//!
//! # Wire schema (a `.prml` file is this JSON)
//!
//! ```json
//! {
//!   "id": "urn:primmel:pkg:battery-rules",
//!   "version": "1.0.0",
//!   "title": "Battery passport decision rules",
//!   "rules": [
//!     {
//!       "id": "soh-guard-band",
//!       "clause_urn": "urn:oiml:pub:r:91-2:2025#clause-6.1",
//!       "title": "State of health >= 85 %, guarded with w = U",
//!       "arms": [
//!         { "label": "conforming",
//!           "when": { "op": "ge",
//!                     "lhs": { "sub": [ { "input": "soh" }, { "input": "U" } ] },
//!                     "rhs": { "const": "85" } } },
//!         { "label": "not-demonstrably-conforming" }
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! - `id` — the package URN (what a lens binding's `package_ref`
//!   names); `version` — the edition pin, recorded in every output.
//! - `rules[].clause_urn` — the legal paragraph the rule implements
//!   (`urn:<document>#clause-…`); never empty, travels to the view.
//! - `rules[].arms` — an ordered decision table, **first match wins**;
//!   an arm without `when` is the unconditional (else) arm and may
//!   only appear last. When no arm matches and no else arm exists the
//!   outcome is the explicit label `unclassified` (never silent).
//! - Numeric sub-expressions (`Expr`): `{"input": "<name>"}`,
//!   `{"const": "<exact decimal>"}`, `{"add"|"sub"|"mul": [e, e]}`,
//!   and `{"round": {"of": e, "decimals": n, "mode": "half-up" |
//!   "half-even" | "truncate"}}`. Comparisons (`Predicate`): `{"op":
//!   "lt"|"le"|"gt"|"ge"|"eq"|"ne", "lhs": e, "rhs": e}`.
//!
//! # Determinism taxonomy (house doctrine)
//!
//! 1. **Determinism** — evaluation is a pure function of (rule,
//!    resolved inputs): exact-decimal arithmetic (never floats),
//!    ordered arms, no wall clock, no environment. The same package
//!    and inputs always produce the same label.
//! 2. **Explicit rounding** — values are never rounded implicitly;
//!    rounding exists only as the `round` expression node, with the
//!    mode and digit count stated in the package.
//! 3. **GUM propagation** — measurement uncertainty is not recomputed
//!    here: the expanded uncertainty `U` (ISO/IEC Guide 98-3) enters
//!    as a *named input*, and guard-band rules apply `w = U` in the
//!    comparison (`soh - U >= 85`, Guide 98-4 guarded acceptance —
//!    the R 91-2 verdict-criterion taxonomy): the rule decides on the
//!    measurand narrowed by its stated uncertainty, exactly and
//!    traceably.

use std::collections::BTreeMap;

use serde_json::Value;
use unidpp_model::Decimal;

/// A numeric sub-expression: deterministic, exact-decimal, over named
/// inputs and constants.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Expr {
    /// A named input, resolved by the lens binding to a twin fact.
    Input { input: String },
    /// An exact decimal constant.
    Const {
        #[serde(rename = "const")]
        value: Decimal,
    },
    /// `a + b`.
    Add { add: Box<[Expr; 2]> },
    /// `a - b`.
    Sub { sub: Box<[Expr; 2]> },
    /// `a * b`.
    Mul { mul: Box<[Expr; 2]> },
    /// Explicit rounding — the only rounding that exists.
    Round { round: RoundSpec },
}

/// The explicit rounding declaration of an [`Expr::Round`] node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoundSpec {
    /// The expression to round.
    pub of: Box<Expr>,
    /// Digits kept after the decimal point (0..=18).
    pub decimals: u8,
    /// How midpoints resolve.
    pub mode: RoundingMode,
}

/// How an explicit rounding node resolves the discarded digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoundingMode {
    /// Half away from zero.
    HalfUp,
    /// Half to even (banker's rounding).
    HalfEven,
    /// Toward zero, midpoints included.
    Truncate,
}

/// A comparison between two numeric sub-expressions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Predicate {
    /// The comparison operator.
    pub op: CmpOp,
    /// Left side.
    pub lhs: Expr,
    /// Right side.
    pub rhs: Expr,
}

/// The comparison operators a rule predicate supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

impl CmpOp {
    fn holds(self, lhs: &Decimal, rhs: &Decimal) -> bool {
        use std::cmp::Ordering::*;
        match self {
            CmpOp::Lt => lhs < rhs,
            CmpOp::Le => lhs <= rhs,
            CmpOp::Gt => lhs > rhs,
            CmpOp::Ge => lhs >= rhs,
            CmpOp::Eq => lhs.cmp(rhs) == Equal,
            CmpOp::Ne => lhs.cmp(rhs) != Equal,
        }
    }
}

/// One arm of a rule's decision table: `label` applies when `when`
/// holds (an arm without `when` is the unconditional else arm).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Arm {
    /// The outcome label (e.g. `conforming`, `B`).
    pub label: String,
    /// The guard; `None` = the else arm (last position only).
    #[serde(default)]
    pub when: Option<Predicate>,
}

/// One deterministic decision rule with its clause-URN provenance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrimmelRule {
    /// The rule id within its package (what a lens binding names).
    pub id: String,
    /// The legal paragraph this rule implements (`urn:…#clause-…`).
    pub clause_urn: String,
    /// Human-readable statement of the rule.
    #[serde(default)]
    pub title: Option<String>,
    /// The ordered decision table; first matching arm wins.
    pub arms: Vec<Arm>,
}

/// The label an unguarded rule yields when no arm matches (explicit,
/// never silent).
pub const UNCLASSIFIED: &str = "unclassified";

/// Why a rule could not be evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    /// A named input has no value in the environment (a coverage gap,
    /// reported as such — not an error).
    MissingInput { input: String },
    /// A named input resolved to a non-numeric fact (a type failure).
    NotNumeric { input: String },
    /// Exact arithmetic failed (overflow beyond the decimal domain).
    Arithmetic(String),
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalError::MissingInput { input } => {
                write!(f, "input `{input}` has no value")
            }
            EvalError::NotNumeric { input } => {
                write!(f, "input `{input}` is not a numeric fact")
            }
            EvalError::Arithmetic(why) => write!(f, "arithmetic failed: {why}"),
        }
    }
}

/// The outcome of evaluating a rule: the winning arm's label, or the
/// explicit [`UNCLASSIFIED`] fall-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleOutcome {
    /// The winning label (`unclassified` when no arm matched).
    pub label: String,
    /// The index of the winning arm; `None` on fall-through.
    pub matched_arm: Option<usize>,
}

impl PrimmelRule {
    /// The named inputs this rule consumes, in declaration order.
    pub fn inputs(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for arm in &self.arms {
            if let Some(p) = &arm.when {
                collect_inputs(&p.lhs, &mut seen);
                collect_inputs(&p.rhs, &mut seen);
            }
        }
        seen
    }

    /// Evaluate the decision table over resolved inputs: first arm
    /// whose guard holds wins; the else arm wins unconditionally; no
    /// match yields [`UNCLASSIFIED`]. Pure and deterministic.
    pub fn evaluate(&self, inputs: &BTreeMap<String, Decimal>) -> Result<RuleOutcome, EvalError> {
        for (index, arm) in self.arms.iter().enumerate() {
            let Some(when) = &arm.when else {
                return Ok(RuleOutcome {
                    label: arm.label.clone(),
                    matched_arm: Some(index),
                });
            };
            let lhs = eval_expr(&when.lhs, inputs)?;
            let rhs = eval_expr(&when.rhs, inputs)?;
            if when.op.holds(&lhs, &rhs) {
                return Ok(RuleOutcome {
                    label: arm.label.clone(),
                    matched_arm: Some(index),
                });
            }
        }
        Ok(RuleOutcome {
            label: UNCLASSIFIED.to_string(),
            matched_arm: None,
        })
    }
}

/// The operand pair of a binary node (`add`/`sub`/`mul`).
fn operands(expr: &Expr) -> Option<&[Expr; 2]> {
    match expr {
        Expr::Add { add } => Some(add),
        Expr::Sub { sub } => Some(sub),
        Expr::Mul { mul } => Some(mul),
        Expr::Input { .. } | Expr::Const { .. } | Expr::Round { .. } => None,
    }
}

fn collect_inputs(expr: &Expr, seen: &mut Vec<String>) {
    match expr {
        Expr::Input { input } => {
            if !seen.iter().any(|s| s == input) {
                seen.push(input.clone());
            }
        }
        Expr::Const { .. } => {}
        Expr::Add { .. } | Expr::Sub { .. } | Expr::Mul { .. } => {
            if let Some(pair) = operands(expr) {
                for e in pair.iter() {
                    collect_inputs(e, seen);
                }
            }
        }
        Expr::Round { round } => collect_inputs(&round.of, seen),
    }
}

fn eval_expr(expr: &Expr, inputs: &BTreeMap<String, Decimal>) -> Result<Decimal, EvalError> {
    match expr {
        Expr::Input { input } => {
            inputs
                .get(input)
                .copied()
                .ok_or_else(|| EvalError::MissingInput {
                    input: input.clone(),
                })
        }
        Expr::Const { value } => Ok(*value),
        Expr::Add { .. } | Expr::Sub { .. } | Expr::Mul { .. } => {
            let Some(pair) = operands(expr) else {
                return Ok(Decimal::zero());
            };
            let a = eval_expr(&pair[0], inputs)?;
            let b = eval_expr(&pair[1], inputs)?;
            let computed = match expr {
                Expr::Add { .. } => a.add(&b),
                Expr::Sub { .. } => a.sub(&b),
                _ => a.mul(&b),
            };
            computed.map_err(|e| EvalError::Arithmetic(e.to_string()))
        }
        Expr::Round { round } => {
            let of = eval_expr(&round.of, inputs)?;
            round_decimal(of, round.decimals, round.mode)
        }
    }
}

/// Explicit rounding on the exact decimal: keep `decimals` fractional
/// digits, resolve midpoints by `mode`. No other rounding exists in
/// the evaluator.
fn round_decimal(v: Decimal, decimals: u8, mode: RoundingMode) -> Result<Decimal, EvalError> {
    if decimals > 18 {
        return Err(EvalError::Arithmetic(format!(
            "rounding to {decimals} decimals exceeds the decimal domain"
        )));
    }
    let target = -(decimals as i32);
    if v.exp >= target {
        // Scale up exactly; nothing is discarded.
        let factor = 10i128
            .checked_pow((v.exp - target) as u32)
            .ok_or_else(|| EvalError::Arithmetic("rounding scale overflow".into()))?;
        let mant = v
            .mant
            .checked_mul(factor)
            .ok_or_else(|| EvalError::Arithmetic("rounding scale overflow".into()))?;
        return Decimal::new(mant, target).map_err(|e| EvalError::Arithmetic(e.to_string()));
    }
    let drop = (target - v.exp) as u32;
    let div = 10i128
        .checked_pow(drop)
        .ok_or_else(|| EvalError::Arithmetic("rounding divisor overflow".into()))?;
    let mag = v.mant.abs();
    let qmag = mag / div;
    let rmag = mag % div;
    let half = div / 2; // 10^k is even for k >= 1 (drop >= 1 here)
    let up = match mode {
        RoundingMode::Truncate => false,
        RoundingMode::HalfUp => rmag >= half,
        RoundingMode::HalfEven => rmag > half || (rmag == half && qmag % 2 == 1),
    };
    let rounded_mag = qmag + i128::from(up);
    let mant = if v.mant < 0 {
        -rounded_mag
    } else {
        rounded_mag
    };
    Decimal::new(mant, target).map_err(|e| EvalError::Arithmetic(e.to_string()))
}

/// A Primmel package: a versioned set of deterministic rules.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrimmelPackage {
    /// The package URN (the `package_ref` a lens binding names).
    pub id: String,
    /// The edition pin (recorded in every evaluated output).
    pub version: String,
    /// Human-readable package title.
    #[serde(default)]
    pub title: Option<String>,
    /// The rules, in package order.
    pub rules: Vec<PrimmelRule>,
}

impl PrimmelPackage {
    /// Parse and validate a package from its `.prml` JSON
    /// serialization (the wire document, schema above).
    pub fn from_json(doc: &Value) -> Result<PrimmelPackage, String> {
        let pkg: PrimmelPackage = serde_json::from_value(doc.clone())
            .map_err(|e| format!("primmel package does not parse: {e}"))?;
        pkg.validate()?;
        Ok(pkg)
    }

    /// Look up a rule by id.
    pub fn rule(&self, id: &str) -> Option<&PrimmelRule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// Structural validation: ids present and unique, clause URNs
    /// well-formed, arms non-empty with the else arm (if any) last,
    /// labels non-empty, rounding digits in range.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("primmel package lacks an id".to_string());
        }
        if self.version.trim().is_empty() {
            return Err(format!("primmel package `{}` lacks a version pin", self.id));
        }
        let mut ids: Vec<&str> = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            if rule.id.trim().is_empty() {
                return Err(format!(
                    "primmel package `{}` has a rule without an id",
                    self.id
                ));
            }
            if ids.contains(&rule.id.as_str()) {
                return Err(format!(
                    "primmel package `{}` has duplicate rule id `{}`",
                    self.id, rule.id
                ));
            }
            ids.push(&rule.id);
            if !rule.clause_urn.trim().starts_with("urn:") {
                return Err(format!(
                    "rule `{}` of package `{}` lacks a clause URN \
                     (expected `urn:<document>#clause-…`)",
                    rule.id, self.id
                ));
            }
            if rule.arms.is_empty() {
                return Err(format!(
                    "primmel rule `{}` has no arms — a decision table \
                     needs at least one",
                    rule.id
                ));
            }
            for (index, arm) in rule.arms.iter().enumerate() {
                if arm.label.trim().is_empty() {
                    return Err(format!(
                        "primmel rule `{}` has an arm without a label",
                        rule.id
                    ));
                }
                let last = index + 1 == rule.arms.len();
                // An unconditional arm anywhere but last would shadow
                // the rest — first match wins. (A table that *ends*
                // guarded yields `unclassified` on fall-through:
                // legitimate and explicit.)
                if arm.when.is_none() && !last {
                    return Err(format!(
                        "primmel rule `{}` has an unconditional arm \
                         that is not last (first match wins — the else \
                         arm must close the table)",
                        rule.id
                    ));
                }
                if let Some(p) = &arm.when {
                    validate_expr(&p.lhs, rule)?;
                    validate_expr(&p.rhs, rule)?;
                }
            }
        }
        Ok(())
    }
}

fn validate_expr(expr: &Expr, rule: &PrimmelRule) -> Result<(), String> {
    match expr {
        Expr::Input { input } if input.trim().is_empty() => Err(format!(
            "primmel rule `{}` references an empty input name",
            rule.id
        )),
        Expr::Input { .. } | Expr::Const { .. } => Ok(()),
        Expr::Add { .. } | Expr::Sub { .. } | Expr::Mul { .. } => match operands(expr) {
            Some(pair) => {
                for e in pair.iter() {
                    validate_expr(e, rule)?;
                }
                Ok(())
            }
            None => Ok(()),
        },
        Expr::Round { round } => {
            if round.decimals > 18 {
                return Err(format!(
                    "primmel rule `{}` rounds to {} decimals (max 18)",
                    rule.id, round.decimals
                ));
            }
            validate_expr(&round.of, rule)
        }
    }
}

/// The packages a projection may consult, with per-package sourcing
/// (`dir` — operator-pinned local file, `registry` — a transform
/// subregister item, `fixtures` — the built-in demo corpus).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageSet {
    /// Packages keyed by package URN.
    pub packages: BTreeMap<String, PrimmelPackage>,
    /// Sourcing mode per package URN.
    pub sources: BTreeMap<String, &'static str>,
}

impl PackageSet {
    /// An empty set (no primmel bindings consult it).
    pub fn empty() -> PackageSet {
        PackageSet::default()
    }

    /// A one-package set with its source mode.
    pub fn of(package: PrimmelPackage, source: &'static str) -> PackageSet {
        let mut set = PackageSet::empty();
        set.insert(package, source);
        set
    }

    /// Add a package with its source mode.
    pub fn insert(&mut self, package: PrimmelPackage, source: &'static str) {
        self.sources.insert(package.id.clone(), source);
        self.packages.insert(package.id.clone(), package);
    }

    /// Look up a package by URN together with its sourcing mode.
    pub fn get(&self, id: &str) -> Option<(&PrimmelPackage, &'static str)> {
        let source = self.sources.get(id).copied()?;
        self.packages.get(id).map(|p| (p, source))
    }

    /// Load the `.prml`/`.json` files of a directory (sorted, so the
    /// read is deterministic) into a package set. A corrupt file is an
    /// error the operator must fix — packages are never silently
    /// skipped.
    pub fn from_dir(dir: &std::path::Path) -> Result<PackageSet, String> {
        let mut files: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e == "prml" || e == "json")
                })
                .collect(),
            Err(e) => {
                return Err(format!(
                    "cannot read the primmel packages directory {}: {e}",
                    dir.display()
                ))
            }
        };
        files.sort();
        let mut set = PackageSet::empty();
        for path in files {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let doc: Value = serde_json::from_str(&text)
                .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
            let package =
                PrimmelPackage::from_json(&doc).map_err(|e| format!("{}: {e}", path.display()))?;
            set.insert(package, "dir");
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The guard-band fixture rule: SoH >= 85 % guarded with w = U.
    fn guard_band_rule() -> PrimmelRule {
        PrimmelPackage::from_json(&json!({
            "id": "urn:primmel:pkg:test",
            "version": "1.0.0",
            "rules": [
                {
                    "id": "soh-guard-band",
                    "clause_urn": "urn:oiml:pub:r:91-2:2025#clause-6.1",
                    "arms": [
                        { "label": "conforming", "when": {
                            "op": "ge",
                            "lhs": { "sub": [ { "input": "soh" }, { "input": "U" } ] },
                            "rhs": { "const": "85" } } },
                        { "label": "not-demonstrably-conforming" }
                    ]
                }
            ]
        }))
        .unwrap()
        .rules
        .pop()
        .unwrap()
    }

    fn inputs(pairs: &[(&str, &str)]) -> BTreeMap<String, Decimal> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.parse().unwrap()))
            .collect()
    }

    #[test]
    fn package_parses_from_the_wire_schema() {
        let doc = json!({
            "id": "urn:primmel:pkg:battery-rules",
            "version": "1.2.0",
            "title": "Battery decision rules",
            "rules": [
                {
                    "id": "soh-guard-band",
                    "clause_urn": "urn:oiml:pub:r:91-2:2025#clause-6.1",
                    "title": "SoH >= 85 %, w = U",
                    "arms": [
                        { "label": "conforming", "when": {
                            "op": "ge",
                            "lhs": { "sub": [ { "input": "soh" }, { "input": "U" } ] },
                            "rhs": { "const": "85" } } },
                        { "label": "not-demonstrably-conforming" }
                    ]
                },
                {
                    "id": "efficiency-class",
                    "clause_urn": "urn:eu:reg:2017:1369#annex-ii",
                    "arms": [
                        { "label": "A", "when": {
                            "op": "ge",
                            "lhs": { "input": "eff" },
                            "rhs": { "const": "92" } } },
                        { "label": "B", "when": {
                            "op": "ge",
                            "lhs": { "input": "eff" },
                            "rhs": { "const": "85" } } },
                        { "label": "C", "when": {
                            "op": "ge",
                            "lhs": { "input": "eff" },
                            "rhs": { "const": "0" } } }
                    ]
                }
            ]
        });
        let pkg = PrimmelPackage::from_json(&doc).unwrap();
        assert_eq!(pkg.id, "urn:primmel:pkg:battery-rules");
        assert_eq!(pkg.version, "1.2.0");
        assert_eq!(pkg.rules.len(), 2);
        assert_eq!(
            pkg.rule("soh-guard-band").unwrap().clause_urn,
            "urn:oiml:pub:r:91-2:2025#clause-6.1"
        );
        assert!(pkg.rule("nope").is_none());
        // Round trip through the typed model is a fixed point.
        let back: Value = serde_json::to_value(&pkg).unwrap();
        let again = PrimmelPackage::from_json(&back).unwrap();
        assert_eq!(again, pkg);
    }

    #[test]
    fn guard_band_decides_on_the_narrowed_limit() {
        let rule = guard_band_rule();
        // 86.3 - 1.8 = 84.5 < 85: not demonstrably conforming under
        // w = U, although the bare value would pass.
        let out = rule
            .evaluate(&inputs(&[("soh", "86.3"), ("U", "1.8")]))
            .unwrap();
        assert_eq!(out.label, "not-demonstrably-conforming");
        assert_eq!(out.matched_arm, Some(1));
        // 86.3 - 1.0 = 85.3 >= 85: conforming.
        let out = rule
            .evaluate(&inputs(&[("soh", "86.3"), ("U", "1.0")]))
            .unwrap();
        assert_eq!(out.label, "conforming");
        assert_eq!(out.matched_arm, Some(0));
        // Exactly on the guard-banded limit: >= is inclusive.
        let out = rule
            .evaluate(&inputs(&[("soh", "86.0"), ("U", "1.0")]))
            .unwrap();
        assert_eq!(out.label, "conforming");
    }

    #[test]
    fn evaluation_is_deterministic_and_order_sensitive() {
        let rule = guard_band_rule();
        let env = inputs(&[("soh", "86.3"), ("U", "1.8")]);
        let first = rule.evaluate(&env).unwrap();
        let second = rule.evaluate(&env).unwrap();
        assert_eq!(first, second);
        // Named inputs resolve by identity, not position.
        let flipped = inputs(&[("U", "86.3"), ("soh", "1.8")]);
        let out = rule.evaluate(&flipped).unwrap();
        assert_eq!(out.label, "not-demonstrably-conforming");

        // First match wins: the earlier arm shadows the later one.
        let shadowing = PrimmelRule {
            id: "shadow".into(),
            clause_urn: "urn:x:test#clause-1".into(),
            title: None,
            arms: vec![
                Arm {
                    label: "first".into(),
                    when: Some(Predicate {
                        op: CmpOp::Ge,
                        lhs: Expr::Input { input: "v".into() },
                        rhs: Expr::Const {
                            value: "10".parse().unwrap(),
                        },
                    }),
                },
                Arm {
                    label: "second".into(),
                    when: Some(Predicate {
                        op: CmpOp::Ge,
                        lhs: Expr::Input { input: "v".into() },
                        rhs: Expr::Const {
                            value: "0".parse().unwrap(),
                        },
                    }),
                },
            ],
        };
        let out = shadowing.evaluate(&inputs(&[("v", "50")])).unwrap();
        assert_eq!(out.label, "first");
        assert_eq!(out.matched_arm, Some(0));
    }

    #[test]
    fn unmatched_guards_fall_through_to_unclassified() {
        let rule = PrimmelRule {
            id: "band".into(),
            clause_urn: "urn:x:test#clause-2".into(),
            title: None,
            arms: vec![Arm {
                label: "high".into(),
                when: Some(Predicate {
                    op: CmpOp::Ge,
                    lhs: Expr::Input { input: "v".into() },
                    rhs: Expr::Const {
                        value: "90".parse().unwrap(),
                    },
                }),
            }],
        };
        let out = rule.evaluate(&inputs(&[("v", "5")])).unwrap();
        assert_eq!(out.label, UNCLASSIFIED);
        assert_eq!(out.matched_arm, None);
    }

    #[test]
    fn arithmetic_is_exact_over_decimals() {
        let env = inputs(&[("a", "0.1"), ("b", "0.2"), ("c", "-3")]);
        let eval = |e: &Expr| eval_expr(e, &env).unwrap();
        let add = Expr::Add {
            add: Box::new([
                Expr::Input { input: "a".into() },
                Expr::Input { input: "b".into() },
            ]),
        };
        assert_eq!(eval(&add).to_string(), "0.3"); // exact, no float error
        let mul = Expr::Mul {
            mul: Box::new([
                Expr::Input { input: "c".into() },
                Expr::Input { input: "b".into() },
            ]),
        };
        assert_eq!(eval(&mul).to_string(), "-0.6");
        let sub = Expr::Sub {
            sub: Box::new([
                Expr::Input { input: "a".into() },
                Expr::Input { input: "b".into() },
            ]),
        };
        assert_eq!(eval(&sub).to_string(), "-0.1");
    }

    #[test]
    fn rounding_is_explicit_and_mode_stable() {
        let round = |v: &str, decimals: u8, mode: RoundingMode| {
            round_decimal(v.parse().unwrap(), decimals, mode)
                .unwrap()
                .to_string()
        };
        // Half away from zero vs half to even at the .5 boundary.
        assert_eq!(round("84.45", 1, RoundingMode::HalfUp), "84.5");
        assert_eq!(round("84.45", 1, RoundingMode::HalfEven), "84.4");
        assert_eq!(round("84.55", 1, RoundingMode::HalfEven), "84.6"); // even up
        assert_eq!(round("84.5", 0, RoundingMode::HalfUp), "85");
        assert_eq!(round("84.5", 0, RoundingMode::HalfEven), "84");
        assert_eq!(round("84.5", 0, RoundingMode::Truncate), "84");
        // Negative values round on magnitude, sign preserved.
        assert_eq!(round("-84.45", 1, RoundingMode::HalfUp), "-84.5");
        assert_eq!(round("-84.45", 1, RoundingMode::HalfEven), "-84.4");
        assert_eq!(round("-84.45", 1, RoundingMode::Truncate), "-84.4");
        // No discarded digits: exact, unchanged value.
        assert_eq!(round("85", 2, RoundingMode::HalfUp), "85");
        assert_eq!(round("85.00", 0, RoundingMode::HalfUp), "85");
    }

    #[test]
    fn rounding_node_participates_in_predicates() {
        // A rule that rounds the measurand to whole per cent before
        // comparing — the rounding is explicit in the package.
        let rule = PrimmelPackage::from_json(&json!({
            "id": "urn:primmel:pkg:round-test",
            "version": "1.0.0",
            "rules": [
                {
                    "id": "rounded-limit",
                    "clause_urn": "urn:x:test#clause-3",
                    "arms": [
                        { "label": "pass", "when": {
                            "op": "ge",
                            "lhs": { "round": { "of": { "input": "v" },
                                                "decimals": 0, "mode": "half-up" } },
                            "rhs": { "const": "85" } } },
                        { "label": "fail" }
                    ]
                }
            ]
        }))
        .unwrap()
        .rules
        .pop()
        .unwrap();
        // 84.6 rounds half-up to 85: pass (the guard band would have
        // said otherwise — the package states which rule applies).
        let out = rule.evaluate(&inputs(&[("v", "84.6")])).unwrap();
        assert_eq!(out.label, "pass");
        let out = rule.evaluate(&inputs(&[("v", "84.4")])).unwrap();
        assert_eq!(out.label, "fail");
    }

    #[test]
    fn missing_and_mistyped_inputs_are_distinguished() {
        let rule = guard_band_rule();
        let err = rule.evaluate(&inputs(&[("soh", "86.3")])).unwrap_err();
        assert_eq!(err, EvalError::MissingInput { input: "U".into() });
        assert!(err.to_string().contains("U"));
        // Declared inputs are reported in declaration order.
        assert_eq!(rule.inputs(), vec!["soh", "U"]);
    }

    #[test]
    fn validation_rejects_structurally_bad_packages() {
        let base = |rules: Value| {
            PrimmelPackage::from_json(&json!({
                "id": "urn:primmel:pkg:bad",
                "version": "1.0.0",
                "rules": rules
            }))
        };
        // Duplicate rule ids.
        let dup = json!([
            { "id": "r", "clause_urn": "urn:x#clause-1",
              "arms": [ { "label": "ok" } ] },
            { "id": "r", "clause_urn": "urn:x#clause-2",
              "arms": [ { "label": "ok" } ] }
        ]);
        assert!(base(dup).unwrap_err().contains("duplicate rule id"));
        // Missing or malformed clause URN.
        let no_urn = json!([
            { "id": "r", "clause_urn": "clause-1",
              "arms": [ { "label": "ok" } ] }
        ]);
        assert!(base(no_urn).unwrap_err().contains("clause URN"));
        // Unconditional arm that is not last.
        let early_else = json!([
            { "id": "r", "clause_urn": "urn:x#clause-1",
              "arms": [
                   { "label": "else-first" },
                   { "label": "guarded", "when": {
                       "op": "ge", "lhs": { "input": "v" }, "rhs": { "const": "1" } } }
              ] }
        ]);
        assert!(base(early_else).unwrap_err().contains("not last"));
        // Guarded arm closing the table: legitimate — fall-through is
        // the explicit `unclassified` (mirrors the classification
        // precedent), so validation accepts it.
        let guarded_last = json!([
            { "id": "r", "clause_urn": "urn:x#clause-1",
              "arms": [
                   { "label": "high", "when": {
                       "op": "ge", "lhs": { "input": "v" }, "rhs": { "const": "9" } } }
              ] }
        ]);
        assert!(base(guarded_last).is_ok());
        // Rounding beyond the decimal domain is refused at parse.
        let over_rounding = json!([
            { "id": "r", "clause_urn": "urn:x#clause-1",
              "arms": [
                   { "label": "x", "when": {
                       "op": "ge",
                       "lhs": { "round": { "of": { "input": "v" },
                                           "decimals": 19, "mode": "half-up" } },
                       "rhs": { "const": "1" } } },
                   { "label": "y" }
              ] }
        ]);
        assert!(base(over_rounding).unwrap_err().contains("max 18"));
        // Empty arms / empty label.
        let no_arms = json!([
            { "id": "r", "clause_urn": "urn:x#clause-1", "arms": [] }
        ]);
        assert!(base(no_arms).unwrap_err().contains("no arms"));
        // Empty input name inside a predicate.
        let empty_input = json!([
            { "id": "r", "clause_urn": "urn:x#clause-1",
              "arms": [
                   { "label": "x", "when": {
                       "op": "ge", "lhs": { "input": " " }, "rhs": { "const": "1" } } },
                   { "label": "y" }
              ] }
        ]);
        assert!(base(empty_input).unwrap_err().contains("empty input name"));
        // Version pin required (serde names the missing field, or the
        // validator rejects the empty pin).
        let doc = json!({ "id": "urn:primmel:pkg:x", "rules": [] });
        assert!(PrimmelPackage::from_json(&doc)
            .unwrap_err()
            .contains("version"));
    }

    #[test]
    fn comparison_operators_hold_on_both_sides() {
        let holds = |op: &str, a: &str, b: &str| -> bool {
            let rule = PrimmelPackage::from_json(&json!({
                "id": "urn:primmel:pkg:cmp",
                "version": "1.0.0",
                "rules": [
                    { "id": "r", "clause_urn": "urn:x#clause-1",
                      "arms": [
                          { "label": "yes", "when": {
                              "op": op,
                              "lhs": { "input": "a" },
                              "rhs": { "const": b } } },
                          { "label": "no" }
                      ] }
                ]
            }))
            .unwrap();
            let rule = &rule.rules[0];
            rule.evaluate(&inputs(&[("a", a)])).unwrap().label == "yes"
        };
        assert!(holds("lt", "1.5", "2"));
        assert!(holds("le", "2", "2"));
        assert!(holds("gt", "2.1", "2"));
        assert!(holds("ge", "2", "2"));
        assert!(holds("eq", "2.0", "2"));
        assert!(holds("ne", "2.1", "2"));
        assert!(!holds("lt", "2", "2"));
        assert!(!holds("gt", "-1", "-0.5"));
    }

    #[test]
    fn package_set_round_trips_and_reads_directories() {
        let mut set = PackageSet::empty();
        assert!(set.get("urn:primmel:pkg:none").is_none());
        let rule = guard_band_rule();
        let pkg = PrimmelPackage {
            id: "urn:primmel:pkg:test".into(),
            version: "1.0.0".into(),
            title: None,
            rules: vec![rule],
        };
        set.insert(pkg.clone(), "dir");
        let (got, source) = set.get("urn:primmel:pkg:test").unwrap();
        assert_eq!(got, &pkg);
        assert_eq!(source, "dir");
        assert_eq!(
            PackageSet::of(pkg.clone(), "registry")
                .get("urn:primmel:pkg:test")
                .unwrap()
                .1,
            "registry"
        );

        // Directory loading: sorted read, parse errors surfaced with
        // the file path, only .prml/.json considered.
        let dir = std::env::temp_dir().join(format!(
            "unidpp-projector-primmel-dir-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("battery.prml"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("notes.txt"), "not a package").unwrap();
        let loaded = PackageSet::from_dir(&dir).unwrap();
        let (got, source) = loaded.get("urn:primmel:pkg:test").unwrap();
        assert_eq!(got, &pkg);
        assert_eq!(source, "dir");

        let broken = dir.join("broken.prml");
        std::fs::write(&broken, "{\"id\": \"nope\"}").unwrap();
        let err = PackageSet::from_dir(&dir).unwrap_err();
        assert!(err.contains("broken.prml"), "{err}");
        let _ = std::fs::remove_file(&broken);
        let _ = std::fs::remove_file(dir.join("battery.prml"));
        let _ = std::fs::remove_file(dir.join("notes.txt"));
        let _ = std::fs::remove_dir(&dir);
    }
}
