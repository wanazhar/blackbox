#!/usr/bin/env bash
# Blackbox Unix release qualification gate (1.4 Q1 + 1.5 integrity + 1.6 verified runs).
#
# One reproducible command for maintainers before tagging.
# Outputs a checksummed report under release-artifacts/.
#
# Usage:
#   ./scripts/release-qualify-unix.sh
#   ./scripts/release-qualify-unix.sh --release    # also build --release + soft release overhead
#   ./scripts/release-qualify-unix.sh --quick      # clippy + trust/integrity gates only
#
# Exit 0 only when all mandatory gates pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

QUICK=0
DO_RELEASE_BUILD=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    --release) DO_RELEASE_BUILD=1 ;;
    -h|--help)
      sed -n '1,20p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $arg" >&2
      exit 2
      ;;
  esac
done

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${ROOT}/release-artifacts"
mkdir -p "$OUT_DIR"
REPORT="${OUT_DIR}/qualify-${STAMP}.md"
LOG="${OUT_DIR}/qualify-${STAMP}.log"

# shellcheck disable=SC2329
pass() { echo "PASS  $1" | tee -a "$LOG"; }
# shellcheck disable=SC2329
fail() { echo "FAIL  $1" | tee -a "$LOG"; FAILS=$((FAILS + 1)); }
# shellcheck disable=SC2329
skip() { echo "SKIP  $1" | tee -a "$LOG"; }
# shellcheck disable=SC2329
run_gate() {
  local name="$1"
  shift
  echo "" | tee -a "$LOG"
  echo "── gate: $name ──" | tee -a "$LOG"
  if "$@" >>"$LOG" 2>&1; then
    pass "$name"
    return 0
  else
    fail "$name"
    return 1
  fi
}

FAILS=0
: >"$LOG"

GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_DESCRIBE="$(git describe --always --dirty 2>/dev/null || echo unknown)"
GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
RUSTC_V="$(rustc --version 2>/dev/null || echo unknown)"
CARGO_V="$(cargo --version 2>/dev/null || echo unknown)"
OS_NAME="$(uname -s 2>/dev/null || echo unknown)"
OS_REL="$(uname -r 2>/dev/null || echo unknown)"
OS_MACH="$(uname -m 2>/dev/null || echo unknown)"
PKG_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"

{
  echo "# Blackbox Unix release qualification"
  echo
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| Generated (UTC) | ${STAMP} |"
  echo "| Package version | ${PKG_VERSION} |"
  echo "| Git commit | \`${GIT_COMMIT}\` |"
  echo "| Git describe | ${GIT_DESCRIBE} |"
  echo "| Branch | ${GIT_BRANCH} |"
  echo "| Rustc | ${RUSTC_V} |"
  echo "| Cargo | ${CARGO_V} |"
  echo "| OS | ${OS_NAME} ${OS_REL} (${OS_MACH}) |"
  echo "| Quick mode | ${QUICK} |"
  echo "| Release build | ${DO_RELEASE_BUILD} |"
  echo
  echo "## Gates"
  echo
} >"$REPORT"

echo "blackbox release-qualify-unix — ${PKG_VERSION} @ ${GIT_DESCRIBE}" | tee -a "$LOG"
echo "report: ${REPORT}" | tee -a "$LOG"

# Mandatory gates
run_gate "rustfmt" cargo fmt --check || true
run_gate "clippy -D warnings" cargo clippy --all-targets -- -D warnings || true
run_gate "doc links" python3 scripts/check_doc_links.py || true

if [ "$QUICK" -eq 1 ]; then
  run_gate "trust: neutrality" cargo test --test neutrality_contract -- --quiet || true
  run_gate "trust: ambient" cargo test --test ambient_contract -- --quiet || true
  run_gate "trust: redaction_gate" cargo test --test redaction_gate -- --quiet || true
  run_gate "trust: redaction_adversarial" cargo test --test redaction_adversarial -- --quiet || true
  run_gate "trust: redaction_store_scan" cargo test --test redaction_store_scan -- --quiet || true
  run_gate "trust: postmortem_golden" cargo test --test postmortem_golden -- --quiet || true
  run_gate "trust: pty_fidelity" cargo test --test pty_fidelity -- --quiet || true
  run_gate "trust: process_spawn_storm" cargo test --test process_spawn_storm -- --quiet || true
  run_gate "trust: fault_recovery" cargo test --test fault_recovery -- --quiet || true
  run_gate "trust: overhead_smoke" cargo test --test overhead_smoke -- --quiet || true
  # 1.5 integrity subset
  run_gate "1.5: long_run_integrity" cargo test --test long_run_integrity -- --quiet || true
  run_gate "1.5: tool_dedup" cargo test --test tool_dedup -- --quiet || true
  run_gate "1.5: portable_import" cargo test --test portable_import_atomicity -- --quiet || true
  run_gate "1.5: patch_path_safety" cargo test --test patch_path_safety -- --quiet || true
  run_gate "1.5: storage_batch" cargo test --test storage_batch_faults -- --quiet || true
  run_gate "1.5: workspace_checkpoint" cargo test --test workspace_checkpoint -- --quiet || true
  run_gate "1.5: event_ordering" cargo test --test event_ordering -- --quiet || true
  run_gate "1.5: filesystem_escape" cargo test --test filesystem_escape -- --quiet || true
  run_gate "1.5: native_log_rotation" cargo test --test native_log_rotation -- --quiet || true
  run_gate "1.5: dashboard_auth" cargo test --test dashboard_auth -- --quiet || true
  run_gate "1.5: pagination_scale" cargo test --test pagination_scale -- --quiet || true
  run_gate "1.5: replay_containment" cargo test --test replay_containment_linux -- --quiet || true
  run_gate "1.5: docs_commands" cargo test --test docs_commands -- --quiet || true
  # 1.6 verified runs subset
  run_gate "1.6: fsck_corruption" cargo test --test fsck_corruption -- --quiet || true
  run_gate "1.6: ingest_spool_recovery" cargo test --test ingest_spool_recovery -- --quiet || true
  run_gate "1.6: verification_receipts" cargo test --test verification_receipts -- --quiet || true
  run_gate "1.6: experiment_reports" cargo test --test experiment_reports -- --quiet || true
  run_gate "1.6: regression_gate" cargo test --test regression_gate -- --quiet || true
  run_gate "1.6: capsule_integrity" cargo test --test capsule_integrity -- --quiet || true
  run_gate "1.6: workspace_symlink_safety" cargo test --test workspace_symlink_safety -- --quiet || true
  run_gate "1.6: portable_v2_references" cargo test --test portable_v2_references -- --quiet || true
  run_gate "1.6: pagination_filtered_scale" cargo test --test pagination_filtered_scale -- --quiet || true
  run_gate "1.7: boundary + incident suite" cargo test \
    --test boundary_contract --test boundary_1_7_full \
    --test boundary_trust_integration --test boundary_detector_quality \
    --test incident_pagination --test auto_provenance \
    --test evidence_adversarial -- --quiet || true
else
  run_gate "cargo test --all-targets" cargo test --all-targets -- --quiet || true
  run_gate "docs first-run + envelope + commands" \
    cargo test --test docs_first_run --test docs_cli_envelope --test docs_commands -- --quiet || true
  # 1.6 integrity + verification suite (non-endurance)
  run_gate "1.6: integrity suite" cargo test --test fsck_corruption --test ingest_spool_recovery --test verification_receipts --test experiment_reports --test regression_gate --test capsule_integrity --test workspace_symlink_safety --test portable_v2_references --test pagination_filtered_scale --test blob_reference_rewrite --test aggregate_semantics --test mcp_record_e2e --test budget_cgroup_linux -- --quiet || true
  run_gate "1.7: boundary + incident suite" cargo test \
    --test boundary_contract --test boundary_1_7_full \
    --test boundary_trust_integration --test boundary_detector_quality \
    --test incident_pagination --test auto_provenance \
    --test evidence_adversarial -- --quiet || true
  # Real 100k-event endurance (ignored by default unit filter; force with --ignored)
  run_gate "1.6: endurance_100k" cargo test --test endurance_100k -- --quiet || true
fi

if [ "$DO_RELEASE_BUILD" -eq 1 ]; then
  run_gate "cargo build --release" cargo build --release --bin blackbox || true
  # Soft release-mode startup (not a hard budget failure if missing hyperfine)
  if command -v /usr/bin/time >/dev/null 2>&1; then
    echo "" | tee -a "$LOG"
    echo "── soft: release supervised true ──" | tee -a "$LOG"
    if (
      TMPD="$(mktemp -d)"
      export BLACKBOX_DB="${TMPD}/bb.db"
      mkdir -p "${TMPD}/blobs"
      /usr/bin/time -f 'wall_sec=%e max_rss_kb=%M' \
        ./target/release/blackbox run --observe-only --store "${TMPD}/bb.db" -- true
      rm -rf "${TMPD}"
    ) >>"$LOG" 2>&1; then
      pass "release supervised true (timed)"
    else
      fail "release supervised true (timed)"
    fi
  else
    skip "release timed true (/usr/bin/time missing)"
  fi
fi

# Known limitations appendix
{
  echo
  echo "## Results"
  echo
  echo "See full log: \`$(basename "$LOG")\`"
  echo
  echo "| Gate summary | Count |"
  echo "|---|---|"
  echo "| FAIL | ${FAILS} |"
  echo
  echo "## Known limitations (not automatic fails)"
  echo
  echo "- Short-lived process descendants may be missed by polling (spawn-storm measures loss)."
  echo "- Normalized PTY transcript is not a full-screen TUI frame replay."
  echo "- Logical redaction ≠ physical secure erase on SSD/COW filesystems."
  echo "- Forensic eBPF process backend and full macOS process matrix are deferred."
  echo "- Windows is out of scope for this epic."
  echo
  echo "## 1.4 Trust Proof bars"
  echo
  echo "| Id | Bar |"
  echo "|---|---|"
  echo "| N1/N2 | Recorder neutrality + nest PID markers |"
  echo "| C1–C3 | Coverage not_applicable + contributions |"
  echo "| S1 | Holdback redaction + store scan |"
  echo "| G1 | Causal confidence (confirmed needs fingerprints) |"
  echo "| Phase D | PTY fidelity, spawn storm, fault recovery |"
  echo "| Q1 | This script |"
  echo
  echo "## 1.5 Integrity bars"
  echo
  echo "| Id | Bar |"
  echo "|---|---|"
  echo "| L1/L2 | Long-run aggregates + analysis_scope |"
  echo "| D1 | Safe tool dedupe |"
  echo "| A1 | Portable import integrity |"
  echo "| R1/W1 | Workspace replay + manifests |"
  echo "| S1 | Batched ingest |"
  echo "| O1 | Event clocks / ordering |"
  echo "| C1 | FS / native-log bounds |"
  echo "| H1 | Dashboard session auth |"
  echo "| P1 | Cursor pagination + blob compression |"
  echo "| Q1 | Linux full + macOS PR runtime gate |"
  echo
  echo "## 1.6 Verified runs bars"
  echo
  echo "| Id | Bar |"
  echo "|---|---|"
  echo "| A | Integrity: symlink/manifest, portable v2, pagination, aggregates |"
  echo "| B | fsck + durable spool recovery |"
  echo "| C | Verification receipts / outcome separation |"
  echo "| D | Experiments, reports, gates (statistical honesty) |"
  echo "| E | Capsules + MCP cassette (experimental limits explicit) |"
  echo "| F | Budgets (capability honesty) + adapter protocol + multi-project index |"
  echo "| L | 100k-event endurance qualification |"
  echo
  echo "## 1.7 Agent boundary bars"
  echo
  echo "| Id | Bar |"
  echo "|---|---|"
  echo "| A/B | Immutable pre-launch policy + evidence-bound containment receipts |"
  echo "| C/D | Atomic external evidence import + authenticity-aware correlation |"
  echo "| E | Evidence-time findings + detector quality gate |"
  echo "| F | Observation-backed provenance |"
  echo "| G/H | Chronological incidents + strict portable trust-artifact restore |"
  echo
  echo "## Host"
  echo
  echo "- commit: \`$(git rev-parse HEAD 2>/dev/null || echo unknown)\`"
  echo "- rustc: \`$(rustc --version 2>/dev/null || echo unknown)\`"
  echo "- target: \`$(rustc -vV 2>/dev/null | awk '/^host:/{print $2}' || uname -m)\`"
  echo "- uname: \`$(uname -srm 2>/dev/null || echo unknown)\`"
  echo
  if [ "$FAILS" -eq 0 ]; then
    echo "**Verdict: GREEN** — mandatory gates passed on this host."
  else
    echo "**Verdict: RED** — ${FAILS} gate(s) failed. Do not tag until green."
  fi
  echo
} >>"$REPORT"

# Append gate lines from log into report
{
  echo "## Gate log (PASS/FAIL/SKIP)"
  echo
  echo '```'
  grep -E '^(PASS|FAIL|SKIP)  ' "$LOG" || true
  echo '```'
} >>"$REPORT"

# Checksum
if command -v sha256sum >/dev/null 2>&1; then
  SUM="$(sha256sum "$REPORT" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  SUM="$(shasum -a 256 "$REPORT" | awk '{print $1}')"
else
  SUM="unavailable"
fi
echo "" >>"$REPORT"
echo "Report sha256: \`${SUM}\`" >>"$REPORT"
echo "${SUM}  $(basename "$REPORT")" >"${REPORT}.sha256"

echo "" | tee -a "$LOG"
echo "report: ${REPORT}" | tee -a "$LOG"
echo "sha256: ${SUM}" | tee -a "$LOG"
echo "fails:  ${FAILS}" | tee -a "$LOG"

if [ "$FAILS" -ne 0 ]; then
  echo "release-qualify-unix: RED" >&2
  exit 1
fi
echo "release-qualify-unix: GREEN"
exit 0
