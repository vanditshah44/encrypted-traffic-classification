#!/usr/bin/env bash
# =============================================================================
# Phase 2: Download 4 CTU Normal (benign) captures and run each through the
# same malicious pipeline to extract TLS flows, then label them as benign
# in the canonical YAML.
#
# Run from project root: bash scripts/phase2_benign_pipeline.sh
#
# What this does:
#   1. Downloads 4 CTU Normal PCAPs (total ~1.4 GB):
#        ctu_normal_7   — 398 MB, 2013, Linux Debian P2P/web
#        ctu_normal_14  — 403 MB, 2017, Windows 7 full traffic
#        ctu_normal_20  — 269 MB, 2017, Windows normal HTTPS browsing
#        ctu_normal_21  — 297 MB, 2017, Kali Linux normal HTTPS
#   2. Runs each through: editcap sanitize → tshark TLS filter → Zeek → NFStream
#   3. Checks TLS flow counts
#   4. Prints the YAML blocks to add to configs/canonical_sources_v2.yaml
#      (with label: benign — same pipeline, different canonical label)
#
# Prerequisites: Zeek must be installed (sudo apt install zeek)
#   Check: zeek --version
#
# Resume-safe: already-downloaded files and already-processed runs are skipped.
# =============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VENV_PYTHON="$ROOT/.venv/bin/python"

# ---- Selected captures -------------------------------------------------------
declare -A CAPTURES
CAPTURES["ctu_normal_7"]="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-7/2013-12-17_capture1.pcap"
CAPTURES["ctu_normal_14"]="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-14/2017-07-23_capture-winFull.pcap"
CAPTURES["ctu_normal_20"]="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-20/2017-04-30_win-normal.pcap"
CAPTURES["ctu_normal_21"]="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-21/2017-05-02_kali-normal.pcap"

# Process in this order (smallest first so we get results quickly)
CAPTURE_ORDER=("ctu_normal_20" "ctu_normal_21" "ctu_normal_7" "ctu_normal_14")

DATA_DIR="$ROOT/data/mcfp_benign"
RUNS_DIR="$ROOT/artifacts/runs"

# ---- Preflight checks --------------------------------------------------------
echo "=== Phase 2: CTU Normal (Benign) Download + Pipeline ==="
echo ""

# Zeek is installed at /opt/zeek/bin — add to PATH if not already present
if ! command -v zeek &>/dev/null; then
    export PATH="/opt/zeek/bin:$PATH"
fi
if ! command -v zeek &>/dev/null; then
    echo "ERROR: zeek not found. Install it first:"
    echo "  sudo apt install zeek"
    echo ""
    echo "After installing, re-run: bash scripts/phase2_benign_pipeline.sh"
    exit 1
fi

echo "zeek:    $(zeek --version 2>&1 | head -1)"
echo "tshark:  $(tshark --version 2>&1 | head -1)"
echo "editcap: $(editcap --version 2>&1 | head -1)"
echo ""

mkdir -p "$DATA_DIR"

# ---- Step 1: Download --------------------------------------------------------
echo "--- Step 1: Downloading captures ---"
echo "Total: ~1.4 GB across 4 captures. Resume-safe — interrupted downloads continue."
echo ""

for name in "${CAPTURE_ORDER[@]}"; do
    url="${CAPTURES[$name]}"
    filename="$(basename "$url")"
    dest="$DATA_DIR/$name/$filename"

    mkdir -p "$DATA_DIR/$name"

    if [[ -f "$dest" ]]; then
        echo "[$name] Already downloaded: $dest"
        continue
    fi

    echo "[$name] Downloading $url"
    echo "       → $dest"
    wget --continue --show-progress -q -O "$dest" "$url"
    echo "[$name] Done: $(du -sh "$dest" | cut -f1)"
    echo ""
done

echo ""

# ---- Step 2: Run pipeline on each capture -----------------------------------
# We reuse the malicious pipeline — it is label-agnostic (just extracts TLS
# flows). The benign label is assigned in canonical_sources_v2.yaml.
echo "--- Step 2: Running pipeline (TLS extraction) ---"
echo ""

for name in "${CAPTURE_ORDER[@]}"; do
    url="${CAPTURES[$name]}"
    filename="$(basename "$url")"
    pcap="$DATA_DIR/$name/$filename"
    out="$RUNS_DIR/$name"

    if [[ ! -f "$pcap" ]]; then
        echo "[$name] PCAP not found — skipping: $pcap"
        continue
    fi

    if [[ -f "$out/${name}_ml_final.csv" ]]; then
        echo "[$name] Pipeline already complete — skipping"
        echo "       $out/${name}_ml_final.csv"
        continue
    fi

    echo "[$name] Running pipeline..."
    echo "       Input:  $pcap"
    echo "       Output: $out/"
    echo ""

    "$VENV_PYTHON" -m tls_dataset.pipeline.malicious \
        --dataset-name "$name" \
        --input-pcap "$pcap" \
        --output-dir "$out" \
        --source-url "$url" \
        --allow-quality-failures \
        2>&1 | sed "s/^/  [$name] /"

    echo ""
    echo "[$name] Pipeline complete."
    echo ""
done

# ---- Step 3: TLS flow counts -------------------------------------------------
echo "--- Step 3: TLS flow counts per capture ---"
echo ""

for name in "${CAPTURE_ORDER[@]}"; do
    out="$RUNS_DIR/$name"
    nfstream_csv="$out/${name}_nfstream.csv"

    if [[ ! -f "$nfstream_csv" ]]; then
        echo "[$name] NFStream CSV missing — pipeline may have failed"
        continue
    fi

    "$VENV_PYTHON" -c "
import pandas as pd
df = pd.read_csv('$nfstream_csv', low_memory=False)
total = len(df)
if 'application_name' in df.columns:
    tls_rows = df['application_name'].str.startswith('TLS', na=False).sum()
    quic_rows = df['application_name'].str.startswith('QUIC', na=False).sum()
    enc_rows = tls_rows + quic_rows
else:
    enc_rows = total
    tls_rows = 0
    quic_rows = 0
print(f'[$name]')
print(f'  Total NFStream flows : {total}')
print(f'  TLS flows            : {tls_rows}')
print(f'  QUIC flows           : {quic_rows}')
print(f'  Encrypted total      : {enc_rows} ({enc_rows/total*100:.1f}%)')
if enc_rows < 100:
    print(f'  WARNING: very few encrypted flows — consider excluding this capture')
"
    echo ""
done

# ---- Step 4: Print YAML blocks -----------------------------------------------
echo "--- Step 4: YAML blocks for configs/canonical_sources_v2.yaml ---"
echo ""
echo "Add the following entries under 'sources:' in configs/canonical_sources_v2.yaml"
echo "under the existing benign_lab_nfstream entry:"
echo ""

for name in "${CAPTURE_ORDER[@]}"; do
    nfstream_csv="artifacts/runs/$name/${name}_nfstream.csv"
    quality_json="artifacts/runs/$name/${name}_quality_report.json"
    provenance_json="artifacts/runs/$name/${name}_provenance.json"

    cat <<YAML
  - name: ${name}_nfstream
    input_csv: $nfstream_csv
    source_dataset: $name
    capture_id: $name
    label: benign
    attack_family: benign
    attack_category: none
    traffic_role: user_activity
    feature_view: nfstream
    encrypted_only: true
    quality_report_json: $quality_json
    provenance_json: $provenance_json
    extra_labels:
      environment: public_dataset
      collection_origin: $name

YAML
done

echo "=== Phase 2 complete ==="
echo ""
echo "Next steps:"
echo "  1. Add the YAML blocks above to configs/canonical_sources_v2.yaml"
echo "     (under the benign_lab_nfstream entry)"
echo "  2. Rebuild canonical dataset:"
echo "       .venv/bin/python -m tls_dataset.pipeline.canonical \\"
echo "           --config configs/canonical_sources_v2.yaml \\"
echo "           --output-csv artifacts/canonical_v2/canonical_labeled_flows.csv \\"
echo "           --output-summary-json artifacts/canonical_v2/canonical_labeled_flows_summary.json"
echo "  3. Verify benign capture diversity:"
echo "       .venv/bin/python -c \""
echo "       import pandas as pd"
echo "       df = pd.read_csv('artifacts/canonical_v2/canonical_labeled_flows.csv', low_memory=False)"
echo "       print(df.groupby(['label', 'capture_id']).size().to_string())\""
echo "  4. Run Phase 3 experiment:"
echo "       bash scripts/run_v2_experiment.sh"
