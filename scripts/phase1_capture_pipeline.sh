#!/usr/bin/env bash
# =============================================================================
# Phase 1: Download 5 CTU captures and run each through the malicious pipeline.
# Run from project root: bash scripts/phase1_capture_pipeline.sh
#
# What this does:
#   1. Downloads 5 CTU botnet PCAPs (total ~6.4 GB):
#        ctu_botnet_112_1  —  68 MB, 2015, Ramnit HTTPS C&C
#        ctu_botnet_110_1  —  83 MB, 2015, Ramnit variant (different host)
#        ctu_botnet_368_1  — 492 MB, 2018, modern HTTPS botnet
#        ctu_botnet_369_1  — 1.6 GB, 2019, newest capture available
#        ctu_botnet_52     — 4.0 GB, 2011, Neris botnet (high-volume, diverse)
#   2. Runs each through: editcap sanitize → tshark TLS filter → Zeek → NFStream
#   3. Checks quality (ssl.log present = quality_status ok)
#   4. Prints the YAML blocks to add to configs/canonical_sources_v2.yaml
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
# Ordered from smallest to largest so you get early results fast.
# Each has a distinct capture_id → enables StratifiedGroupKFold in the ML pipeline.
declare -A CAPTURES
CAPTURES["ctu_botnet_112_1"]="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-112-1/2015-03-09_capture-win11.pcap"
CAPTURES["ctu_botnet_110_1"]="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-110-1/2015-03-09_capture-win9.pcap"
CAPTURES["ctu_botnet_368_1"]="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-368-1/2018-09-15_win2.pcap"
CAPTURES["ctu_botnet_369_1"]="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-369-1/2019-12-07_capture-win5.pcap"
CAPTURES["ctu_botnet_52"]="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/botnet-capture-20110818-bot-2.pcap"

# Process in this order (smallest first so we get pipeline results quickly)
CAPTURE_ORDER=("ctu_botnet_112_1" "ctu_botnet_110_1" "ctu_botnet_368_1" "ctu_botnet_369_1" "ctu_botnet_52")

DATA_DIR="$ROOT/data/mcfp_malicious"
RUNS_DIR="$ROOT/artifacts/runs"

# ---- Preflight checks --------------------------------------------------------
echo "=== Phase 1: CTU Capture Download + Pipeline ==="
echo ""

# Zeek is installed at /opt/zeek/bin — add to PATH if not already present
if ! command -v zeek &>/dev/null; then
    export PATH="/opt/zeek/bin:$PATH"
fi
if ! command -v zeek &>/dev/null; then
    echo "ERROR: zeek not found. Install it first:"
    echo "  sudo apt install zeek"
    echo ""
    echo "After installing, re-run: bash scripts/phase1_capture_pipeline.sh"
    exit 1
fi

echo "zeek:    $(zeek --version 2>&1 | head -1)"
echo "tshark:  $(tshark --version 2>&1 | head -1)"
echo "editcap: $(editcap --version 2>&1 | head -1)"
echo ""

mkdir -p "$DATA_DIR"

# ---- Step 1: Download --------------------------------------------------------
echo "--- Step 1: Downloading captures ---"
echo "Total: ~6.4 GB across 5 captures. Resume-safe — interrupted downloads continue."
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

# ---- Step 2: Run malicious pipeline on each capture -------------------------
echo "--- Step 2: Running malicious pipeline ---"
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

# ---- Step 3: Quality check ---------------------------------------------------
echo "--- Step 3: Quality check (ssl.log presence) ---"
echo ""

for name in "${CAPTURE_ORDER[@]}"; do
    out="$RUNS_DIR/$name"
    nfstream_csv="$out/${name}_nfstream.csv"
    zeek_csv_dir="$out/${name}_zeek_csv"

    if [[ ! -f "$nfstream_csv" ]]; then
        echo "[$name] NFStream CSV missing — pipeline may have failed"
        continue
    fi

    row_count="$("$VENV_PYTHON" -c "import pandas as pd; df=pd.read_csv('$nfstream_csv', low_memory=False); print(len(df))")"

    if [[ -f "$zeek_csv_dir/ssl.csv" ]] || [[ -f "$zeek_csv_dir/tls.csv" ]]; then
        quality="OK (Zeek TLS metadata present)"
    else
        quality="PARTIAL (NFStream-only — ssl.csv absent)"
    fi

    echo "[$name]"
    echo "  Flows:   $row_count"
    echo "  Quality: $quality"
    echo "  Output:  $nfstream_csv"
    echo ""
done

# ---- Step 4: Print YAML blocks to add to canonical_sources_v2.yaml ----------
echo "--- Step 4: YAML blocks for configs/canonical_sources_v2.yaml ---"
echo ""
echo "Add the following entries under 'sources:' in configs/canonical_sources_v2.yaml"
echo "(uncomment the matching template, or paste these directly):"
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
    label: malicious
    attack_family: botnet
    attack_category: c2_exfil
    traffic_role: adversarial_activity
    feature_view: nfstream
    encrypted_only: true
    quality_report_json: $quality_json
    provenance_json: $provenance_json
    extra_labels:
      environment: public_dataset
      collection_origin: $name

YAML
done

echo "=== Phase 1 complete ==="
echo ""
echo "Next steps:"
echo "  1. Add the YAML blocks above to configs/canonical_sources_v2.yaml"
echo "  2. Rebuild canonical dataset:"
echo "       .venv/bin/python -m tls_dataset.pipeline.canonical \\"
echo "           --config configs/canonical_sources_v2.yaml \\"
echo "           --output-dir artifacts/canonical_v2/"
echo "  3. Verify capture diversity:"
echo "       .venv/bin/python -c \""
echo "       import pandas as pd"
echo "       df = pd.read_csv('artifacts/canonical_v2/canonical_labeled_flows.csv', low_memory=False)"
echo "       print(df.groupby('label_id')['capture_id'].nunique())\""
