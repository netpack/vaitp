#!/bin/bash
# Setup script for Phase-3-vertex-sven-pyvul-1504 experiment
# Copies the SVEN+PyVul dataset files into the standard vaitp_dataset locations
# and backs up any existing files.

set -e

SRC_VULN="vaitp_dataset/phase3_sven_pyvul/vulnerable"
SRC_PATCH="vaitp_dataset/phase3_sven_pyvul/injectable"
DST_VULN="vaitp_dataset/vulnerable"
DST_PATCH="vaitp_dataset/injectable"
BACKUP_DIR="vaitp_dataset/_backup_before_sven_pyvul_$(date +%Y%m%d_%H%M%S)"

echo "=== Phase-3-vertex-sven-pyvul-1504: Dataset Setup (100 files) ==="
echo ""

# Backup existing files
if [ -d "$DST_VULN" ] && [ "$(ls -A $DST_VULN 2>/dev/null)" ]; then
    echo "Backing up existing vulnerable/ to $BACKUP_DIR/vulnerable/"
    mkdir -p "$BACKUP_DIR/vulnerable"
    cp -r "$DST_VULN"/* "$BACKUP_DIR/vulnerable/" 2>/dev/null || true
fi
if [ -d "$DST_PATCH" ] && [ "$(ls -A $DST_PATCH 2>/dev/null)" ]; then
    echo "Backing up existing injectable/ to $BACKUP_DIR/injectable/"
    mkdir -p "$BACKUP_DIR/injectable"
    cp -r "$DST_PATCH"/* "$BACKUP_DIR/injectable/" 2>/dev/null || true
fi

# Clean destination directories
echo "Cleaning destination directories..."
rm -f "$DST_VULN"/*.py 2>/dev/null || true
rm -f "$DST_PATCH"/*.py 2>/dev/null || true
mkdir -p "$DST_VULN" "$DST_PATCH"

# Copy experiment files
echo "Copying $SRC_VULN -> $DST_VULN"
cp "$SRC_VULN"/*.py "$DST_VULN/"
echo "Copying $SRC_PATCH -> $DST_PATCH"
cp "$SRC_PATCH"/*.py "$DST_PATCH/"

VULN_COUNT=$(ls "$DST_VULN"/*.py 2>/dev/null | wc -l)
PATCH_COUNT=$(ls "$DST_PATCH"/*.py 2>/dev/null | wc -l)

echo ""
echo "Done. Vulnerable: $VULN_COUNT files, Injectable: $PATCH_COUNT files"
echo "Run experiments with:"
echo "  python main_orchestrator.py --config configs/Phase-3-vertex-sven-pyvul-1504_gemini.yaml"
echo "  python main_orchestrator.py --config configs/Phase-3-vertex-sven-pyvul-1504_deepseek.yaml"
echo "  python main_orchestrator.py --config configs/Phase-3-vertex-sven-pyvul-1504_qwen.yaml"
