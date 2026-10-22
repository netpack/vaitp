#!/bin/sh
# One day's slice of the VAITP RAG code-sample pass: ten records, then exit.
#
# Run by ~/Library/LaunchAgents/pt.netpack.vaitp.ragpass.plist (or a crontab line).
# Credentials come from the gitignored .env in the framework root, because launchd and
# cron do not inherit a login shell's environment.
#
# The daily quota is counted from the audit log, so running this twice in one day is
# harmless - the second run finds the quota spent and exits without an API call.

set -eu

VAITP_PATH="/Users/fredericbogaerts/vaitp-framework"
cd "$VAITP_PATH"

mkdir -p results
printf '\n===== %s =====\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" >> results/rag_code_pass.log

exec venv/bin/python scripts/rag_code_quality_pass.py \
    --apply \
    --resume \
    --daily-quota 10 \
    >> results/rag_code_pass.log 2>&1
