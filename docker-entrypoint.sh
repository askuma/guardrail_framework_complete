#!/bin/sh
set -e

# Ensure the data directory exists and is writable by the guardrail user,
# regardless of whether a stale named volume was mounted over it.
mkdir -p /app/data
chown guardrail:guardrail /app/data

# Drop from root to the guardrail user for the main process.
exec gosu guardrail "$@"
