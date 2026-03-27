#!/bin/bash
# Quick stability check — 1 hour, 10s intervals
# Usage: ./stability-quick.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/stability-24h.sh" 1 10
